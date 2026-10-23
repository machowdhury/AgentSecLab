"""HEC transport contract: dual-mode TLS material and no verification bypass on the HEC path.

Deterministic and offline. Certificates are throwaway openssl fixtures in tmp_path.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hec-certs.sh"
SANS = "DNS:agentsec_splunk,DNS:localhost,IP:127.0.0.1"

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl required")


def _run(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def _ca(d: Path, name="ca"):
    key, crt = d / f"{name}.key", d / f"{name}.crt"
    _run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
          "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", f"/CN={name}",
          "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"])
    return key, crt


def _leaf(d: Path, ca, name="srv", sans=SANS, extra=()):
    ca_key, ca_crt = ca
    key, csr, crt, ext = d / f"{name}.key", d / f"{name}.csr", d / f"{name}.crt", d / f"{name}.ext"
    _run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
          "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=agentsec_splunk"])
    lines = ["basicConstraints=CA:FALSE", "extendedKeyUsage=serverAuth"]
    if sans:
        lines.append(f"subjectAltName={sans}")
    ext.write_text("\n".join(lines) + "\n")
    _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
          "-CAcreateserial", "-out", str(crt), "-days", "1", "-extfile", str(ext), *extra])
    return crt, key


def _certs(env_overrides, tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTSEC_HEC")}
    env["AGENTSEC_CERT_DIR"] = str(tmp_path / "out")
    env.update(env_overrides)
    return subprocess.run(["sh", str(SCRIPT)], capture_output=True, text=True, env=env)


# --- LOCAL_SELF_SIGNED -------------------------------------------------------

def test_local_generates_once_and_reuses(tmp_path):
    out = tmp_path / "out"
    assert _certs({}, tmp_path).returncode == 0
    first = (out / "hec.crt").read_bytes()
    assert (out / "hec.key").stat().st_mode & 0o777 == 0o600
    assert (out / "hec.pem").stat().st_mode & 0o777 == 0o644  # the Splunk container uid must read it; .certs/ stays 0700 and hec.key stays 0600
    assert _certs({}, tmp_path).returncode == 0
    assert (out / "hec.crt").read_bytes() == first  # not regenerated on later runs


def test_local_cert_has_required_sans_and_verifies(tmp_path):
    _certs({}, tmp_path)
    crt = tmp_path / "out" / "hec.crt"
    text = _run(["openssl", "x509", "-in", str(crt), "-noout", "-ext", "subjectAltName"]).stdout
    for san in ("DNS:agentsec_splunk", "DNS:localhost", "IP Address:127.0.0.1"):
        assert san in text
    ca = tmp_path / "out" / "hec-ca.crt"
    assert _run(["openssl", "verify", "-CAfile", str(ca), "-verify_hostname", "agentsec_splunk", str(crt)],
                check=False).returncode == 0
    wrong = _run(["openssl", "verify", "-CAfile", str(ca), "-verify_hostname", "splunk", str(crt)], check=False)
    assert wrong.returncode != 0  # hostname outside the SANs must fail


def test_local_never_prints_key_material(tmp_path):
    r = _certs({}, tmp_path)
    assert "PRIVATE KEY" not in r.stdout + r.stderr


# --- EXTERNAL_CERT -----------------------------------------------------------

def _external(tmp_path, crt, key, ca):
    return _certs({"AGENTSEC_HEC_TLS_MODE": "EXTERNAL_CERT", "AGENTSEC_HEC_CERT_FILE": str(crt),
                   "AGENTSEC_HEC_KEY_FILE": str(key), "AGENTSEC_HEC_CA_FILE": str(ca)}, tmp_path)


def test_external_valid_chain_leaves_inputs_untouched(tmp_path):
    ca = _ca(tmp_path)
    crt, key = _leaf(tmp_path, ca)
    before = [p.read_bytes() for p in (crt, key, ca[1])]
    r = _external(tmp_path, crt, key, ca[1])
    assert r.returncode == 0, r.stderr
    assert before == [p.read_bytes() for p in (crt, key, ca[1])]
    assert (tmp_path / "out" / "hec.pem").exists()


def test_external_client_only_needs_no_server_key(tmp_path):
    ca = _ca(tmp_path)
    r = _certs({"AGENTSEC_HEC_TLS_MODE": "EXTERNAL_CERT", "AGENTSEC_HEC_CA_FILE": str(ca[1])}, tmp_path)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "out" / "hec.pem").exists()


@pytest.mark.parametrize("env", [
    {"AGENTSEC_HEC_TLS_MODE": "EXTERNAL_CERT"},                       # CA required
    {"AGENTSEC_HEC_TLS_MODE": "EXTERNAL_CERT", "AGENTSEC_HEC_CA_FILE": "/nonexistent/ca.pem"},
    {"AGENTSEC_HEC_TLS_MODE": "BOGUS"},
])
def test_external_rejects_missing_or_invalid_config(tmp_path, env):
    assert _certs(env, tmp_path).returncode != 0


def test_external_unreadable_cert_path_fails(tmp_path):
    ca = _ca(tmp_path)
    _crt, key = _leaf(tmp_path, ca)
    assert _external(tmp_path, tmp_path / "missing.crt", key, ca[1]).returncode != 0


def test_external_cert_without_required_sans_fails(tmp_path):
    ca = _ca(tmp_path)
    crt, key = _leaf(tmp_path, ca, sans="DNS:other.example")
    r = _external(tmp_path, crt, key, ca[1])
    assert r.returncode != 0 and "SAN" in r.stderr + r.stdout


def test_external_wrong_ca_fails(tmp_path):
    ca, other = _ca(tmp_path), _ca(tmp_path, "other")
    crt, key = _leaf(tmp_path, ca)
    r = _external(tmp_path, crt, key, other[1])
    assert r.returncode != 0 and "chain" in r.stderr + r.stdout


def test_external_key_mismatch_fails(tmp_path):
    ca = _ca(tmp_path)
    crt, _key = _leaf(tmp_path, ca)
    _crt2, key2 = _leaf(tmp_path, ca, name="srv2")
    r = _external(tmp_path, crt, key2, ca[1])
    assert r.returncode != 0 and "match" in r.stderr + r.stdout


def test_external_expired_cert_fails(tmp_path):
    ca = _ca(tmp_path)
    key, crt = tmp_path / "old.key", tmp_path / "old.crt"
    probe = _run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                  "-nodes", "-keyout", str(key), "-out", str(crt), "-subj", "/CN=agentsec_splunk",
                  "-addext", f"subjectAltName={SANS}", "-not_before", "20200101000000Z",
                  "-not_after", "20200102000000Z"], check=False)
    if probe.returncode != 0:
        pytest.skip("this openssl cannot backdate certificates")
    r = _external(tmp_path, crt, key, crt)
    assert r.returncode != 0 and "expired" in r.stderr + r.stdout


# --- static contract: no verification bypass on the HEC path -----------------

def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_no_hec_http_scheme_or_ssl_disable():
    for rel in ("docker-compose.yml", "scripts/splunk_hec_init.sh", "scripts/lab-ready.sh",
                "scripts/ingest_lab_mcp_catalog_scanner_hec.py", "config/otel-collector-config.yaml",
                ".env.example"):
        text = _read(rel)
        assert not re.search(r"http://[^\s\"']*:8088", text), rel
        assert "enableSSL=0" not in text and "SPLUNK_HEC_SSL=0" not in text, rel
        assert "SPLUNK_HEC_TLS_SKIP_VERIFY" not in text, rel


def test_collector_verifies_with_explicit_ca():
    cfg = _read("config/otel-collector-config.yaml")
    assert "insecure_skip_verify: false" in cfg and "ca_file: /certs/hec-ca.crt" in cfg


def test_hec_clients_use_explicit_ca_not_curl_k():
    ready = _read("scripts/lab-ready.sh")
    hec_block = ready[ready.index("Checking HEC"):ready.index("Checking Dashboard Studio")]
    assert "curl -sk" not in hec_block and "--cacert" in hec_block
    init = _read("scripts/splunk_hec_init.sh")
    for line in init.splitlines():
        if "HEC_URL" in line or "HEC_CA" in line:
            assert " -k" not in line
    assert "verify=False" not in _read("scripts/ingest_lab_mcp_catalog_scanner_hec.py")


def test_persistent_https_config_for_bundled_splunk():
    conf = _read("splunk_app/agentsec/local/inputs.conf")
    assert "enableSSL = 1" in conf and "serverCert = " in conf and "sslVersions = tls1.2" in conf


def test_certs_are_git_ignored():
    assert re.search(r"(?m)^\.certs/$", _read(".gitignore"))
    tracked = _run(["git", "-C", str(ROOT), "ls-files", ".certs"]).stdout.strip()
    assert tracked == ""


def test_env_example_documents_both_modes_with_empty_secrets_paths():
    env = _read(".env.example")
    assert "AGENTSEC_HEC_TLS_MODE=LOCAL_SELF_SIGNED" in env
    for k in ("AGENTSEC_HEC_CERT_FILE", "AGENTSEC_HEC_KEY_FILE", "AGENTSEC_HEC_CA_FILE"):
        assert re.search(rf"(?m)^{k}=$", env)


def test_scheme_check_rejects_non_https_endpoint(tmp_path):
    env = {**os.environ, "SPLUNK_HEC_ENDPOINT": "http://agentsec_splunk:8088/services/collector/event"}
    r = subprocess.run(["sh", str(ROOT / "scripts" / "hec-scheme-check.sh")], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "https" in r.stdout


# --- collector delivery contract ---------------------------------------------

def test_logs_pipeline_routes_otlp_to_splunk_hec():
    svc = _read("config/otel-collector-config.yaml").split("\nservice:", 1)[1]
    logs = svc.split("    logs:\n", 1)[1].split("    traces:", 1)[0]
    assert "receivers: [otlp]" in logs
    assert "splunk_hec" in logs
    # Only logs reach HEC; traces/metrics stay on debug. A trace-only probe never indexes.
    traces = svc.split("    traces:\n", 1)[1].split("    metrics:", 1)[0]
    assert "splunk_hec" not in traces


def test_hec_init_pins_provisioned_token_to_lab_index():
    # The image provisions the token with index=default, so events would land in main.
    init = _read("scripts/splunk_hec_init.sh")
    assert "splunk_httpinput/data/inputs/http/splunk_hec_token" in init
    assert 'index=${HEC_INDEX}' in init and 'indexes=${HEC_INDEX}' in init
    assert init.index("splunk_hec_token") < init.index("early_code=")  # before the early exit


def test_sourcetype_requires_json_bodies_for_indexing():
    # otel:agentic:json uses INDEXED_EXTRACTIONS=json: HEC returns 200 for a plain-string log body
    # that Splunk then discards. Probes and emitters must send JSON documents.
    props = _read("splunk_app/agentsec/default/props.conf").split("[otel:agentic:json]", 1)[1].split("\n[", 1)[0]
    assert "INDEXED_EXTRACTIONS = json" in props


def test_hec_pem_is_readable_by_the_splunk_container_but_the_cert_dir_stays_private():
    text = (ROOT / "scripts" / "hec-certs.sh").read_text(encoding="utf-8")
    assert text.count('chmod 644 "$CERT_DIR/hec.pem"') == 2 and 'chmod 700 "$CERT_DIR"' in text


def test_lab_up_refuses_a_stale_plain_http_hec_endpoint_before_starting_anything():
    text = (ROOT / "scripts" / "lab-up.sh").read_text(encoding="utf-8")
    guard, first_compose = text.index("SPLUNK_HEC_ENDPOINT=//p"), text.index("hec-certs.sh\" || exit 1")
    assert guard < first_compose and "https://*) ;;" in text
