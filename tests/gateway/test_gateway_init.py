"""LOCAL_DEV certificate authority created by `gateway.sh init` (RC1 M-3): name-constrained, signing key not retained, strict validation preserved.
No Docker needed; uses the openssl CLI. ORG_CERT material is operator-supplied and is never created, modified or deleted by init."""
import os, re, stat, subprocess
from pathlib import Path
import pytest
from gwhelpers import ROOT, needs_openssl, sh, _ossl

pytestmark = needs_openssl
SCRIPT = ROOT / "scripts/gateway.sh"
HOST = "lab.example.org"


def init(tmp, host=HOST, path=None):
    env = {**os.environ, "AGENTSEC_GATEWAY_DIR": str(tmp / "g"), "AGENTSEC_PUBLIC_HOST": host, "AGENTSEC_PUBLIC_PORT": "8000"}
    if path: env["PATH"] = path + os.pathsep + env["PATH"]
    return subprocess.run(["sh", str(SCRIPT), "init"], cwd=ROOT, env=env, capture_output=True, text=True)


def test_the_ca_signing_key_is_not_retained_but_the_server_key_is_private(tmp_path):
    p = init(tmp_path); assert p.returncode == 0, p.stderr
    tls = tmp_path / "g/tls"
    assert sorted(x.name for x in tls.iterdir()) == ["ca.pem", "fullchain.pem", "server.key", "server.pem"]        # no ca.key, ca.srl, csr or ext file
    assert stat.S_IMODE((tls / "server.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "g/credentials.txt").stat().st_mode) == 0o600
    assert "signing key has already been deleted" in p.stdout and "PRIVATE KEY" not in p.stdout + p.stderr


def test_the_key_is_removed_even_when_provisioning_fails(tmp_path):
    shim = tmp_path / "bin"; shim.mkdir()
    real = subprocess.run(["which", "openssl"], capture_output=True, text=True).stdout.strip()
    (shim / "openssl").write_text(f'#!/bin/sh\n[ "$1" = x509 ] && exit 1\nexec {real} "$@"\n'); (shim / "openssl").chmod(0o755)
    p = init(tmp_path, path=str(shim))
    assert p.returncode != 0
    assert not (tmp_path / "g/tls/ca.key").exists() and not (tmp_path / "g/tls/ca.srl").exists()


def test_the_ca_is_name_constrained_to_the_host_and_localhost(tmp_path):
    assert init(tmp_path).returncode == 0
    text = _ossl("x509", "-in", tmp_path / "g/tls/ca.pem", "-noout", "-text").stdout
    assert "X509v3 Name Constraints: critical" in text and f"DNS:{HOST}" in text and "DNS:localhost" in text
    assert "Excluded" not in text and text.count("Permitted:") == 1


def test_strict_validation_still_passes_for_the_intended_names_and_fails_for_others(tmp_path):
    assert init(tmp_path).returncode == 0
    ca, leaf = tmp_path / "g/tls/ca.pem", tmp_path / "g/tls/server.pem"
    ok = sh("openssl", "verify", "-CAfile", ca, leaf)
    assert ok.returncode == 0 and "OK" in ok.stdout, ok.stdout + ok.stderr
    if "-verify_hostname" in sh("openssl", "verify", "-help").stderr + sh("openssl", "verify", "-help").stdout:   # LibreSSL has no hostname check
        assert sh("openssl", "verify", "-CAfile", ca, "-verify_hostname", HOST, leaf).returncode == 0
        assert sh("openssl", "verify", "-CAfile", ca, "-verify_hostname", "localhost", leaf).returncode == 0
        assert sh("openssl", "verify", "-CAfile", ca, "-verify_hostname", "evil.example", leaf).returncode != 0
    if "LibreSSL" in sh("openssl", "version").stdout:
        return                                                    # the repository validator itself documents LibreSSL as unsupported (no -verify_hostname)
    # the repository's own gateway validator accepts it too (chain, key match, hostname, dates)
    env = {**os.environ, "AGENTSEC_GATEWAY_DIR": str(tmp_path / "g"), "AGENTSEC_PUBLIC_HOST": HOST, "PYTHONPATH": str(ROOT / "src")}
    v = subprocess.run(["sh", str(SCRIPT), "validate"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert v.returncode == 0 and "0 errors" in v.stdout, v.stdout + v.stderr


def test_a_ca_built_with_the_scripts_constraint_cannot_vouch_for_other_names(tmp_path):
    """Takes the constraint string from the script itself, builds a CA with it, and tries to sign a certificate for a name outside the constraint."""
    ext = re.search(r'-addext "(nameConstraints=[^"]+)"', SCRIPT.read_text()).group(1).replace("$HOST", HOST)
    d = tmp_path / "ca"; d.mkdir()
    _ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=t", "-keyout", d / "ca.key", "-out", d / "ca.pem",
          "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", ext)
    def leaf(name, san):
        _ossl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", d / f"{name}.key", "-out", d / f"{name}.csr")
        (d / f"{name}.ext").write_text(f"subjectAltName=DNS:{san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
        _ossl("x509", "-req", "-in", d / f"{name}.csr", "-CA", d / "ca.pem", "-CAkey", d / "ca.key", "-CAcreateserial", "-days", "1", "-extfile", d / f"{name}.ext", "-out", d / f"{name}.pem")
        return sh("openssl", "verify", "-CAfile", d / "ca.pem", d / f"{name}.pem")
    assert leaf("good", HOST).returncode == 0 and leaf("lo", "localhost").returncode == 0
    rogue = leaf("rogue", "bank.example.com")
    assert rogue.returncode != 0 and "subtree violation" in (rogue.stdout + rogue.stderr).lower(), rogue.stdout + rogue.stderr


def test_init_still_refuses_to_overwrite_an_existing_directory(tmp_path):
    (tmp_path / "g").mkdir(); (tmp_path / "g/keep.txt").write_text("mine")
    p = init(tmp_path)
    assert p.returncode == 1 and "refusing" in p.stdout and (tmp_path / "g/keep.txt").read_text() == "mine"


def test_init_writes_the_fullchain_that_compose_mounts(tmp_path):
    assert init(tmp_path).returncode == 0
    tls = tmp_path / "g/tls"
    assert (tls / "fullchain.pem").read_text() == (tls / "server.pem").read_text() + (tls / "ca.pem").read_text()


def test_gateway_compose_calls_keep_the_installer_override_last(tmp_path):
    """-f replaces COMPOSE_FILE from .env, so without this the gateway's `up` recreated the app services under the old container names (EC2 run)."""
    fake = tmp_path / "bin"; fake.mkdir()
    (fake / "docker").write_text('#!/bin/sh\necho "$@" >> "$FAKE_LOG"\n'); (fake / "docker").chmod(0o755)
    work = tmp_path / "w"; (work / ".agentsec").mkdir(parents=True); (work / "scripts").mkdir()
    (work / "scripts/gateway.sh").write_text(SCRIPT.read_text())   # the script cds to its own checkout root
    (work / ".agentsec/compose.override.yml").write_text("services: {}\n")
    env = {**os.environ, "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}", "FAKE_LOG": str(tmp_path / "log"), "AGENTSEC_GATEWAY_DIR": str(tmp_path / "nog")}
    p = subprocess.run(["sh", str(work / "scripts/gateway.sh"), "down"], cwd=work, env=env, capture_output=True, text=True)
    first = (tmp_path / "log").read_text().splitlines()[0]
    assert first.index("docker-compose.gateway.yml") < first.index(".agentsec/compose.override.yml"), (first, p.stderr)
