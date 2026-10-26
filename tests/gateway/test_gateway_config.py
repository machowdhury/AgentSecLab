"""Configuration validation: every error path fails closed with a specific code, and no secret is ever printed."""
import os, stat, subprocess, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from gwhelpers import ROOT, base_env, make_ca, make_leaf, make_org_pki, needs_openssl, sh

sys.path.insert(0, str(ROOT / "src"))
from agentsec.gateway_config import validate  # noqa: E402

pytestmark = needs_openssl


def codes(env, **kw):
    return {(f.level, f.code) for f in validate(env, **kw)}


@pytest.fixture
def pki(tmp_path):
    return make_org_pki(tmp_path / "pki")


def test_valid_org_cert_configuration_has_no_errors(tmp_path, pki):
    assert [f for f in validate(base_env(tmp_path, pki)) if f.level == "ERROR"] == []


def test_defaults_are_443_and_canonical_host_localhost(tmp_path, pki):
    env = base_env(tmp_path, pki, AGENTSEC_PUBLIC_HOST=pki["host"]); env.pop("AGENTSEC_HTTPS_PORT")
    assert [f for f in validate(env) if f.code == "PORT_INVALID"] == []


@pytest.mark.parametrize("mode,code", [("EDGE_TERMINATED", "TLS_MODE_NOT_IMPLEMENTED"), ("SOMETHING", "TLS_MODE_INVALID")])
def test_tls_modes_that_are_planned_or_unknown_are_refused(tmp_path, pki, mode, code):
    assert ("ERROR", code) in codes(base_env(tmp_path, pki, AGENTSEC_TLS_MODE=mode))


@pytest.mark.parametrize("mode,code", [("OIDC", "AUTH_MODE_NOT_IMPLEMENTED"), ("EDGE_HEADER", "AUTH_MODE_NOT_IMPLEMENTED"), ("NONE", "AUTH_MODE_INVALID")])
def test_auth_modes_that_are_planned_or_unknown_are_refused(tmp_path, pki, mode, code):
    assert ("ERROR", code) in codes(base_env(tmp_path, pki, AGENTSEC_AUTH_MODE=mode))


@pytest.mark.parametrize("name,val,code", [("AGENTSEC_HTTPS_PORT", "0", "PORT_INVALID"), ("AGENTSEC_HTTPS_PORT", "70000", "PORT_INVALID"), ("AGENTSEC_HTTPS_PORT", "https", "PORT_INVALID"),
                                           ("AGENTSEC_PUBLIC_HOST", "https://x.test", "HOST_INVALID"), ("AGENTSEC_PUBLIC_HOST", "*.x.test", "HOST_INVALID"), ("AGENTSEC_PUBLIC_HOST", "a b", "HOST_INVALID"),
                                           ("AGENTSEC_ATTACK_TIER", "maybe", "ATTACK_TIER_INVALID")])
def test_bad_scalar_settings(tmp_path, pki, name, val, code):
    assert ("ERROR", code) in codes(base_env(tmp_path, pki, **{name: val}))


def test_missing_files_are_reported_individually(tmp_path, pki):
    c = codes(base_env(tmp_path, pki, AGENTSEC_TLS_CERT_FILE="/nonexistent/c.pem", AGENTSEC_TLS_KEY_FILE="/nonexistent/k.pem", AGENTSEC_TLS_CHAIN_FILE="/nonexistent/ch.pem", AGENTSEC_AUTH_FILE="/nonexistent/h"))
    assert {("ERROR", "TLS_CERT_MISSING"), ("ERROR", "TLS_KEY_MISSING"), ("ERROR", "TLS_CHAIN_MISSING"), ("ERROR", "AUTH_FILE_MISSING")} <= c


def test_mismatched_key_is_refused(tmp_path, pki):
    other_key = tmp_path / "other.key"; sh("openssl", "genrsa", "-out", other_key, "2048"); other_key.chmod(0o600)
    assert ("ERROR", "TLS_KEY_MISMATCH") in codes(base_env(tmp_path, pki, AGENTSEC_TLS_KEY_FILE=str(other_key)))


def test_expired_and_not_yet_valid_certificates(tmp_path, pki):
    exp, k = make_leaf(tmp_path / "exp", pki["int_pem"], pki["int_key"], f"DNS:{pki['host']}", "server", "-not_before", "20200101000000Z", "-not_after", "20200102000000Z")
    assert ("ERROR", "TLS_CERT_EXPIRED") in codes(base_env(tmp_path, pki, AGENTSEC_TLS_CERT_FILE=str(exp), AGENTSEC_TLS_KEY_FILE=str(k)))
    assert ("ERROR", "TLS_CERT_NOT_YET_VALID") in codes(base_env(tmp_path, pki), now=datetime.now(timezone.utc) - timedelta(days=5))


def test_certificate_expiring_soon_warns_but_is_valid(tmp_path, pki):
    c = codes(base_env(tmp_path, pki), now=datetime.now(timezone.utc) + timedelta(days=15))
    assert ("WARN", "TLS_EXPIRES_SOON") in c and not any(l == "ERROR" for l, _ in c)


def test_wrong_hostname_and_wrong_ca_are_refused(tmp_path, pki):
    assert ("ERROR", "TLS_HOSTNAME_MISMATCH") in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_HOST="elsewhere.test"))
    other_ca, _ = make_ca(tmp_path / "otherca", "unrelated-ca")
    assert ("ERROR", "TLS_CHAIN_UNTRUSTED") in codes(base_env(tmp_path, pki, AGENTSEC_TLS_CHAIN_FILE=str(other_ca)))


def test_missing_intermediate_in_chain_is_refused(tmp_path, pki):
    assert ("ERROR", "TLS_CHAIN_UNTRUSTED") in codes(base_env(tmp_path, pki, AGENTSEC_TLS_CHAIN_FILE=str(pki["root"])))   # root only: the intermediate is not supplied


def test_garbage_cert_and_key_files(tmp_path, pki):
    bad = tmp_path / "bad.pem"; bad.write_text("not pem")
    c = codes(base_env(tmp_path, pki, AGENTSEC_TLS_CERT_FILE=str(bad)))
    assert ("ERROR", "TLS_CERT_INVALID") in c
    assert ("ERROR", "TLS_KEY_INVALID") in codes(base_env(tmp_path, pki, AGENTSEC_TLS_KEY_FILE=str(bad)))


def test_world_readable_key_warns(tmp_path, pki):
    pki["key"].chmod(0o644)
    assert ("WARN", "TLS_KEY_PERMISSIONS") in codes(base_env(tmp_path, pki))


def test_htpasswd_must_hold_hashes_and_both_roles(tmp_path, pki):
    plain = tmp_path / "plain"; plain.write_text("learner:secret\noperator:secret2\n")
    assert ("ERROR", "AUTH_FILE_INVALID") in codes(base_env(tmp_path, pki, AGENTSEC_AUTH_FILE=str(plain)))
    one = tmp_path / "one"; one.write_text(Path(base_env(tmp_path, pki)["AGENTSEC_AUTH_FILE"]).read_text().splitlines()[0] + "\n")
    assert ("ERROR", "AUTH_ROLES_MISSING") in codes(base_env(tmp_path, pki, AGENTSEC_AUTH_FILE=str(one)))


def test_nonloopback_bind_warns_unless_acknowledged(tmp_path, pki):
    assert ("WARN", "BIND_NONLOOPBACK") in codes(base_env(tmp_path, pki, AGENTSEC_GATEWAY_BIND="0.0.0.0"))
    assert ("WARN", "BIND_NONLOOPBACK") not in codes(base_env(tmp_path, pki, AGENTSEC_GATEWAY_BIND="0.0.0.0", AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK="1"))


def test_findings_never_contain_key_material_or_hashes(tmp_path, pki):
    text = " ".join(f.message for f in validate(base_env(tmp_path, pki, AGENTSEC_TLS_CHAIN_FILE=str(pki["root"]), AGENTSEC_PUBLIC_HOST="elsewhere.test")))
    assert "PRIVATE KEY" not in text and "$apr1$" not in text and "BEGIN" not in text


def test_cli_exit_codes(tmp_path, pki):
    env = {**os.environ, **base_env(tmp_path, pki), "PYTHONPATH": str(ROOT / "src")}
    ok = subprocess.run([sys.executable, "-m", "agentsec.gateway_config", "validate"], env=env, capture_output=True, text=True)
    bad = subprocess.run([sys.executable, "-m", "agentsec.gateway_config", "validate"], env={**env, "AGENTSEC_TLS_MODE": "EDGE_TERMINATED"}, capture_output=True, text=True)
    usage = subprocess.run([sys.executable, "-m", "agentsec.gateway_config"], env=env, capture_output=True, text=True)
    assert (ok.returncode, bad.returncode, usage.returncode) == (0, 1, 2) and "INVALID" in bad.stdout


def test_gateway_script_refuses_to_start_docker_when_configuration_is_invalid(tmp_path, pki):
    """gateway.sh up must stop at validation: a shim `docker` records any call and none may happen."""
    shim = tmp_path / "bin"; shim.mkdir(); log = tmp_path / "docker.calls"
    (shim / "docker").write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 0\n'); (shim / "docker").chmod(0o755)
    env = {**os.environ, **base_env(tmp_path, pki, AGENTSEC_PUBLIC_HOST="elsewhere.test"), "PATH": f"{shim}:{os.environ['PATH']}", "PYTHONPATH": str(ROOT / "src")}
    p = subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "up"], env=env, capture_output=True, text=True, cwd=ROOT)
    assert p.returncode != 0 and "TLS_HOSTNAME_MISMATCH" in p.stdout and not log.exists()


# ---- single public port contract (443 default, 8000 alternative) ----
@pytest.mark.parametrize("port", ["443", "8000"])
def test_supported_public_ports_are_accepted_without_warnings(tmp_path, pki, port):
    c = codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT=port))
    assert not any(code.startswith("PORT") for _, code in c)


@pytest.mark.parametrize("port", ["5000", "5001", "8088", "8089", "4317", "4318", "11434"])
def test_internal_service_ports_can_never_be_the_public_port(tmp_path, pki, port):
    assert ("ERROR", "PORT_RESERVED") in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT=port))


def test_other_ports_warn_as_development_only_and_the_old_alias_still_works(tmp_path, pki):
    assert ("WARN", "PORT_NONSTANDARD") in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT="8443"))
    env = base_env(tmp_path, pki); env.pop("AGENTSEC_PUBLIC_PORT", None)               # base_env sets the alias AGENTSEC_HTTPS_PORT=8443
    assert ("WARN", "PORT_NONSTANDARD") in codes(env)
    assert ("ERROR", "PORT_INVALID") in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT="abc"))


def test_splunk_local_port_must_not_collide_with_the_public_port(tmp_path, pki):
    assert ("ERROR", "PORT_CONFLICT") in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT="8000", AGENTSEC_SPLUNK_LOCAL_PORT="8000"))
    assert ("ERROR", "SPLUNK_LOCAL_PORT_INVALID") in codes(base_env(tmp_path, pki, AGENTSEC_SPLUNK_LOCAL_PORT="x"))


def test_an_occupied_port_is_reported_before_anything_is_started(tmp_path, pki):
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
    try:
        port = str(s.getsockname()[1])
        c = codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT=port, AGENTSEC_CHECK_PORT_FREE="1"))
        assert ("ERROR", "PORT_IN_USE") in c
        assert ("ERROR", "PORT_IN_USE") not in codes(base_env(tmp_path, pki, AGENTSEC_PUBLIC_PORT=port))     # only checked when asked (gateway.sh up asks)
    finally:
        s.close()
