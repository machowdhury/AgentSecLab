"""gateway-ready.sh and lab-ready.sh gateway awareness, tested with shim `docker` and `curl` commands (nothing real is touched).
The shims answer from files so each test states exactly which facts are true."""
import os, stat, subprocess
from pathlib import Path
import pytest
from gwhelpers import ROOT

DOCKER = r'''#!/bin/sh
S="$SHIM_DIR"; echo "$*" >> "$S/docker.calls"
case "$*" in
  "ps --format {{.Names}}") cat "$S/containers" ;;
  "exec agentsec_gateway nginx -t") [ "$(cat "$S/nginx")" = ok ] ;;
  *"agentsec_attack_service curl"*"/learn"*) cat "$S/learn" ;;
  *"agentsec_attack_service curl"*"/health"*) cat "$S/health" ;;
  *"agentsec_splunk"*) cat "$S/telemetry" ;;
  *) exit 1 ;;
esac
'''
CURL = r'''#!/bin/sh
S="$SHIM_DIR"; echo "$*" >> "$S/curl.calls"
case "$*" in
  *"https://"*"/learn"*) cat "$S/gateway_code" ;;
  *"/en-US/account/login"*) cat "$S/splunk_code" ;;
  *) echo 000 ;;
esac
'''


def run(tmp, args=(), **files):
    shim = tmp / "bin"; shim.mkdir(exist_ok=True)
    for name, body in (("docker", DOCKER), ("curl", CURL)):
        (shim / name).write_text(body); (shim / name).chmod(0o755)
    use_ca = files.pop("_ca", True)
    state = {"containers": "agentsec_gateway\nagentsec_attack_service\n", "nginx": "ok", "learn": "200", "health": "200", "gateway_code": "401", "splunk_code": "200", "telemetry": "0"}
    state.update(files)
    for k, v in state.items(): (tmp / k).write_text(v)
    ca = tmp / "ca.pem"; ca.write_text("x")
    env = {**os.environ, "PATH": f"{shim}:{os.environ['PATH']}", "SHIM_DIR": str(tmp), "AGENTSEC_GATEWAY_DIR": str(tmp / "g"), "AGENTSEC_TLS_CHAIN_FILE": str(ca) if use_ca else "/nonexistent"}
    return subprocess.run(["sh", str(ROOT / "scripts/gateway-ready.sh"), *args], env=env, cwd=ROOT, capture_output=True, text=True)


def test_all_checked_facts_ready_but_telemetry_and_live_are_never_claimed(tmp_path):
    p = run(tmp_path)
    assert p.returncode == 0, p.stdout
    for w in ("GATEWAY READY", "ACADEMY READY", "ATTACK SERVICE READY", "SPLUNK REACHABLE", "TELEMETRY NOT VERIFIED", "LIVE WORKFLOW NOT VERIFIED"):
        assert w in p.stdout, w
    assert "TELEMETRY VERIFIED" not in p.stdout and "not proof" in p.stdout.lower()


def test_gateway_not_running_fails(tmp_path):
    p = run(tmp_path, containers="agentsec_attack_service\n")
    assert p.returncode == 1 and "GATEWAY NOT READY" in p.stdout


def test_invalid_nginx_configuration_fails(tmp_path):
    assert "GATEWAY NOT READY" in run(tmp_path, nginx="bad").stdout


@pytest.mark.parametrize("code", ["000", "200", "502"])
def test_tls_or_auth_misbehaviour_is_not_ready(tmp_path, code):
    p = run(tmp_path, gateway_code=code)
    assert p.returncode == 1 and "GATEWAY NOT READY" in p.stdout and code in p.stdout


def test_without_a_ca_file_tls_is_reported_not_verified_rather_than_ready(tmp_path):
    p = run(tmp_path, _ca=False)
    assert "GATEWAY RUNNING" in p.stdout and "TLS NOT VERIFIED" in p.stdout and "GATEWAY READY" not in p.stdout


@pytest.mark.parametrize("name,val,word", [("learn", "502", "ACADEMY NOT READY"), ("health", "503", "ATTACK SERVICE NOT READY")])
def test_academy_and_attack_service_are_reported_separately(tmp_path, name, val, word):
    p = run(tmp_path, **{name: val})
    assert p.returncode == 1 and word in p.stdout and ("ATTACK SERVICE READY" in p.stdout or name == "health")


def test_splunk_being_down_does_not_fail_readiness_and_is_stated(tmp_path):
    p = run(tmp_path, splunk_code="000")
    assert p.returncode == 0 and "SPLUNK NOT REACHABLE" in p.stdout


def test_telemetry_is_verified_only_for_the_given_run_and_only_with_events(tmp_path):
    assert "TELEMETRY VERIFIED for run_id=abc-1: 7" in run(tmp_path, ["--run-id", "abc-1"], telemetry="count\n7\n").stdout
    none = run(tmp_path, ["--run-id", "abc-1"], telemetry="count\n0\n").stdout
    assert "TELEMETRY NOT VERIFIED for run_id=abc-1" in none and "TELEMETRY VERIFIED" not in none
    bad = run(tmp_path, ["--run-id", "x; rm -rf /"]).stdout
    assert "TELEMETRY NOT VERIFIED: --run-id must be" in bad
    assert "agentsec_splunk" not in (tmp_path / "docker.calls").read_text() or "rm -rf" not in (tmp_path / "docker.calls").read_text()


def test_the_script_is_read_only(tmp_path):
    run(tmp_path)
    calls = (tmp_path / "docker.calls").read_text()
    assert not any(v in calls for v in ("compose", " rm ", " stop ", " restart ", " kill ", " run ", " up ", " down "))
    text = (ROOT / "scripts/gateway-ready.sh").read_text()
    assert "curl -k" not in text and "--insecure" not in text and "-sk" not in text.replace("curl -sk -u \\\"admin", "")


def test_lab_ready_switches_to_gateway_mode_only_when_the_gateway_container_exists():
    text = (ROOT / "scripts/lab-ready.sh").read_text()
    assert "grep -qx agentsec_gateway" in text and "gateway-ready.sh" in text and 'GATEWAY_MODE" = 1' in text
    assert text.index('GATEWAY_MODE" = 1 ]; then\n  log "Deployment mode: GATEWAY') < text.index('"${AGENTSEC_DEPLOYMENT:-local}" = "remote"')   # gateway branch precedes the REMOTE classifier
    assert 'http://127.0.0.1:5001/health || echo 000)"\nif' not in text                                                               # direct probes only in the non-gateway branch
