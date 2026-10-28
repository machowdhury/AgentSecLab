"""Runtime checks of the gateway's abuse controls in the ISOLATED stack (project agentsec-gw-dev). Opt-in like test_gateway_runtime.py."""
import os, time
import pytest
from gwhelpers import needs_docker, needs_openssl
from test_gateway_runtime import HOST, PORT, stack  # noqa: F401

pytestmark = [needs_docker, needs_openssl, pytest.mark.skipif(os.environ.get("AGENTSEC_GATEWAY_RUNTIME_TESTS") != "1", reason="opt-in: starts an isolated compose project; set AGENTSEC_GATEWAY_RUNTIME_TESTS=1")]
J = ["Content-Type: application/json"]
ATTACK_POST = "/api/missions/loan-desk/runs"          # a state-changing attack-tier route


def _post(stack, user, path=ATTACK_POST):
    return stack.curl(path, user=user, method="POST", data="{}", headers=J)


def _drain(stack):
    """Spend the operator's quota; returns the statuses seen."""
    return [_post(stack, "operator").status for _ in range(14)]


def test_unauthorized_requests_cannot_spend_the_operators_attack_quota(stack):
    time.sleep(65)                                                                  # start from a full bucket
    anon = [stack.curl(ATTACK_POST, method="POST", data="{}", headers=J).status for _ in range(40)]
    learner = [_post(stack, "learner").status for _ in range(40)]
    assert set(anon) == {401} and set(learner) == {403}, (set(anon), set(learner))   # never 429: nothing was charged
    first = [_post(stack, "operator").status for _ in range(6)]                        # the full burst is still available to the operator
    assert 429 not in first and not {401, 403} & set(first), first


def test_quota_applies_to_execution_posts_only_and_returns_retry_after(stack):
    time.sleep(65)
    polls = [stack.curl("/api/launches/abc123", user="operator").status for _ in range(30)]   # GET status polling
    assert 429 not in polls and not {401, 403} & set(polls), set(polls)
    codes = _drain(stack)
    assert 429 in codes and codes.index(429) <= 8, codes
    over = _post(stack, "operator")
    assert over.status == 429 and over.headers.get("retry-after") == ["10"]
    assert stack.curl("/api/launches/abc123", user="operator").status != 429                    # polling still works while the quota is spent
    assert _post(stack, "learner").status == 403                                              # and a learner is told 403, not 429, even now


def test_the_quota_recovers(stack):
    _drain(stack)
    time.sleep(15)                                                                  # rate 6/min: about one token per 10 s
    assert _post(stack, "operator").status not in (429, 401, 403)


def test_the_8000_configuration_works_at_runtime_without_binding_host_port_8000(stack):
    """AGENTSEC_PUBLIC_PORT=8000 in the gateway container (what a real 8000 deployment sets) behind a free host port: the Host/Origin contract is the part of the
    8000 deployment that differs from 443, and it is checked here for real. (The host bind itself is test_public_port_8000_binds_..., skipped while 8000 is busy.)"""
    import subprocess
    from test_gateway_runtime import FILES, ROOT
    alt = 18544
    files = FILES + ["-f", "tests/gateway/compose.port8000.test.yml"]
    env = {**os.environ, **stack.vars, "AGENTSEC_PUBLIC_PORT": "8000", "TEST_ALT_PORT": str(alt)}
    up = subprocess.run(["docker", "compose", "-p", "agentsec-gw-dev", *files, "--profile", "gateway", "up", "-d", "--no-deps", "--force-recreate", "gateway"], cwd=ROOT, capture_output=True, text=True, env=env)
    assert up.returncode == 0, up.stderr
    try:
        def curl(path, *, user="learner", method="GET", headers=(), data=None):
            pw = {"learner": "l-pass", "operator": "o-pass"}[user]
            cmd = ["curl", "-sS", "-m", "20", "-o", "/tmp/_p8000_body", "-w", "%{http_code}", "--cacert", str(stack.pki["root"]), "--resolve", f"{HOST}:{alt}:127.0.0.1", "-u", f"{user}:{pw}", "-X", method]
            for h in headers: cmd += ["-H", h]
            if data is not None: cmd += ["--data", data]
            p = subprocess.run(cmd + [f"https://{HOST}:{alt}{path}"], capture_output=True, text=True)
            return int(p.stdout or 0), open("/tmp/_p8000_body", errors="replace").read()
        for _ in range(40):
            if curl("/health", headers=[f"Host: {HOST}:8000"])[0] == 200: break
            time.sleep(1.5)
        assert curl("/health", headers=[f"Host: {HOST}:8000"])[0] == 200                # the configured authority is accepted
        assert curl("/health", headers=[f"Host: {HOST}"])[0] == 421                     # port-less Host is not the 8000 deployment's authority
        assert curl("/health", headers=[f"Host: {HOST}:{alt}"])[0] == 421               # nor is the test's real host port
        assert curl("/health", headers=[f"Host: {HOST}:443"])[0] == 421
        time.sleep(15)
        ok = curl("/api/launch", user="operator", method="POST", data="{}", headers=["Content-Type: application/json", f"Host: {HOST}:8000", f"Origin: https://{HOST}:8000"])
        assert ok[0] not in (401, 403, 421) and "cross_origin_rejected" not in ok[1], ok       # what a browser on https://host:8000 sends
        time.sleep(11)
        bad = curl("/api/launch", user="operator", method="POST", data="{}", headers=["Content-Type: application/json", f"Host: {HOST}:8000", f"Origin: https://{HOST}"])
        assert bad[0] == 403 and "cross_origin_rejected" in bad[1], bad                  # the 443-style Origin is a different origin on the 8000 deployment
    finally:
        stack.up_gateway(AGENTSEC_PUBLIC_PORT=str(PORT))


def test_hardening_is_applied_to_the_running_containers_and_the_service_still_works_under_load(stack):
    import json, subprocess
    from gwhelpers import sh
    for name, mem in (("agentsec-gw-dev-gateway", 128 << 20), ("agentsec-gw-dev-attack", 512 << 20), ("agentsec-gw-dev-acmebank", 768 << 20)):
        h = json.loads(sh("docker", "inspect", name).stdout)[0]["HostConfig"]
        assert h["CapDrop"] == ["ALL"] and "no-new-privileges:true" in h["SecurityOpt"] and h["Memory"] == mem and h["PidsLimit"] in (128, 256) and not h["Privileged"], (name, h["CapDrop"], h["SecurityOpt"], h["Memory"], h["PidsLimit"])
    # bounded load through the gateway: the limits must not break normal use
    import concurrent.futures as cf
    codes = list(cf.ThreadPoolExecutor(16).map(lambda i: stack.curl(["/learn", "/api/learn/config", "/api/academy/status", "/health"][i % 4], user="learner").status, range(240)))
    assert set(codes) == {200}, {c: codes.count(c) for c in set(codes)}
    stats = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemPerc}} {{.PIDs}}", "agentsec-gw-dev-gateway", "agentsec-gw-dev-attack", "agentsec-gw-dev-acmebank").stdout
    for line in stats.strip().splitlines():
        name, perc, pids = line.split(); assert float(perc.rstrip("%")) < 60 and int(pids) < 100, line
