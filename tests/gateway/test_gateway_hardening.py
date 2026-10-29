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
        assert bad[0] == 403 and "nginx" in bad[1], bad                                    # the 443-style Origin is a different origin on the 8000 deployment (refused by the gateway)
    finally:
        stack.up_gateway(AGENTSEC_PUBLIC_PORT=str(PORT))


def test_hardening_is_applied_to_the_running_containers_and_the_service_still_works_under_load(stack):
    import json, subprocess
    from gwhelpers import sh
    for name, mem in (("agentsec-gw-dev-gateway", 128 << 20), ("agentsec-gw-dev-attack", 512 << 20), ("agentsec-gw-dev-acmebank", 768 << 20)):
        h = json.loads(sh("docker", "inspect", name).stdout)[0]["HostConfig"]
        want = ["ALL"] if name != "agentsec-gw-dev-gateway" else ["NET_RAW", "MKNOD", "SETFCAP", "SETPCAP", "FSETID", "AUDIT_WRITE", "SYS_CHROOT", "NET_BIND_SERVICE"]
        assert sorted(c.removeprefix("CAP_") for c in h["CapDrop"] or []) == sorted(want) and "no-new-privileges:true" in h["SecurityOpt"] and h["Memory"] == mem and h["PidsLimit"] in (128, 256) and not h["Privileged"], (name, h["CapDrop"], h["SecurityOpt"], h["Memory"], h["PidsLimit"])
    # bounded load through the gateway: the limits must not break normal use
    import concurrent.futures as cf
    codes = list(cf.ThreadPoolExecutor(16).map(lambda i: stack.curl(["/learn", "/api/learn/config", "/api/academy/status", "/health"][i % 4], user="learner").status, range(240)))
    assert set(codes) == {200}, {c: codes.count(c) for c in set(codes)}
    stats = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemPerc}} {{.PIDs}}", "agentsec-gw-dev-gateway", "agentsec-gw-dev-attack", "agentsec-gw-dev-acmebank").stdout
    for line in stats.strip().splitlines():
        name, perc, pids = line.split(); assert float(perc.rstrip("%")) < 60 and int(pids) < 100, line


def test_cross_site_marked_posts_cannot_spend_the_operators_quota_and_the_429_keeps_the_security_headers(stack):
    """RC1 review F2 and F5."""
    time.sleep(65)
    body = '{"lab_id":"LAB-PI-001","specimen_id":"ATK-002","mode":"ATTACK","execution":"live"}'
    refused = []
    for hdr in (["Sec-Fetch-Site: cross-site"], ["Sec-Fetch-Site: same-site"], ["Origin: https://evil.test"], [f"Origin: https://{HOST}"], [f"Origin: https://{HOST}:{PORT}@evil.test"]):
        refused += [stack.curl("/api/launch", user="operator", method="POST", data=body, headers=J + hdr).status for _ in range(8)]
    assert set(refused) == {403}, set(refused)                                                  # refused by the gateway, never 429
    ok = [stack.curl("/api/launch", user="operator", method="POST", data=body, headers=J + [f"Origin: https://{HOST}:{PORT}", "Sec-Fetch-Site: same-origin"]).status for _ in range(5)]
    assert 429 not in ok and not {401, 403} & set(ok), ok                                       # the whole burst is still there
    for _ in range(6): last = _post(stack, "operator")
    assert last.status == 429
    for h in ("strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "retry-after"):
        assert h in last.headers, (h, last.headers)


def test_a_wrong_password_cannot_spend_or_probe_the_operators_quota(stack):
    """Review F1: nginx parses the user name from the Authorization header before it checks the password, so a request that CLAIMS to be the operator must be
    refused (401) before the authorization subrequest, and must not charge the operator's bucket."""
    import subprocess
    time.sleep(65)
    def curl_as(user, pw):
        p = subprocess.run(["curl", "-sS", "-m", "15", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", str(stack.pki["root"]), "--resolve", f"{HOST}:{PORT}:127.0.0.1", "-u", f"{user}:{pw}",
                            "-X", "POST", "-H", "Content-Type: application/json", "--data", "{}", f"https://{HOST}:{PORT}{ATTACK_POST}"], capture_output=True, text=True)
        return int(p.stdout or 0)
    wrong = [curl_as("operator", f"guess-{i}") for i in range(40)] + [curl_as("operator", "") for _ in range(5)] + [curl_as("operator", "l-pass") for _ in range(5)]
    assert set(wrong) == {401}, set(wrong)                                          # never 403/429/2xx: the credential is verified first
    first = [_post(stack, "operator").status for _ in range(6)]
    assert 429 not in first and not {401, 403} & set(first), first                  # the operator's whole burst is intact
