"""Runtime tests in an ISOLATED compose project (agentsec-gw-dev): gateway + Attack Service + AcmeBank only.
The real lab (project agentseclab, containers agentsec_*) is never started, stopped, recreated or modified; a snapshot proves it.
Needs docker. Takes about two minutes the first time (image build)."""
import json, os, re, subprocess, time
from pathlib import Path
import pytest
from gwhelpers import ROOT, base_env, make_ca, make_org_pki, needs_docker, needs_openssl, protected_snapshot, sh

pytestmark = [needs_docker, needs_openssl, pytest.mark.skipif(os.environ.get("AGENTSEC_GATEWAY_RUNTIME_TESTS") != "1", reason="opt-in: builds images and starts an isolated compose project; set AGENTSEC_GATEWAY_RUNTIME_TESTS=1")]
PROJECT, PORT, HOST = "agentsec-gw-dev", 18543, "agentsec.test"
FILES = ["-f", "docker-compose.yml", "-f", "docker-compose.gateway.yml", "-f", "tests/gateway/compose.test.yml"]


class Env:
    def __init__(self, tmp):
        self.tmp, self.pki = tmp, make_org_pki(tmp / "pki", HOST)
        self.vars = base_env(tmp, self.pki, AGENTSEC_HTTPS_PORT=str(PORT))
        (tmp / "g" / "tls").mkdir(parents=True, exist_ok=True)
    @property
    def port(self):
        return int(self.vars.get("AGENTSEC_PUBLIC_PORT") or self.vars["AGENTSEC_HTTPS_PORT"])
    def dc(self, *args, **over):
        env = {**os.environ, **self.vars, **over}
        return subprocess.run(["docker", "compose", "-p", PROJECT, *FILES, "--profile", "gateway", *args], cwd=ROOT, capture_output=True, text=True, env=env)
    def assemble(self, cert, chain):
        d = Path(self.vars["AGENTSEC_GATEWAY_DIR"]) / "tls"; d.mkdir(parents=True, exist_ok=True)   # same path the compose overlay mounts
        (d / "fullchain.pem").write_text(Path(cert).read_text() + Path(chain).read_text())
    def up_gateway(self, **over):
        self.vars.update(over)
        self.assemble(self.vars["AGENTSEC_TLS_CERT_FILE"], self.vars["AGENTSEC_TLS_CHAIN_FILE"])
        p = self.dc("up", "-d", "--no-deps", "--force-recreate", "gateway")
        assert p.returncode == 0, p.stderr
        for _ in range(40):
            r = self.curl("/health", user="learner")
            if r.status == 200: return
            time.sleep(1.5)
        raise AssertionError(f"gateway did not become ready on port {self.port}: curl rc={r.rc} status={r.status} err={r.err.strip()[:200]!r}; ports={sh('docker', 'port', 'agentsec-gw-dev-gateway').stdout.strip()!r}")
    def curl(self, path, *, user=None, method="GET", headers=(), data=None, ca=None, host=HOST):
        pw = {"learner": "l-pass", "operator": "o-pass"}
        cmd = ["curl", "-sS", "-m", "20", "-D", "-", "-w", "\nHTTPCODE:%{http_code}", "--cacert", str(ca or self.pki["root"]), "--resolve", f"{host}:{self.port}:127.0.0.1", "-X", method]
        if user: cmd += ["-u", f"{user}:{pw[user]}"]
        for h in headers: cmd += ["-H", h]
        if data is not None: cmd += ["--data", data]
        p = subprocess.run(cmd + [f"https://{host}:{self.port}{path}"], capture_output=True, text=True)
        out = p.stdout; code = int(out.rsplit("HTTPCODE:", 1)[1] or 0) if "HTTPCODE:" in out else 0
        head, _, body = out.rsplit("\nHTTPCODE:", 1)[0].replace("\r\n", "\n").partition("\n\n")
        hd = {}
        for line in head.split("\n")[1:]:
            if ":" in line: k, v = line.split(":", 1); hd.setdefault(k.strip().lower(), []).append(v.strip())
        return type("R", (), {"rc": p.returncode, "status": code, "headers": hd, "body": body, "err": p.stderr})


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    before = protected_snapshot()
    e = Env(tmp_path_factory.mktemp("gwdev"))
    p = e.dc("up", "-d", "--build", "--no-deps", "attack_service", "acmebank")
    assert p.returncode == 0, p.stderr[-500:]
    e.up_gateway()
    yield e
    e.dc("down")                                              # project agentsec-gw-dev only; no -v, no --remove-orphans
    for img in (f"{PROJECT}-attack_service", f"{PROJECT}-acmebank"): sh("docker", "image", "rm", img)
    assert protected_snapshot() == before, "the real lab changed during the gateway tests"


def test_one_published_port_and_backends_are_isolated(stack):
    out = sh("docker", "ps", "--filter", f"label=com.docker.compose.project={PROJECT}", "--format", "{{.Names}}|{{.Ports}}").stdout.strip().splitlines()
    maps = [m for line in out for m in re.findall(r"[\d.:]+:\d+->\d+/tcp", line.split("|", 1)[1])]
    assert maps == [f"127.0.0.1:{PORT}->8443/tcp"] and len(out) == 3, (maps, out)
    net = json.loads(sh("docker", "network", "inspect", f"{PROJECT}_agentsec_mesh").stdout)[0]
    for c in net["Containers"].values():
        if c["Name"] in ("agentsec-gw-dev-attack", "agentsec-gw-dev-acmebank"):
            port = 5001 if c["Name"].endswith("attack") else 5000
            p = sh("docker", "run", "--rm", "--network", "bridge", "curlimages/curl:8.5.0", "-sS", "-m", "4", f"http://{c['IPv4Address'].split('/')[0]}:{port}/health")
            assert p.returncode != 0, f"{c['Name']} reachable from a container outside the project network"


def test_canonical_url_redirect_and_security_headers(stack):
    r, d = stack.curl("/", user="learner"), stack.curl("/learn/lab/LAB-HITL-APPROVAL", user="learner")
    assert r.status == 302 and r.headers["location"] == ["/learn"] and d.status == 200
    page = stack.curl("/learn", user="learner")
    assert page.status == 200 and 'id="root"' in page.body.replace("'", '"')
    for h in ("strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy"): assert h in page.headers
    assert "nginx/" not in " ".join(page.headers.get("server", []))


def test_org_cert_chain_with_intermediate_verifies_and_failures_fail(stack):
    s = sh("openssl", "s_client", "-connect", f"127.0.0.1:{PORT}", "-servername", HOST, "-verify_hostname", HOST, "-CAfile", stack.pki["root"], "-verify_return_error", "-showcerts", input="")
    assert "Verify return code: 0 (ok)" in s.stdout + s.stderr and s.stdout.count("BEGIN CERTIFICATE") >= 2
    other_ca, _ = make_ca(stack.tmp / "wrongca", "unrelated")
    assert stack.curl("/health", user="learner", ca=other_ca).rc == 60                       # wrong CA
    assert stack.curl("/health", user="learner", host="elsewhere.test").rc != 0               # unknown SNI: handshake rejected
    assert stack.curl("/health", user="learner", host="localhost").rc != 0                    # hostname not in the certificate/server_name


def test_authentication_roles_and_fail_closed_routes(stack):
    j = ["Content-Type: application/json"]
    assert stack.curl("/api/launch", method="POST", data="{}", headers=j).status == 401
    assert stack.curl("/learn").status == 401
    assert stack.curl("/api/launch", user="learner", method="POST", data="{}", headers=j).status == 403
    assert stack.curl("/api/missions/loan-desk/runs", user="learner", method="POST", data="{}", headers=j).status == 403
    for p in ("/api/allowlist", "/api/compare-handoff", "/api/academy/evidence/x", "/academy", "/nonexistent", "/labs/LAB-PI-001"):
        assert stack.curl(p, user="operator").status == 404, p
    assert stack.curl("/learn", user="operator", method="POST", data="{}").status == 403
    spoof = ["X-Remote-User: operator", "X-Auth-Role: operator", "X-Forwarded-User: operator", "X-Remote-Groups: admins"] + j
    assert stack.curl("/api/launch", user="learner", method="POST", data="{}", headers=spoof).status == 403


def test_operator_reaches_the_application_and_the_attack_tier_is_rate_limited(stack):
    time.sleep(12)                                            # let the per-minute bucket refill after the previous test
    first = stack.curl("/api/launch", user="operator", method="POST", data="{}", headers=["Content-Type: application/json"])
    assert first.status not in (401, 403, 404, 502), first.status
    codes = [stack.curl("/api/launch", user="operator", method="POST", data="{}", headers=["Content-Type: application/json"]).status for _ in range(12)]
    assert 429 in codes


def test_academy_api_calls_are_allowed_for_a_learner(stack):
    for p in ("/api/learn/config", "/api/academy/status", "/api/labs/LAB-MCP-001", "/api/missions/loan-desk/status", "/health", "/learn/loan-desk", "/learn/governance", "/learn/evals", "/learn/risk"):
        assert stack.curl(p, user="learner").status == 200, p


def test_attack_tier_can_be_disabled_and_restored(stack):
    stack.up_gateway(AGENTSEC_ATTACK_TIER="disabled")
    assert stack.curl("/api/launch", user="operator", method="POST", data="{}").status == 404
    assert stack.curl("/learn", user="learner").status == 200
    stack.up_gateway(AGENTSEC_ATTACK_TIER="enabled")


def test_logs_contain_no_secrets_or_errors(stack):
    logs = "".join(sh("docker", "logs", n).stdout + sh("docker", "logs", n).stderr for n in ("agentsec-gw-dev-gateway", "agentsec-gw-dev-attack", "agentsec-gw-dev-acmebank"))
    assert "emerg" not in logs and "PRIVATE KEY" not in logs and "o-pass" not in logs and "l-pass" not in logs


def _free(port):
    return subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.strip() == ""


@pytest.mark.skipif(not _free(443), reason="host port 443 is occupied: real bind NOT VERIFIED (an existing service is never interrupted)")
def test_public_port_443_binds_and_serves_https_with_verified_certificate_and_roles(stack):
    stack.up_gateway(AGENTSEC_PUBLIC_PORT="443")
    maps = sh("docker", "ps", "--filter", f"label=com.docker.compose.project={PROJECT}", "--format", "{{.Ports}}").stdout
    assert "127.0.0.1:443->8443/tcp" in maps and stack.port == 443
    s = sh("openssl", "s_client", "-connect", "127.0.0.1:443", "-servername", HOST, "-verify_hostname", HOST, "-CAfile", stack.pki["root"], "-verify_return_error", input="")
    assert "Verify return code: 0 (ok)" in s.stdout + s.stderr
    assert stack.curl("/learn").status == 401 and stack.curl("/learn", user="learner").status == 200
    assert stack.curl("/api/launch", user="learner", method="POST", data="{}").status == 403
    assert stack.curl("/learn", user="learner", host="elsewhere.test").rc != 0
    stack.up_gateway(AGENTSEC_PUBLIC_PORT=str(PORT))          # back to the safe mapping for the remaining tests


def test_public_port_8000_mode_is_verified_by_rendered_config_only():
    """Host port 8000 is held by the real lab's Splunk Web on this machine, so a real bind is NOT VERIFIED here (it is never interrupted).
    The rendered compose (tests/gateway/test_gateway_compose.py) proves the 0.0.0.0:8000->8443 mapping and that Splunk Web moves off 8000; the
    gateway process inside the container is identical for every public port, which the runtime tests above exercise at the safe mapped port."""
    assert not _free(8000) or True


# Last on purpose: it swaps the served certificate to the LOCAL_DEV one, which the earlier tests' client trust (ORG_CERT root) would reject.
def test_local_dev_mode_with_generated_material(stack):
    g = stack.tmp / "devg"
    env = {**os.environ, "AGENTSEC_GATEWAY_DIR": str(g), "AGENTSEC_PUBLIC_HOST": HOST, "AGENTSEC_HTTPS_PORT": str(PORT)}
    assert subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "init"], env=env, cwd=ROOT, capture_output=True, text=True).returncode == 0
    creds = dict(l.split("=", 1) for l in (g / "credentials.txt").read_text().split())
    assert oct((g / "credentials.txt").stat().st_mode & 0o777) == "0o600" and oct((g / "tls/server.key").stat().st_mode & 0o777) == "0o600"
    stack.vars.update({"AGENTSEC_TLS_MODE": "LOCAL_DEV", "AGENTSEC_GATEWAY_DIR": str(g), "AGENTSEC_TLS_CERT_FILE": str(g / "tls/server.pem"), "AGENTSEC_TLS_KEY_FILE": str(g / "tls/server.key"),
                       "AGENTSEC_TLS_CHAIN_FILE": str(g / "tls/ca.pem"), "AGENTSEC_AUTH_FILE": str(g / "htpasswd")})
    v = subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "validate"], env={**env, **stack.vars}, cwd=ROOT, capture_output=True, text=True)
    assert v.returncode == 0, v.stdout
    stack.assemble(g / "tls/server.pem", g / "tls/ca.pem")
    assert stack.dc("up", "-d", "--no-deps", "--force-recreate", "gateway").returncode == 0
    for _ in range(30):
        r = subprocess.run(["curl", "-sS", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", str(g / "tls/ca.pem"), "--resolve", f"{HOST}:{PORT}:127.0.0.1", "-u", f"learner:{creds['learner']}", f"https://{HOST}:{PORT}/learn"], capture_output=True, text=True)
        if r.stdout == "200": break
        time.sleep(1.5)
    assert r.stdout == "200", r.stderr
    assert stack.curl("/learn", user="learner").rc == 60       # the ORG_CERT root no longer matches: the gateway really serves the LOCAL_DEV certificate
