"""Installer-managed Splunk search access: the in-container provisioning script (run for real against a mock management endpoint over TLS), the host
side that writes the access directory, and the loop back through the REST client. MOCK ONLY: real Splunk behaviour is verified at checkpoint 5."""
from __future__ import annotations

import json, os, secrets, ssl, stat, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests" / "gateway")]
from gwhelpers import needs_openssl                                         # noqa: E402
from agentsec import splunk_client as sc                                     # noqa: E402
from agentsec.installer import splunk_access as sa                           # noqa: E402

pytestmark = needs_openssl
ADMIN_PW = "admin-pw"
CN = "SplunkServerDefaultCert"


def self_signed(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", f"/CN={CN}", "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"),
                    "-addext", "basicConstraints=CA:FALSE", "-addext", "keyUsage=digitalSignature,keyEncipherment", "-addext", "extendedKeyUsage=serverAuth"], check=True, capture_output=True)
    return d / "c.pem", d / "k.pem"


class Mgmt:
    """A tiny stand-in for Splunk's management port: roles, users, tokens and a search export, with switches for the failure modes."""
    def __init__(self, cert, key, *, kv_ready=True, imports=False, leaky=False, user_roles=None, probe=None):
        self.kv_ready, self.imports, self.leaky, self.user_roles, self.probe = kv_ready, imports, leaky, user_roles, probe
        self.roles, self.users, self.tokens, self.log = {}, {}, set(), []
        outer = self

        class H(BaseHTTPRequestHandler):
            log_message = lambda *a: None

            def _send(self, code, body=""):
                b = body.encode(); self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

            def _who(self):
                import base64
                a = self.headers.get("Authorization", "")
                if a.startswith("Bearer "): return ("agentsec_search", "token") if a[7:] in outer.tokens else None
                if a.startswith("Basic "):
                    u, _, p = base64.b64decode(a[6:]).decode().partition(":")
                    if u == "admin" and p == ADMIN_PW: return ("admin", "admin")
                    if u in outer.users and outer.users[u]["password"] == p: return (u, "user")
                return None

            def _form(self):
                return {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()).items()}

            def do_GET(self):
                who, path = self._who(), urlsplit(self.path).path
                outer.log.append(("GET", path))
                if not who: return self._send(401)
                if who[1] != "admin": return self._send(403)                       # a search-only identity may not read server info
                if path.startswith("/services/authentication/users/"):
                    u = outer.users.get(path.rsplit("/", 1)[1])
                    if not u: return self._send(404)
                    return self._send(200, json.dumps({"entry": [{"content": {"roles": outer.user_roles if outer.user_roles is not None else [u["roles"]]}}]}))
                if path.startswith("/services/authorization/roles/"):
                    r = outer.roles.get(path.rsplit("/", 1)[1])
                    if not r: return self._send(404)
                    c = {"capabilities": r["capabilities"], "imported_roles": ["user"] if outer.imports else [], "srchIndexesAllowed": r["srchIndexesAllowed"]}
                    return self._send(200, json.dumps({"entry": [{"content": c}]}))
                self._send(404)

            def do_POST(self):
                who, path, form = self._who(), urlsplit(self.path).path, self._form()
                outer.log.append(("POST", path))
                if not who: return self._send(401)
                if path == "/services/search/v2/jobs/export":
                    if "makeresults" in form["search"]: return self._send(200, "ok\n1\n" if "table ok" in form["search"] else "_time,ok\n2026-10-30T13:00:00.000+00:00,1\n")      # real Splunk adds _time to makeresults
                    if "index=_internal" in form["search"]:
                        if outer.probe is not None: return self._send(*outer.probe)
                        return self._send(200, "count\n" + ("7" if outer.leaky else "0") + "\n")
                    return self._send(200, "events\n3\n")
                if who[1] != "admin": return self._send(403)
                if path == "/services/authorization/roles":
                    if form["name"] in outer.roles: return self._send(409)
                    outer.roles[form["name"]] = {"capabilities": form["capabilities"].split(","), "srchIndexesAllowed": form["srchIndexesAllowed"].split(",")}; return self._send(201)
                if path.startswith("/services/authorization/roles/"):
                    outer.roles[path.rsplit("/", 1)[1]] = {"capabilities": form["capabilities"].split(","), "srchIndexesAllowed": form["srchIndexesAllowed"].split(",")}; return self._send(200)
                if path == "/services/authentication/users":
                    if form["name"] in outer.users: return self._send(400, json.dumps({"messages": [{"type": "ERROR", "text": "Cannot create user that already exists: " + form["name"]}]}))      # real Splunk 10.2.7: 400, not 409
                    outer.users[form["name"]] = {"password": form["password"], "roles": form["roles"]}; return self._send(201)
                if path.startswith("/services/authentication/users/"):
                    outer.users[path.rsplit("/", 1)[1]]["password"] = form["password"]; return self._send(200)
                if path == "/services/authorization/tokens":
                    if not outer.kv_ready: return self._send(503, "KVStore is not ready. Token auth system will not work.")
                    tok = "tok-" + secrets.token_hex(8); outer.tokens.add(tok)
                    return self._send(201, json.dumps({"entry": [{"content": {"token": tok}}]}))
                self._send(404)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(cert, key)
        self.srv.socket = c.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_port

    def close(self): self.srv.shutdown()


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return self_signed(tmp_path_factory.mktemp("mgmt"))


@pytest.fixture
def mgmt(cert):
    made = []
    def make(**kw):
        m = Mgmt(*cert, **kw); made.append(m); return m
    yield make
    for m in made: m.close()


def run_script(port, mode="auto", index="agentsec_telemetry", host="127.0.0.1"):
    env = {**os.environ, "AGENTSEC_ACCESS_HOST": host, "AGENTSEC_ACCESS_PORT": str(port), "AGENTSEC_ACCESS_OPENSSL": "openssl", "SPLUNK_PASSWORD": ADMIN_PW}
    p = subprocess.run([sys.executable, "-c", sa.SCRIPT, index, mode], capture_output=True, text=True, env=env, timeout=60)
    return p.returncode, p.stdout + p.stderr


def result_of(out):
    return json.loads([ln for ln in out.splitlines() if ln.startswith("AGENTSEC_RESULT ")][-1][len("AGENTSEC_RESULT "):])


# ------------------------------------------------------------------ the in-container script
def test_token_path_when_the_kv_store_is_ready(mgmt, cert):
    m = mgmt()
    rc, out = run_script(m.port)
    assert rc == 0, out
    doc = result_of(out)
    assert doc["auth"] == "bearer" and doc["credential"] in m.tokens and doc["server_name"] == CN and doc["user"] == "agentsec_search"
    assert doc["ca_pem"].strip() == Path(cert[0]).read_text().strip() and doc["token_expires"].count("-") == 2 and doc["fallback"] == ""
    assert m.roles["agentsec_search"] == {"capabilities": ["search"], "srchIndexesAllowed": ["agentsec_telemetry"]}


def test_auto_falls_back_to_the_search_only_password_when_tokens_are_unavailable(mgmt):
    m = mgmt(kv_ready=False)
    rc, out = run_script(m.port)
    doc = result_of(out)
    assert rc == 0 and doc["auth"] == "basic" and doc["credential"] == m.users["agentsec_search"]["password"] and doc["fallback"] == "kvstore_not_ready"
    assert "kvstore_not_ready" in out


def test_token_only_mode_refuses_instead_of_silently_downgrading(mgmt):
    m = mgmt(kv_ready=False)
    rc, out = run_script(m.port, mode="bearer")
    assert rc == 1 and "AGENTSEC_ERROR token_unavailable kvstore_not_ready" in out and "AGENTSEC_RESULT" not in out


def test_basic_only_mode_never_asks_for_a_token(mgmt):
    m = mgmt()
    rc, out = run_script(m.port, mode="basic")
    assert rc == 0 and result_of(out)["auth"] == "basic" and ("POST", "/services/authorization/tokens") not in m.log


def test_a_role_that_is_not_search_only_is_refused(mgmt):
    rc, out = run_script(mgmt(imports=True).port)
    assert rc == 1 and "AGENTSEC_ERROR role_not_least_privilege" in out and "AGENTSEC_RESULT" not in out


@pytest.mark.parametrize("probe,ok", [((500, "boom"), False), ((200, ""), False), ((200, "count\n"), False), ((404, "x"), False), ((403, "denied"), True), ((400, "bad index"), True), ((200, "count\n0\n"), True)])
def test_the_other_index_probe_needs_an_explicit_zero_or_a_refusal_never_silence(mgmt, probe, ok):
    rc, out = run_script(mgmt(probe=probe).port)
    assert (rc == 0) is ok and (ok or "AGENTSEC_ERROR index_not_restricted" in out)


def test_a_user_with_extra_roles_is_refused(mgmt):
    rc, out = run_script(mgmt(user_roles=["agentsec_search", "power"]).port)
    assert rc == 1 and "AGENTSEC_ERROR user_not_least_privilege" in out


def test_the_token_expiry_is_an_absolute_date(mgmt):
    import re
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", result_of(run_script(mgmt().port)[1])["token_expires"])


def test_an_identity_that_can_read_other_indexes_is_refused(mgmt):
    rc, out = run_script(mgmt(leaky=True).port)
    assert rc == 1 and "AGENTSEC_ERROR index_not_restricted" in out and "AGENTSEC_RESULT" not in out


def test_rerunning_updates_in_place_and_rotates_the_password(mgmt):
    m = mgmt(kv_ready=False)
    first = result_of(run_script(m.port)[1])["credential"]
    rc, out = run_script(m.port)
    assert rc == 0 and result_of(out)["credential"] != first and m.users["agentsec_search"]["password"] == result_of(out)["credential"]


def test_a_closed_port_is_not_ready_not_a_failure():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    rc, out = run_script(port)
    assert rc == sa.NOT_READY and "AGENTSEC_ERROR not_ready" in out


def test_bad_arguments_and_a_missing_admin_password_stop_early(mgmt):
    m = mgmt()
    assert "bad_arguments" in run_script(m.port, index="bad index;")[1] and "bad_arguments" in run_script(m.port, mode="digest")[1]
    env = {k: v for k, v in os.environ.items() if k != "SPLUNK_PASSWORD"} | {"AGENTSEC_ACCESS_PORT": str(m.port)}
    p = subprocess.run([sys.executable, "-c", sa.SCRIPT, "agentsec_telemetry", "auto"], capture_output=True, text=True, env=env)
    assert "no_admin_password" in p.stdout and p.returncode == 1


def test_the_script_carries_no_secret_and_no_tls_bypass():
    s = sa.SCRIPT
    assert "CERT_NONE" not in s and "check_hostname" not in s and "-k " not in s and "verify_mode" not in s
    assert s.count("AGENTSEC_RESULT") == 1 and s.rstrip().splitlines()[-1].startswith('print("AGENTSEC_RESULT')      # the only line that carries the credential is the last
    assert "ADMIN_PW" in s and "argv" in s and "sys.argv[3]" not in s                                                   # the admin password comes from the environment, never from an argument


# ------------------------------------------------------------------ host side
def fake_compose(m, calls=None, *, not_ready_first=0):
    state = {"n": 0}

    def compose(argv):
        if calls is not None: calls.append(argv)
        state["n"] += 1
        if state["n"] <= not_ready_first: return sa.NOT_READY, "AGENTSEC_ERROR not_ready x"
        assert argv[:3] == ["exec", "-T", "splunk"]
        script, index, auth = argv[-3], argv[-2], argv[-1]
        assert script == sa.SCRIPT
        return run_script(m.port, auth, index)
    return compose


def test_provision_writes_owner_only_files_and_prints_no_secret(mgmt, tmp_path):
    m, said = mgmt(kv_ready=False), []
    assert sa.provision(tmp_path, fake_compose(m), said.append) is True
    d = tmp_path / sa.ACCESS_DIR
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    for n in ("auth", "credential", "user", "server_name", "ca.pem", "provisioned.json"):
        assert stat.S_IMODE((d / n).stat().st_mode) == 0o600, n
    cred = (d / "credential").read_text()
    assert cred == m.users["agentsec_search"]["password"] and not cred.endswith("\n")
    assert all(cred not in line and "AGENTSEC_RESULT" not in line for line in said) and any(line.startswith("OK") for line in said)
    meta = sa.read_status(tmp_path)
    assert meta["auth"] == "basic" and meta["fallback"] == "kvstore_not_ready" and "credential" not in meta


def test_provisioned_files_drive_the_rest_client_end_to_end(mgmt, tmp_path):
    for kv in (True, False):
        m = mgmt(kv_ready=kv)
        root = tmp_path / f"kv{kv}"; root.mkdir()
        assert sa.provision(root, fake_compose(m), lambda s: None)
        env = {"AGENTSEC_SPLUNK_MODE": "BUNDLED", "AGENTSEC_SPLUNK_REST_URL": f"https://127.0.0.1:{m.port}", "AGENTSEC_SPLUNK_ACCESS_DIR": str(root / sa.ACCESS_DIR), "AGENTSEC_SPLUNK_TIMEOUT_SEC": "5"}
        assert sc.rest_configured(env)
        assert sc.client_for_mode(env).export_rows("| makeresults count=1 | eval ok=1")[0]["ok"] == "1"
        assert {s: st for s, st, _ in sc.client_for_mode(env).diagnose()}["search"] == "PASS"


def test_provision_waits_for_splunk_then_succeeds(mgmt, tmp_path):
    m, said, naps, calls = mgmt(), [], [], []
    ok = sa.provision(tmp_path, fake_compose(m, calls, not_ready_first=3), said.append, sleep=naps.append)
    assert ok and naps == [10, 10, 10] and len(calls) == 4 and sum("waiting for Splunk" in s for s in said) == 1


def test_provision_gives_up_softly_after_the_deadline_and_writes_nothing(tmp_path):
    t = [0.0]
    said = []
    ok = sa.provision(tmp_path, lambda argv: (sa.NOT_READY, ""), said.append, wait_s=30, sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0])
    assert ok is False and any("SPLUNK_ACCESS_UNAVAILABLE" in s and "did not become ready" in s for s in said)
    assert sa.read_status(tmp_path) is None and not (tmp_path / sa.ACCESS_DIR / "credential").exists()


def test_a_stopped_container_is_retried_like_not_ready(tmp_path):
    outs = iter([(1, "service \"splunk\" is not running"), (sa.NOT_READY, "")])
    said, t = [], [0.0]
    sa.provision(tmp_path, lambda a: next(outs, (1, "AGENTSEC_ERROR x y")), said.append, wait_s=100, sleep=lambda s: t.__setitem__(0, t[0] + s), clock=lambda: t[0])
    assert any("waiting for Splunk" in s for s in said)


def test_each_refusal_is_reported_without_writing_files(mgmt, tmp_path):
    for kw, needle in (({"imports": True}, "role_not_least_privilege"), ({"leaky": True}, "index_not_restricted")):
        m, said = mgmt(**kw), []
        root = tmp_path / needle; root.mkdir()
        assert sa.provision(root, fake_compose(m), said.append) is False
        assert any("SPLUNK_ACCESS_UNAVAILABLE" in s and needle in s and "unavailable" in s for s in said) and not (root / sa.ACCESS_DIR / "credential").exists()


def test_unusable_script_output_writes_nothing(tmp_path):
    said = []
    assert sa.provision(tmp_path, lambda a: (0, "STEP x\nAGENTSEC_RESULT {\"auth\": \"basic\"}"), said.append) is False
    assert not (tmp_path / sa.ACCESS_DIR).exists() and any("no usable result" in s for s in said)


def test_a_symbolic_link_directory_is_refused(tmp_path):
    real = tmp_path / "elsewhere"; real.mkdir()
    (tmp_path / sa.ACCESS_DIR).symlink_to(real)
    doc = {"auth": "basic", "credential": "c", "user": "agentsec_search", "server_name": CN, "ca_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"}
    with pytest.raises(OSError):
        sa.write_access(tmp_path, doc)
    assert list(real.iterdir()) == []


def test_invalid_arguments_are_refused_before_anything_runs(tmp_path):
    said = []
    assert sa.provision(tmp_path, lambda a: pytest.fail("must not run"), said.append, auth="digest") is False
    assert sa.provision(tmp_path, lambda a: pytest.fail("must not run"), said.append, index="a b") is False


def test_a_leftover_temp_file_with_a_wide_mode_does_not_leak_the_credential(tmp_path):
    d = tmp_path / sa.ACCESS_DIR; d.mkdir(mode=0o700)
    (d / "credential.tmp").write_text("old"); (d / "credential.tmp").chmod(0o666)
    sa.write_access(tmp_path, {"auth": "basic", "credential": "s3cret", "user": "agentsec_search", "server_name": CN, "ca_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"})
    assert stat.S_IMODE((d / "credential").stat().st_mode) == 0o600 and not (d / "credential.tmp").exists()


def test_an_expired_certificate_message_tells_the_operator_what_to_do(tmp_path):
    said = []
    sa.provision(tmp_path, lambda a: (1, "AGENTSEC_ERROR tls_self_check_failed SSLCertVerificationError certificate has expired"), said.append)
    assert any("expired default certificate must be regenerated" in s for s in said)
