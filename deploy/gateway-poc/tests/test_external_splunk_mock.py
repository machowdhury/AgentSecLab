"""External-Splunk configuration contract against a DISPOSABLE HTTPS mock with its own test CA. Proves the repository's strict
REST probe behaves as specified; it is NOT evidence of compatibility with real Splunk Enterprise or Splunk Cloud."""
import json, ssl, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import pytest
from conftest import POC, check, rec

sys.path.insert(0, str(POC.parents[1] / "src"))
from agentsec.evidence_readiness import probe_splunk_count_rest  # noqa: E402  (the real product code under test)

GOOD, HEC = "good-search-token-0123", "good-hec-token-0123"


def mk_ca_and_cert(d: Path, name, sans):
    d.mkdir(exist_ok=True)
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", f"/CN={name}-ca", "-keyout", d / f"{name}-ca.key", "-out", d / f"{name}-ca.pem",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=mock-splunk", "-keyout", d / f"{name}.key", "-out", d / f"{name}.csr")
    (d / f"{name}.ext").write_text(f"subjectAltName={sans}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", d / f"{name}.csr", "-CA", d / f"{name}-ca.pem", "-CAkey", d / f"{name}-ca.key", "-CAcreateserial", "-days", "2", "-extfile", d / f"{name}.ext", "-out", d / f"{name}.pem")


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0)); a = self.headers.get("Authorization", "")
        if self.path.startswith("/services/search/v2/jobs/export"):
            if a != f"Bearer {GOOD}": return self._r(401, b"unauthorized")
            return self._r(200, b"n\n3\n")
        if self.path.startswith("/services/collector/event"):
            return self._r(200, b'{"text":"Success","code":0}') if a == f"Splunk {HEC}" else self._r(403, b'{"text":"Invalid token","code":4}')
        self._r(404, b"")
    def _r(self, c, b):
        self.send_response(c); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


@pytest.fixture(scope="module")
def mock(tmp_path_factory):
    d = tmp_path_factory.mktemp("extsplunk")
    mk_ca_and_cert(d, "good", "DNS:splunk-ext.poc.test,IP:127.0.0.1")
    mk_ca_and_cert(d, "wrongname", "DNS:someone-else.poc.test")
    mk_ca_and_cert(d, "other", "IP:127.0.0.1")               # a different CA, for the 'wrong trust bundle' case
    servers = {}
    for name in ("good", "wrongname"):
        s = ThreadingHTTPServer(("127.0.0.1", 0), Mock); c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(d / f"{name}.pem", d / f"{name}.key")
        s.socket = c.wrap_socket(s.socket, server_side=True); threading.Thread(target=s.serve_forever, daemon=True).start(); servers[name] = s
    (d / "token").write_text(GOOD)                            # token FILE reference (contract); harness reads it, the probe takes the value
    yield d, servers
    for s in servers.values(): s.shutdown()


def env(d, port, ca, token=GOOD, host="127.0.0.1"):
    return {"AGENTSEC_SPLUNK_PROBE_ENABLED": "true", "AGENTSEC_SPLUNK_PROBE_URL": f"https://{host}:{port}", "AGENTSEC_SPLUNK_PROBE_TOKEN": token, "AGENTSEC_SPLUNK_PROBE_CA_FILE": str(d / ca)}


def test_t18_valid_ca_and_token_accepted(mock):
    d, s = mock; port = s["good"].server_port
    r = probe_splunk_count_rest("run-1", env=env(d, port, "good-ca.pem", token=(d / "token").read_text()))
    check("T18", r["splunk_ok"] is True and r["splunk_count"] == 3, f"strict REST probe over TLS with the mock's CA bundle and a token read from a file: {r}. MOCK ONLY; not real Splunk")


def test_t19_wrong_ca_hostname_and_misconfig_fail_closed(mock):
    d, s = mock; port = s["good"].server_port
    wrong_ca = probe_splunk_count_rest("run-1", env=env(d, port, "other-ca.pem"))
    wrong_host = probe_splunk_count_rest("run-1", env=env(d, s["wrongname"].server_port, "wrongname-ca.pem"))      # trusted CA, but cert is not valid for the host connected to
    no_ca = probe_splunk_count_rest("run-1", env=env(d, port, "missing.pem"))
    http_url = probe_splunk_count_rest("run-1", env={**env(d, port, "good-ca.pem"), "AGENTSEC_SPLUNK_PROBE_URL": f"http://127.0.0.1:{port}"})
    ok = [x["error"] for x in (wrong_ca, wrong_host, no_ca, http_url)] == ["tls_verification_failed", "tls_verification_failed", "probe_misconfigured", "probe_misconfigured"] and not any(x["splunk_ok"] for x in (wrong_ca, wrong_host, no_ca, http_url))
    check("T19", ok, f"wrong CA -> {wrong_ca['error']}; hostname mismatch -> {wrong_host['error']}; missing CA file -> {no_ca['error']}; http:// URL -> {http_url['error']}; none reported success")
    src = (POC.parents[1] / "src/agentsec/evidence_readiness.py").read_text()
    assert "CERT_NONE" not in src and "_create_unverified_context" not in src


def test_t20_invalid_token_and_unreachable(mock):
    d, s = mock; port = s["good"].server_port
    bad = probe_splunk_count_rest("run-1", env=env(d, port, "good-ca.pem", token="wrong-token-value"))
    down = probe_splunk_count_rest("run-1", env=env(d, 1, "good-ca.pem"))
    ok = bad["error"] == "probe_auth_failed" and not bad["splunk_ok"] and down["error"] == "splunk_probe_failed" and not down["splunk_ok"]
    check("T20", ok, f"invalid token -> {bad['error']}; connection refused -> {down['error']}")
    import urllib.request, urllib.error
    ctx = ssl.create_default_context(cafile=str(d / "good-ca.pem"))
    def hec(tok):
        rq = urllib.request.Request(f"https://127.0.0.1:{port}/services/collector/event", data=b"{}", headers={"Authorization": f"Splunk {tok}"}, method="POST")
        try: return urllib.request.urlopen(rq, timeout=10, context=ctx).status
        except urllib.error.HTTPError as e: return e.code
    assert hec(HEC) == 200 and hec("bad") == 403      # HEC URL/CA/token contract on the mock (the real HEC client is the OTel collector: NOT exercised)
