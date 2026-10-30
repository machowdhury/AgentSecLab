"""The three evidence-verification states over REAL HTTPS: the strict client and the probe talk to a local TLS server that behaves like Splunk's search export
(bearer token in, CSV out). Nothing here needs Splunk, Docker or a KV store: the application only sends a token and reads a CSV. SKIPPED without the openssl CLI."""
from __future__ import annotations

import shutil
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentsec import evidence_readiness as er

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI to make a throwaway CA")
TOKEN = "t0ken-" + "x" * 20


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _ca(d, name):
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem", "-subj", f"/CN={name}", "-days", "2", cwd=d)


def _leaf(d, ca, name, san):
    (d / f"{name}.ext").write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\n")
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}", cwd=d)
    _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "2", "-extfile", f"{name}.ext", cwd=d)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    _ca(d, "goodca"); _ca(d, "otherca")
    _leaf(d, "goodca", "good", "DNS:localhost")
    _leaf(d, "goodca", "wrongname", "DNS:not-this-host.example")
    return d


class _Splunk:
    """Answers POST /services/search/v2/jobs/export like Splunk: 401 without the right bearer token, else a CSV with the count."""
    def __init__(self, pki, leaf, count):
        self.requests, self.count = [], count
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "form": urllib.parse.parse_qs(body)})
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    self.send_response(401); self.end_headers(); return
                data = f"n\n{outer.count}\n".encode()
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

            def log_message(self, *a): pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki / f"{leaf}.pem", pki / f"{leaf}.key")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"https://localhost:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


def _env(tmp_path, url, ca, token=TOKEN):
    tf = tmp_path / "token"; tf.write_text(token); tf.chmod(0o600)
    return {"AGENTSEC_SPLUNK_REST_URL": url, "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": str(tf), "AGENTSEC_SPLUNK_CA_BUNDLE_FILE": str(ca), "AGENTSEC_SPLUNK_TIMEOUT_SEC": "5"}


def _verify(tmp_path, env, run_id="run-1"):
    art = tmp_path / "art"; (art / run_id).mkdir(parents=True, exist_ok=True)
    (art / run_id / "events.jsonl").write_text('{"a":1}\n' * 3)
    return er.wait_for_searchable_evidence(run_id, artifacts_dir=art, timeout_seconds=0, probe_fn=er.select_probe(env))


def test_verified_when_splunk_returns_the_events_for_that_run_id(pki, tmp_path):
    s = _Splunk(pki, "good", 3)
    try:
        got = _verify(tmp_path, _env(tmp_path, s.url, pki / "goodca.pem"))
    finally:
        s.close()
    assert (got["verification"], got["splunk_verified"], got["splunk_count"], got["completeness_ok"]) == ("VERIFIED", True, 3, True)
    req = s.requests[0]
    assert req["path"] == "/services/search/v2/jobs/export" and req["auth"] == "Bearer " + TOKEN
    assert "run-1" in req["form"]["search"][0] and req["form"]["output_mode"] == ["csv"]      # the run id is in the search; the token is not


def test_not_verified_when_splunk_answers_and_finds_nothing(pki, tmp_path):
    s = _Splunk(pki, "good", 0)
    try:
        got = _verify(tmp_path, _env(tmp_path, s.url, pki / "goodca.pem"))
    finally:
        s.close()
    assert (got["verification"], got["splunk_verified"], got["splunk_count"]) == ("NOT VERIFIED", False, 0)     # it answered: zero rows is a real answer


@pytest.mark.parametrize("why", ["bad_token", "untrusted_ca", "wrong_host_name"])
def test_unavailable_when_the_check_cannot_run_and_never_reads_as_zero_rows(pki, tmp_path, why):
    leaf = "wrongname" if why == "wrong_host_name" else "good"
    s = _Splunk(pki, leaf, 3)
    try:
        ca = pki / ("otherca.pem" if why == "untrusted_ca" else "goodca.pem")
        env = _env(tmp_path, s.url, ca, token="not-the-token-" + "y" * 10 if why == "bad_token" else TOKEN)
        got = _verify(tmp_path, env)
    finally:
        s.close()
    assert got["verification"] == "VERIFICATION UNAVAILABLE" and got["evidence_state"] == "EVIDENCE_CHECK_UNAVAILABLE" and got["splunk_verified"] is False
    assert got["splunk_count"] is None
    if why != "bad_token":
        assert s.requests == []             # TLS verification failed before the token was ever sent


def test_a_splunk_that_is_not_answering_yet_is_retried_and_reads_not_verified_never_verified(pki, tmp_path):
    env = _env(tmp_path, "https://localhost:1", pki / "goodca.pem")          # nothing listens: Splunk may still be starting, so this is a retryable failure, not "cannot run"
    got = _verify(tmp_path, env)
    assert (got["verification"], got["splunk_verified"], got["splunk_count"], got["probe_error"]) == ("NOT VERIFIED", False, None, "splunk_probe_failed")
