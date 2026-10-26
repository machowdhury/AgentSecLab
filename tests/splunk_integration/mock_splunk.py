"""Deterministic MOCK Splunk management endpoint over real TLS (test CA). It is NOT Splunk: it lets us test the client's TLS, auth,
timeout, size and parsing behaviour. Passing against it proves nothing about real Splunk Enterprise or Splunk Cloud compatibility."""
import ssl, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOK_ADMIN, TOK_SEARCH_ONLY, TOK_NO_SEARCH, TOK_REDIRECT, TOK_SLOW = "t-admin", "t-search-only", "t-no-search", "t-redirect", "t-slow"


class Handler(BaseHTTPRequestHandler):
    log_message = lambda *a: None
    seen = []                                     # (method, path-with-query, authorization-present, form) for assertions

    def _send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _tok(self):
        a = self.headers.get("Authorization", ""); return a[7:] if a.startswith("Bearer ") else None

    def do_GET(self):
        tok, path = self._tok(), urlsplit(self.path).path
        type(self).seen.append(("GET", self.path, tok is not None, None))
        if tok in (None, "bad") or tok not in (TOK_ADMIN, TOK_SEARCH_ONLY, TOK_NO_SEARCH, TOK_REDIRECT, TOK_SLOW):
            return self._send(401, b"unauthorized")
        if path == "/services/server/info":
            if tok == TOK_REDIRECT: return self._send(302, b"", [("Location", "http://evil.invalid/steal")])
            if tok == TOK_SEARCH_ONLY: return self._send(403, b"forbidden")
            return self._send(200, b'{"entry":[{"content":{"version":"10.2"}}]}')
        self._send(404)

    def do_POST(self):
        tok = self._tok(); n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode()); spl = (form.get("search") or [""])[0]
        type(self).seen.append(("POST", self.path, tok is not None, spl))
        if tok not in (TOK_ADMIN, TOK_SEARCH_ONLY, TOK_NO_SEARCH, TOK_SLOW, TOK_REDIRECT): return self._send(401, b"unauthorized")
        if tok == TOK_NO_SEARCH: return self._send(403, b"forbidden")
        if urlsplit(self.path).path != "/services/search/v2/jobs/export": return self._send(404)
        if tok == TOK_SLOW or "SLOWSEARCH" in spl:
            time.sleep(4); return self._send(200, b"ok\n1\n")
        if "BIGRESPONSE" in spl: return self._send(200, b"x" * (3 * 1024 * 1024))
        if "makeresults" in spl: return self._send(200, b"ok\n1\n")
        if "r-present" in spl: return self._send(200, b"count,n\n5,5\n")       # both column names the application's searches use
        if "r-absent" in spl: return self._send(200, b"count,n\n0,0\n")
        if "ROWS" in spl: return self._send(200, ("a,b\n" + "".join(f"{i},v{i}\n" for i in range(200))).encode())
        self._send(200, b"events\n3\n")


def start(cert, key, host="127.0.0.1"):
    s = ThreadingHTTPServer((host, 0), Handler)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(cert, key)
    s.socket = c.wrap_socket(s.socket, server_side=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s
