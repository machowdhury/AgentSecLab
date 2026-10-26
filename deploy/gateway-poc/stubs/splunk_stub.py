"""NOT SPLUNK. Mimics proxy-relevant behaviours only: a CSRF cookie, session cookie, absolute-URL redirects, header echo.
A pass against this stub proves gateway mechanics, not Splunk compatibility."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

USER, PASSWORD = os.environ.get("STUB_USER", "poc-splunk"), os.environ.get("STUB_PASSWORD", "poc-splunk-pass")
CSRF, SESSION = "stubcsrf-token-1", "stubsession-1"
ABS = "http://splunk-stub:8000"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def cookies(self):
        return dict(p.strip().split("=", 1) for p in self.headers.get("Cookie", "").split(";") if "=" in p)
    def send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers: self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/en-US/account/login":
            return self.send(200, b"<form>login</form>", [("Set-Cookie", f"splunkweb_csrf_token_8000={CSRF}; Path=/"), ("Content-Type", "text/html")])
        if p.startswith("/static/"): return self.send(200, b"/* asset */", [("Content-Type", "application/javascript")])
        if p == "/_echo": return self.send(200, json.dumps({k.lower(): v for k, v in self.headers.items()}).encode(), [("Content-Type", "application/json")])
        if p == "/en-US/account/logout":
            return self.send(303, b"", [("Location", f"{ABS}/en-US/account/login"), ("Set-Cookie", "session_id_8000=; Path=/; Max-Age=0")])
        if p == "/en-US/app/agentsec/home":
            if self.cookies().get("session_id_8000") != SESSION: return self.send(303, b"", [("Location", f"{ABS}/en-US/account/login")])
            return self.send(200, b"<h1>agentsec app (stub)</h1>", [("Content-Type", "text/html")])
        self.send(404, b"nope")
    def do_POST(self):
        p, n = self.path.split("?")[0], int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode()
        if p == "/en-US/account/login":
            f = parse_qs(body)
            ok = f.get("username") == [USER] and f.get("password") == [PASSWORD] and self.cookies().get("splunkweb_csrf_token_8000") == CSRF
            if not ok: return self.send(401, b"bad login")
            return self.send(303, b"", [("Location", f"{ABS}/en-US/app/agentsec/home"), ("Set-Cookie", f"session_id_8000={SESSION}; Path=/; HttpOnly")])
        if p == "/en-US/splunkd/__raw/action":
            if self.headers.get("X-Splunk-Form-Key") != self.cookies().get("splunkweb_csrf_token_8000") or self.cookies().get("session_id_8000") != SESSION:
                return self.send(403, b"csrf")
            return self.send(200, b"done")
        self.send(404, b"nope")


ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
