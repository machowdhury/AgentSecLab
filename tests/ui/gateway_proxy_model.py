"""In-test reverse proxy that applies tests/gateway/nginx_model.Gateway (a MODEL of the gateway's path mapping, auth and header overwriting).
It is NOT nginx: no TLS, no real nginx parsing. It only lets a real browser exercise the apps behind the /attack-service prefix."""
from __future__ import annotations

import http.client
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from nginx_model import Gateway  # noqa: E402

HOP = {"connection", "transfer-encoding", "keep-alive", "content-length", "server", "date"}


def start(upstream_port: int, host: str = "127.0.0.1", **gw_kw):   # gw_kw: extra Gateway(...) options (ctf, ctf_secret, scheme, ...)
    log: list[tuple[str, str, int, str | None]] = []   # (method, client target, status, upstream path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    gw = Gateway(host=host, port=str(srv.server_port), **gw_kw)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):  # noqa: D401
            pass

        def handle_any(self):
            d = gw.handle(self.command, self.path, {k: v for k, v in self.headers.items()})
            if d.status != 200:
                self.send_response(d.status)
                if d.status == 401: self.send_header("WWW-Authenticate", 'Basic realm="AgentSecLab"')
                if d.redirect: self.send_header("Location", d.redirect)
                self.send_header("Content-Length", "0"); self.end_headers()
                log.append((self.command, self.path, d.status, None)); return
            c = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=30)
            c.request(self.command, d.path, headers=d.headers)
            r = c.getresponse(); body = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in HOP: self.send_header(k, v)
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            if self.command != "HEAD": self.wfile.write(body)
            log.append((self.command, self.path, r.status, d.path))

        do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = handle_any

    srv.RequestHandlerClass = H
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, log
