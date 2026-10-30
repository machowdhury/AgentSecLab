"""Classic Attack UI pages behind the HTTPS gateway's approved prefix.

The gateway serves the classic pages (labs, the read-only AcmeBank view, a few Academy pages) under /attack-service/ and tells this service
so with X-Forwarded-Prefix. The header is honoured ONLY when AGENTSEC_GATEWAY_MODE=1 and its value is exactly PREFIX (never an arbitrary
client-supplied value, never in direct mode); the gateway overwrites it on every proxied request ("" outside the prefix).
Templates keep their root-relative links, so direct mode is untouched: in a prefixed response the page links are rewritten here, once.
Only page links move. /static/ and /api/ stay at the root, where the gateway already routes them (launch POSTs keep their operator-tier path).
"""
from __future__ import annotations

import re

from flask import Flask, request

from agentsec.learn_web import gateway_mode

PREFIX = "/attack-service"
# Must equal the gateway's allowlist (gateway.conf.template, location ~ ^/attack-service/...; ctf pages: gateway/ctf-enabled.conf, only when enabled): a link the gateway would 404 is left untouched, not prefixed.
_PAGE = re.compile(r"^/(?:|labs/[A-Za-z0-9_-]+|acmebank|ctf|ctf/scoreboard|ctf/[A-Za-z0-9_-]+|academy/(?:home|foundations|path|status|missions/loan-desk|labs/[A-Za-z0-9_-]+))(?:[?#].*)?$")
_HREF = re.compile(r'(\bhref=")(/[^"]*)"')
_SPLUNK = re.compile(r'(<a\b[^>]*?)\bhref="/en-US[^"]*"')


def active() -> bool:
    return gateway_mode() and request.headers.get("X-Forwarded-Prefix") == PREFIX


def _link(m: re.Match) -> str:
    url = m.group(2)
    if url == "/academy":
        url = "/learn"                       # the canonical Academy entry (React) is served at the root
    elif _PAGE.match(url):
        url = PREFIX + url
    return f'{m.group(1)}{url}"'


def rewrite_html(html: str) -> str:
    # Splunk Web is not published through the gateway: keep the element (page scripts look it up by id) but make it inert and hidden.
    html = _SPLUNK.sub(r'\1hidden aria-disabled="true" data-gateway-unavailable="splunk"', html)
    return _HREF.sub(_link, html)


def install_gateway_prefix(app: Flask) -> None:
    @app.after_request
    def _prefix(response):
        if response.status_code == 200 and response.mimetype == "text/html" and not response.direct_passthrough and active():
            response.set_data(rewrite_html(response.get_data(as_text=True)))
        return response
