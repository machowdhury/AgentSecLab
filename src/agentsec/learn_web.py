"""The unified Academy shell: serves the committed React build at /learn and the deployment config it reads.

GET-only. It decides nothing and runs nothing: runs, verification and evidence stay on the existing /api/missions/loan-desk/* and
/api/academy/* routes. Service URLs are derived from the hostname the browser used, so the UI never hard-codes localhost or a port
that belongs to the lab machine instead of the learner's computer.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, Response, jsonify, request

from agentsec.academy_web import _no_store
from agentsec.mission_loan_desk import (
    ATTACK_NOTES, BOUNDARIES, DEFAULT_APPLICATION, DURATION_MINUTES, NORMAL_NOTES, OBJECTIVES, PREREQUISITES,
)

STATIC_LEARN = Path(__file__).resolve().parent / "static" / "learn"
SPLUNK_WEB_PORT = 8000
ACMEBANK_PUBLIC_PORT = int(os.environ.get("AGENTSEC_ACMEBANK_PUBLIC_PORT", "5000"))


def _browser_origin(host_header: str, scheme: str, port: int) -> str:
    """scheme://hostname:port using the hostname the browser used to reach this service (IPv6 literals keep their brackets)."""
    raw = (host_header or "").split(",")[0].strip()
    hostname = raw
    if raw.startswith("[") and "]" in raw:
        hostname = raw[: raw.index("]") + 1]
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        hostname = raw.rsplit(":", 1)[0]
    if not hostname or hostname in {"0.0.0.0", "::"}:
        hostname = "127.0.0.1"
    return f"{scheme if scheme in ('http', 'https') else 'http'}://{hostname}:{port}"


def gateway_mode() -> bool:
    """True when the opt-in HTTPS gateway fronts this service (docker-compose.gateway.yml sets AGENTSEC_GATEWAY_MODE=1)."""
    return os.environ.get("AGENTSEC_GATEWAY_MODE") == "1"


def ctf_url(host_header: str, gateway: bool) -> str | None:
    """Where the Advanced CTF page is, or None when it is not reachable from this browser. Behind the gateway only when the CTF overlay is on;
    direct only on a loopback host name (the CTF refuses everything else)."""
    if gateway:
        return "/attack-service/ctf" if os.environ.get("AGENTSEC_CTF_ALLOW_GATEWAY") == "1" else None
    raw = (host_header or "").split(",")[0].strip().lower()
    name = raw[1: raw.index("]")] if raw.startswith("[") and "]" in raw else raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
    return "/ctf" if name in {"localhost", "127.0.0.1", "::1"} else None


def build_config(host_header: str, scheme: str, version: str, *, gateway: bool = False) -> dict:
    """Behind the gateway, Splunk Web is not published (null: the UI links to nothing); the classic pages are reached under /attack-service/."""
    return {
        "version": version,
        "gateway": gateway,
        "urls": {
            "splunk_web": None if gateway else _browser_origin(host_header, scheme, SPLUNK_WEB_PORT),
            # Gateway: same-origin paths of the approved classic-UI prefix (gateway_prefix.PREFIX). acmebank is the READ-ONLY view the Attack
            # Service renders; the real AcmeBank app is never routed. Direct mode: attack_service is not needed (the classic pages are at the root).
            "acmebank": "/attack-service/acmebank" if gateway else _browser_origin(host_header, scheme, ACMEBANK_PUBLIC_PORT),
            **({"attack_service": "/attack-service/"} if gateway else {}),
            **({"ctf": u} if (u := ctf_url(host_header, gateway)) else {}),      # additive: absent when the CTF cannot answer this browser
        },
        "mission": {
            "id": "loan-desk",
            "lab_id": "LAB-LOANDESK-001",
            "duration_minutes": DURATION_MINUTES,
            "objectives": list(OBJECTIVES),
            "prerequisites": list(PREREQUISITES),
            "boundaries": list(BOUNDARIES),
            "default_application": dict(DEFAULT_APPLICATION),
            "normal_notes": NORMAL_NOTES,
            "attack_notes": ATTACK_NOTES,
        },
    }


def register_learn(app: Flask, *, version: str) -> None:
    @app.get("/learn")
    @app.get("/learn/")
    @app.get("/learn/<path:rest>")
    def learn(rest: str = ""):
        index = STATIC_LEARN / "index.html"
        if not index.is_file():
            return _no_store(Response("The Academy UI has not been built. Run scripts/build_academy_ui.sh.", status=503, mimetype="text/plain"))
        return _no_store(Response(index.read_text(encoding="utf-8"), mimetype="text/html"))

    @app.get("/api/learn/config")
    def learn_config():
        return _no_store(jsonify(build_config(request.host, request.scheme, version, gateway=gateway_mode())))
