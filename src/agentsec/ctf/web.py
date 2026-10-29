"""Thin HTTP layer for the CTF. Local-only by construction: see _allowed()."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import stat
import threading

from flask import Blueprint, Flask, Response, abort, current_app, jsonify, render_template, request

from agentsec.ctf.challenges import default_scenarios
from agentsec.ctf.service import LABELS, CtfService
from agentsec.ctf.store import CtfStore, StoreError
from agentsec.json_strict import DuplicateJsonKeyError, loads_json_no_duplicate_keys
from agentsec.search_handoff import browser_splunk_web

log = logging.getLogger("agentsec.ctf")
MAX_BODY = 4096
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
GATEWAY_OPT_IN = "AGENTSEC_CTF_ALLOW_GATEWAY"      # must be "1"; without it a non-loopback client is always refused
GATEWAY_HEADER = "X-Remote-User"                   # set by gateway/identity-headers.conf from the authenticated user
GATEWAY_SECRET_ENV = "AGENTSEC_CTF_GATEWAY_SECRET"           # shared secret the gateway injects in GATEWAY_SECRET_HEADER (or ..._FILE)
GATEWAY_SECRET_HEADER = "X-AgentSec-Gateway-Secret"

bp = Blueprint("ctf", __name__)


def _loopback_addr(addr: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(addr or "")
    except ValueError:
        return False
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def _hostname(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


_secret_cache: dict = {}


def _gateway_secret() -> bytes | None:
    """Env value, or a 0600-style file (group/world-readable is refused), both stripped; the file is re-read only when its mtime/size change."""
    val = (os.environ.get(GATEWAY_SECRET_ENV) or "").strip()
    path = os.environ.get(GATEWAY_SECRET_ENV + "_FILE")
    if not val and path:
        try:
            st = os.stat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
                return None
            key = (path, st.st_mtime_ns, st.st_size)
            if _secret_cache.get("key") != key:
                _secret_cache.update(key=key, val=open(path, encoding="utf-8").read().strip())
            val = _secret_cache["val"]
        except OSError:
            return None
    return val.encode() if val and len(val) >= 16 else None     # a short or missing secret means the gateway path is closed


def _from_gateway() -> bool:
    secret, sent = _gateway_secret(), request.headers.get(GATEWAY_SECRET_HEADER, "")
    ident = request.headers.get(GATEWAY_HEADER, "")
    return (os.environ.get(GATEWAY_OPT_IN) == "1" and secret is not None and hmac.compare_digest(sent.encode(), secret)
            and 0 < len(ident) <= 128 and ident.isprintable())


def _allowed() -> bool:
    """Loopback peer AND a loopback Host name (a DNS-rebinding page has a loopback peer but its own Host). Otherwise only the gateway path:
    the env opt-in AND a configured shared secret that the gateway injects (constant-time compare) AND the identity header. The identity header
    alone never suffices. Neither is user authentication; network reachability remains the control."""
    if _loopback_addr(request.remote_addr) and _hostname(request.host) in LOOPBACK_NAMES:
        return True
    return _from_gateway()


def _json(body: dict, status: int = 200) -> Response:
    resp = jsonify(body)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def svc() -> CtfService:
    holder = current_app.config["AGENTSEC_CTF_HOLDER"]
    with holder["lock"]:
        if holder["service"] is None:
            holder["service"] = CtfService(CtfStore(), default_scenarios())
        return holder["service"]


def _web() -> str:
    return browser_splunk_web(request.host, request.scheme)


@bp.before_request
def _gate():
    if not _allowed():
        return _json({"error": "local_only", "detail": "The CTF answers loopback clients only. NOT MULTI-USER, NOT PUBLIC HOSTING."}, 403)
    if request.method == "POST":
        if request.mimetype != "application/json":
            return _json({"error": "unsupported_media_type"}, 415)
        if request.content_length is not None and request.content_length > MAX_BODY:
            return _json({"error": "payload_too_large"}, 413)
    return None


def _body() -> tuple[object, Response | None]:
    raw = request.get_data(as_text=True)
    if len(raw) > MAX_BODY:
        return None, _json({"error": "payload_too_large"}, 413)
    if not raw.strip():
        return {}, None
    try:
        return loads_json_no_duplicate_keys(raw), None
    except (DuplicateJsonKeyError, ValueError):
        return None, _json({"error": "malformed_json"}, 400)


def _reply(result: tuple[int, dict]) -> Response:
    status, body = result
    resp = _json(body, status)
    if status == 429:
        resp.headers["Retry-After"] = str(body.get("retry_after_seconds", 60))
    return resp


@bp.errorhandler(StoreError)
def _store_error(_exc):
    return _json({"error": "state_unavailable"}, 503)


@bp.errorhandler(Exception)
def _generic(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return _json({"error": "not_found" if exc.code == 404 else "bad_request"}, exc.code or 400)
    log.warning("ctf unexpected error type=%s", type(exc).__name__)
    return _json({"error": "internal_error"}, 500)


@bp.get("/api/ctf/health")
def health():
    return _json(svc().health())


@bp.get("/api/ctf/challenges")
def challenges():
    return _json(svc().list_challenges())


@bp.get("/api/ctf/challenges/<cid>")
def challenge(cid: str):
    return _reply(svc().challenge(cid))


@bp.get("/api/ctf/challenges/<cid>/hint")
def hint(cid: str):
    return _reply(svc().hint(cid))


@bp.post("/api/ctf/challenges/<cid>/attempts")
def start(cid: str):
    return _reply(svc().start(cid, _web()))


@bp.get("/api/ctf/attempts/<aid>")
def attempt(aid: str):
    return _reply(svc().get(aid, _web()))


@bp.post("/api/ctf/attempts/<aid>/run")
def run(aid: str):
    data, err = _body()
    return err or _reply(svc().run(aid, data, _web()))


@bp.post("/api/ctf/attempts/<aid>/verify")
def verify(aid: str):
    data, err = _body()
    if err:
        return err
    if not isinstance(data, dict) or set(data) - {"run_ids"}:
        return _json({"error": "bad_parameters"}, 400)
    return _reply(svc().verify(aid, data.get("run_ids"), _web()))


@bp.post("/api/ctf/attempts/<aid>/redeem")
def redeem(aid: str):
    data, err = _body()
    if err:
        return err
    if not isinstance(data, dict) or set(data) != {"receipt"}:
        return _json({"error": "bad_parameters"}, 400)
    return _reply(svc().redeem(aid, data["receipt"]))


@bp.post("/api/ctf/attempts/<aid>/reset")
def reset(aid: str):
    data, err = _body()
    if err:
        return err
    if data not in ({}, None):
        return _json({"error": "bad_parameters"}, 400)
    return _reply(svc().reset(aid, _web()))


@bp.get("/api/ctf/scoreboard")
def scoreboard():
    return _json(svc().scoreboard())


CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def _page(template: str, **ctx) -> Response:
    resp = current_app.make_response(render_template(template, labels=LABELS, **ctx))
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@bp.get("/ctf")
def page_list():
    return _page("ctf/list.html", page="list", data=svc().list_challenges())


@bp.get("/ctf/scoreboard")
def page_scoreboard():
    return _page("ctf/scoreboard.html", page="scoreboard", board=svc().scoreboard())


@bp.get("/ctf/<cid>")
def page_challenge(cid: str):
    status, body = svc().challenge(cid)
    if status != 200:
        abort(404)
    return _page("ctf/challenge.html", page="challenge", ch=body)


def register_ctf(app: Flask, *, service: CtfService | None = None) -> None:
    """Register the CTF blueprint. The service (and its state directory) is created on first use, never at import or app creation."""
    app.config["AGENTSEC_CTF_HOLDER"] = {"lock": threading.Lock(), "service": service}
    app.register_blueprint(bp)
