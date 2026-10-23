"""Request guard for state-changing Attack Service / AcmeBank routes.

Browser CSRF defence only. An Origin / Sec-Fetch-Site check stops another website from making a learner's browser POST here. It is NOT
authentication: a request that sends neither header (curl, scripts, tests, other services) is allowed, because those clients are
the documented non-browser API policy (docs/AGENTSEC_ATTACK_LAUNCH_CONTRACT.md). Network reachability remains the access control.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import Flask, jsonify, request

MAX_BODY_BYTES = 16 * 1024
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
STRICT_JSON_PATHS = {"/api/launch", "/api/compare-handoff"}

_ERRORS = {
    "cross_origin_rejected": (403, "Browser requests must come from this service's own origin."),
    "unsupported_media_type": (415, "Content-Type must be application/json."),
    "payload_too_large": (413, f"Body exceeds {MAX_BODY_BYTES} bytes."),
    "unexpected_parameters": (400, "This endpoint takes a JSON body only, not query parameters."),
}


def _reject(code: str):
    status, detail = _ERRORS[code]
    return jsonify({"error": code, "error_class": "ERROR", "evidence_state": "ERROR", "detail": detail}), status


def cross_origin(headers, host: str) -> bool:
    """True when a browser says this request came from somewhere else. No browser headers means a non-browser client: not cross-origin."""
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site not in {"same-origin", "none"}:
        return True
    origin = headers.get("Origin")
    return origin is not None and urlsplit(origin).netloc != host  # "null" has no netloc, so it is rejected


def install_request_guard(app: Flask, *, launch_boundary: bool = True) -> None:
    """launch_boundary=False (AcmeBank) applies only the cross-origin check; its routes keep their own body limits."""
    if launch_boundary:
        app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

    @app.before_request
    def _guard():
        if request.method not in STATE_CHANGING:
            return None
        if cross_origin(request.headers, request.host):
            return _reject("cross_origin_rejected")
        if launch_boundary and request.path in STRICT_JSON_PATHS:
            if request.mimetype != "application/json":
                return _reject("unsupported_media_type")
            if request.args:
                return _reject("unexpected_parameters")
        return None

    @app.errorhandler(413)
    def _too_large(_exc):
        return _reject("payload_too_large")
