"""Provider-neutral Splunk REST client: strict TLS, bounded time and size, no secrets in logs, URLs or errors.

Modes (AGENTSEC_SPLUNK_MODE): BUNDLED (default; the lab's own container, searched through the existing docker backend, unchanged),
EXTERNAL_ENTERPRISE and CLOUD (REST to a management endpoint you supply). In the two external modes NOTHING falls back to docker.

Security rules enforced here: https only; certificate AND hostname verification always on (a CA bundle may ADD trust, nothing can
disable it); redirects are never followed (a token must not travel to another host); the token comes from a file, never from a URL,
never from the process environment value, never in repr/str/log/error text; responses are size-capped; searches have a wall-clock
deadline; only fixed, read-only SPL built by the application is accepted (see assert_read_only_spl). Failures are classified by
stage: connectivity, authentication, authorization, search, telemetry.
"""
from __future__ import annotations

import csv
import io
import logging
import os
import re
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

MODES = ("BUNDLED", "EXTERNAL_ENTERPRISE", "CLOUD")
EXTERNAL_MODES = ("EXTERNAL_ENTERPRISE", "CLOUD")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SPL_CHARS = 8192
MAX_TOKEN_FILE_BYTES = 4096
INDEX_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FORBIDDEN_COMMANDS = {"delete", "outputlookup", "outputcsv", "collect", "mcollect", "meventcollect", "sendemail", "script", "run", "dbxquery", "rest",
                      "tscollect", "sendalert", "map", "loadjob", "savedsearch", "crawl", "input", "audit", "diag"}


@dataclass(frozen=True)
class Finding:
    level: str   # ERROR | WARN
    code: str
    message: str


class SplunkError(Exception):
    """stage: connectivity | authentication | authorization | search. code: fixed, safe to show. Never contains a secret or a URL query."""
    def __init__(self, stage: str, code: str, message: str = ""):
        super().__init__(f"{stage}/{code}" + (f": {message}" if message else ""))
        self.stage, self.code = stage, code


@dataclass(frozen=True)
class SplunkConfig:
    mode: str
    rest_url: str = ""
    ca_file: str = ""
    token: str = field(default="", repr=False)          # never printed
    index: str = "agentsec_telemetry"
    timeout_s: int = 30

    def __str__(self) -> str:
        return f"SplunkConfig(mode={self.mode}, rest_url={self.rest_url}, ca_file={'set' if self.ca_file else 'system'}, token=<hidden>)"


def _mode(env) -> str:
    return (env.get("AGENTSEC_SPLUNK_MODE") or "BUNDLED").strip().upper()


def _read_token(path: str) -> tuple[str, str | None]:
    p = Path(path)
    if not p.is_file() or not os.access(p, os.R_OK):
        return "", "TOKEN_FILE_MISSING"
    if p.stat().st_size > MAX_TOKEN_FILE_BYTES:
        return "", "TOKEN_FILE_TOO_LARGE"
    tok = p.read_text(encoding="utf-8", errors="ignore").strip()
    return (tok, None) if tok and "\n" not in tok and "\r" not in tok else ("", "TOKEN_FILE_EMPTY")


def validate_config(env: dict | None = None) -> list[Finding]:
    env, out = dict(os.environ if env is None else env), []
    err = lambda c, m: out.append(Finding("ERROR", c, m))
    warn = lambda c, m: out.append(Finding("WARN", c, m))
    mode = _mode(env)
    if mode not in MODES:
        err("MODE_INVALID", f"AGENTSEC_SPLUNK_MODE must be one of {list(MODES)}")
        return out
    if mode == "BUNDLED":
        if env.get("AGENTSEC_SPLUNK_REST_URL"):
            warn("EXTERNAL_SETTINGS_IGNORED", "AGENTSEC_SPLUNK_REST_URL is ignored in BUNDLED mode")
        return out
    url = env.get("AGENTSEC_SPLUNK_REST_URL", "")
    u = urllib.parse.urlsplit(url)
    if not url:
        err("REST_URL_MISSING", "AGENTSEC_SPLUNK_REST_URL is required (https://host:8089)")
    elif u.scheme != "https" or not u.hostname:
        err("REST_URL_INVALID", "AGENTSEC_SPLUNK_REST_URL must be an https:// URL with a host name")
    elif u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        err("REST_URL_INVALID", "AGENTSEC_SPLUNK_REST_URL must not contain credentials, a path, a query or a fragment")
    else:
        if u.port not in (None, 8089):
            warn("REST_PORT_NONSTANDARD", f"Splunk management normally listens on 8089; got {u.port}")
        if mode == "CLOUD":
            if not re.search(r"\.splunkcloud(gc)?\.com$", u.hostname):
                warn("CLOUD_HOST_UNRECOGNIZED", "CLOUD mode expects <deployment>.splunkcloud.com (or your Splunk-provided host)")
            warn("CLOUD_REST_ACCESS", "Splunk Cloud REST access (port 8089) must be enabled for your source addresses (ACS IP allow list or a support case); free trials cannot use the REST API")
    ca = env.get("AGENTSEC_SPLUNK_CA_BUNDLE_FILE", "")
    if ca:
        cp = Path(ca)
        if not cp.is_file() or not os.access(cp, os.R_OK):
            err("CA_BUNDLE_MISSING", "AGENTSEC_SPLUNK_CA_BUNDLE_FILE is missing or unreadable")
        else:
            try:
                ssl.create_default_context().load_verify_locations(cafile=str(cp))
            except (ssl.SSLError, OSError):
                err("CA_BUNDLE_INVALID", "AGENTSEC_SPLUNK_CA_BUNDLE_FILE contains no usable PEM certificate")
    tf = env.get("AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE", "")
    if not tf:
        err("TOKEN_FILE_MISSING", "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE is required (a least-privilege, search-only token stored in a file)")
    else:
        _, bad = _read_token(tf)
        if bad:
            err(bad, "the search token file is missing, empty, multi-line or too large")
        elif Path(tf).stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            warn("TOKEN_FILE_PERMISSIONS", "the token file is readable by group or others; use mode 0400 or 0600")
    if not INDEX_RE.match(env.get("AGENTSEC_SPLUNK_INDEX", "agentsec_telemetry")):
        err("INDEX_INVALID", "AGENTSEC_SPLUNK_INDEX must be 1-64 characters from A-Z a-z 0-9 _ -")
    t = env.get("AGENTSEC_SPLUNK_TIMEOUT_SEC", "30")
    if not (t.isdigit() and 1 <= int(t) <= 120):
        err("TIMEOUT_INVALID", "AGENTSEC_SPLUNK_TIMEOUT_SEC must be an integer from 1 to 120")
    hec = env.get("AGENTSEC_SPLUNK_HEC_URL", "")
    if hec:
        h = urllib.parse.urlsplit(hec)
        if h.scheme != "https" or not h.hostname or h.username or h.password or h.query or h.fragment:
            err("HEC_URL_INVALID", "AGENTSEC_SPLUNK_HEC_URL must be an https:// URL without credentials, query or fragment")
        ht = env.get("AGENTSEC_SPLUNK_HEC_TOKEN_FILE", "")
        if not ht or _read_token(ht)[1]:
            err("HEC_TOKEN_FILE_MISSING", "AGENTSEC_SPLUNK_HEC_TOKEN_FILE must point to a readable single-line token file")
        warn("HEC_NOT_EXERCISED", "HEC export through the collector is configured by SPLUNK_HEC_ENDPOINT and the CA mount; it is NOT exercised by this client")
    return out


def config_from_env(env: dict | None = None) -> SplunkConfig:
    """Returns a config for an EXTERNAL mode, or raises SplunkError(connectivity/config_invalid) when invalid. BUNDLED returns a bare config."""
    env = dict(os.environ if env is None else env)
    mode = _mode(env)
    if mode == "BUNDLED":
        return SplunkConfig(mode)
    if any(f.level == "ERROR" for f in validate_config(env)):
        raise SplunkError("connectivity", "config_invalid", "AGENTSEC_SPLUNK_* configuration is invalid (run: python -m agentsec.splunk_client validate)")
    token, _ = _read_token(env["AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE"])
    return SplunkConfig(mode, env["AGENTSEC_SPLUNK_REST_URL"].rstrip("/"), env.get("AGENTSEC_SPLUNK_CA_BUNDLE_FILE", ""), token,
                        env.get("AGENTSEC_SPLUNK_INDEX", "agentsec_telemetry"), int(env.get("AGENTSEC_SPLUNK_TIMEOUT_SEC", "30")))


def assert_read_only_spl(spl: str) -> str:
    """Defence in depth: only application-built, read-only SPL may be sent. Learners never supply SPL (see loan_desk/search.py)."""
    if not isinstance(spl, str) or not spl.strip() or len(spl) > MAX_SPL_CHARS:
        raise SplunkError("search", "forbidden_spl", "empty or oversized search")
    for segment in spl.split("|"):
        words = segment.strip().split(None, 1)
        if words and words[0].lower() in FORBIDDEN_COMMANDS:
            raise SplunkError("search", "forbidden_spl", f"command '{words[0].lower()}' is not allowed")
    return " ".join(spl.split())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):      # a token must never follow a redirect to another host
        return None


class SplunkRestClient:
    def __init__(self, config: SplunkConfig, *, opener: Callable | None = None):
        if config.mode not in EXTERNAL_MODES:
            raise SplunkError("connectivity", "config_invalid", "the REST client is used only in EXTERNAL_ENTERPRISE or CLOUD mode")
        self.config = config
        ctx = ssl.create_default_context(cafile=config.ca_file or None)     # CERT_REQUIRED and check_hostname stay on
        self._opener = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect()).open

    def _request(self, method: str, path: str, form: dict | None = None, *, timeout: float | None = None, deadline: float | None = None) -> bytes:
        url = self.config.rest_url + path
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Authorization": "Bearer " + self.config.token, "Accept": "*/*"})
        timeout = timeout or self.config.timeout_s
        try:
            resp = self._opener(req, timeout=timeout)
            body, total = [], 0
            while True:
                if deadline and time.monotonic() > deadline:
                    raise SplunkError("search", "timeout", "search exceeded its time limit")
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise SplunkError("search", "too_large", "response exceeded the size limit")
                body.append(chunk)
            return b"".join(body)
        except SplunkError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                raise SplunkError("connectivity", "redirect_refused") from None
            if exc.code == 401:
                raise SplunkError("authentication", "auth_failed") from None
            if exc.code == 403:
                raise SplunkError("authorization", "forbidden") from None
            raise SplunkError("search", "http_error", f"HTTP {exc.code}") from None
        except (ssl.SSLError, ssl.CertificateError):
            raise SplunkError("connectivity", "tls_verification_failed") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (ssl.SSLError, ssl.CertificateError)):
                raise SplunkError("connectivity", "tls_verification_failed") from None
            if isinstance(exc.reason, TimeoutError):
                raise SplunkError("connectivity", "timeout") from None
            raise SplunkError("connectivity", "connect_failed") from None
        except (TimeoutError, OSError):
            raise SplunkError("connectivity", "timeout") from None

    # ---- staged checks -------------------------------------------------
    def server_info(self) -> None:
        """Connectivity + authentication in one call: TLS handshake with verification, then the token is presented."""
        self._request("GET", "/services/server/info?output_mode=json", timeout=min(15, self.config.timeout_s))

    def export_csv(self, spl: str, *, timeout_s: int | None = None) -> str:
        spl = assert_read_only_spl(spl)
        t = int(timeout_s or self.config.timeout_s)
        body = self._request("POST", "/services/search/v2/jobs/export", {"search": spl if spl.lstrip().startswith(("search", "|")) else "search " + spl, "output_mode": "csv", "earliest_time": "0"},
                             timeout=t, deadline=time.monotonic() + t)
        return body.decode("utf-8", "replace")

    def export_rows(self, spl: str, *, timeout_s: int | None = None, max_rows: int = 500) -> list[dict]:
        text = self.export_csv(spl, timeout_s=timeout_s).strip()
        rows = list(csv.DictReader(io.StringIO(text))) if text else []
        return rows[:max_rows]

    def diagnose(self, run_id: str | None = None) -> list[tuple[str, str, str]]:
        """[(stage, PASS|FAIL|NOT VERIFIED, detail)]. Each stage is judged on its own evidence: a PASS never implies the next stage."""
        nv = "not reached"
        st = {k: ("NOT VERIFIED", nv) for k in ("connectivity", "authentication", "authorization", "search", "telemetry")}
        fail = lambda e: st.__setitem__(e.stage if e.stage in st else "search", ("FAIL", e.code))
        try:
            self.server_info()
            st["connectivity"], st["authentication"] = ("PASS", "TLS handshake verified and the endpoint answered"), ("PASS", "the token was accepted")
        except SplunkError as e:
            if e.stage == "authorization":        # 403 means the token authenticated but may not read server info; search is checked next
                st["connectivity"], st["authentication"] = ("PASS", "TLS handshake verified"), ("PASS", "the token was accepted (server info not permitted)")
            else:
                fail(e)
                if e.stage == "authentication": st["connectivity"] = ("PASS", "TLS handshake verified")
                return [(k, *v) for k, v in {**st, "telemetry": ("NOT VERIFIED", "not reached")}.items()]
        try:
            rows = self.export_rows("| makeresults count=1 | eval ok=1")
            st["authorization"] = ("PASS", "the token may run searches")
            st["search"] = ("PASS", "a trivial search returned a parsable result") if rows and rows[0].get("ok") == "1" else ("FAIL", "no parsable result")
        except SplunkError as e:
            fail(e)
            return [(k, *v) for k, v in {**st, "telemetry": ("NOT VERIFIED", "not reached")}.items()]
        if not run_id:
            st["telemetry"] = ("NOT VERIFIED", "service checks do not prove ingestion; pass --run-id <id> after a launch")
        elif not RUN_ID_RE.match(run_id):
            st["telemetry"] = ("NOT VERIFIED", "run id must be 1-64 characters from A-Z a-z 0-9 _ -")
        else:
            try:
                r = self.export_rows(f'search index={self.config.index} "agentsec.run.id"="{run_id}" | stats count')
                n = int(r[0]["count"]) if r and (r[0].get("count") or "").isdigit() else 0
                st["telemetry"] = ("PASS", f"{n} indexed events for that run") if n else ("NOT VERIFIED", "no indexed events for that run (not ingested, wrong id, or index not visible to this token)")
            except SplunkError as e:
                fail(e); st["telemetry"] = ("FAIL", e.code)
        return [(k, *v) for k, v in st.items()]


def client_for_mode(env: dict | None = None) -> SplunkRestClient | None:
    """None in BUNDLED mode (callers keep their docker backend). External modes: a client, or SplunkError if the config is invalid (no silent fallback)."""
    cfg = config_from_env(env)
    return None if cfg.mode == "BUNDLED" else SplunkRestClient(cfg)


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "validate":
        f = validate_config()
        for x in f: print(f"{x.level} {x.code}: {x.message}")
        errs = [x for x in f if x.level == "ERROR"]
        print("splunk configuration: " + ("INVALID" if errs else "valid") + f" (mode {_mode(os.environ)})")
        return 1 if errs else 0
    if cmd == "check":
        run_id = argv[argv.index("--run-id") + 1] if "--run-id" in argv and len(argv) > argv.index("--run-id") + 1 else None
        if _mode(os.environ) == "BUNDLED":
            print("BUNDLED mode: searches use the lab's own container; run scripts/lab-ready.sh. (not applicable to the REST client)")
            return 0
        try:
            res = client_for_mode().diagnose(run_id)
        except SplunkError as e:
            print(f"connectivity FAIL: {e.code}"); return 1
        for stage, state, detail in res: print(f"{stage.upper()} {state}: {detail}")
        return 1 if any(st == "FAIL" for _, st, _ in res) else 0
    print("usage: python -m agentsec.splunk_client validate | check [--run-id ID]"); return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
