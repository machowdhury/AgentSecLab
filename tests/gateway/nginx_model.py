"""A pure-Python MODEL of the gateway's request handling. It is NOT nginx and proves nothing about nginx at runtime.

MODELLED (read from the real gateway files, so a config edit changes the model's answer):
  - Host / port check (421), HTTP Basic (401), role from the user name, location selection (exact, then regex locations in file order, then `/`)
  - URI normalisation as nginx does it for $uri: ONE percent-decode, `.`/`..` resolution, slash merging; %00 and `..` above the root are 400
  - PCRE `$` semantics (matches before a final newline), by using Python's equivalent `re.match`
  - limit_except, `return`, proxy_pass URI construction (named captures; no URI = original raw request URI), proxy_set_header overwrites
  - the attack-tier Origin / Sec-Fetch-Site / operator checks (hand-coded from attack-enabled.conf; asserted to still be present in the file)
  - CTF-through-gateway (gateway/ctf-enabled.conf | ctf-disabled.conf): location selection and anchored captures, `limit_except POST`, and the gateway secret: the model sets
    $gw_secret to the rendered ctf-secret.conf value ONLY in locations that include it, and sends it through identity-headers.conf's `X-AgentSec-Gateway-Secret $gw_secret`
    (every client copy of that header is dropped first). Whether nginx really evaluates `set` + `proxy_set_header` this way is NOT verified here (no nginx).
NOT MODELLED: TLS/SNI, the 8081 authz subrequest and its quota (limit_req), client_max_body_size, error_page/add_header behaviour, header
  size limits, chunked/odd request framing, HTTP/2, nginx's exact status for an unknown Host, `proxy_pass` query-string appending,
  unknown-header pass-through details (Connection etc.). Exact nginx syntax is NOT validated (nginx is not installed here).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote_to_bytes

ROOT = Path(__file__).resolve().parents[2]
USERS = {"learner": "l-pass", "operator": "o-pass"}


@dataclass
class Decision:
    status: int
    upstream: str | None = None          # "attack_service" when proxied
    method: str | None = None
    path: str | None = None              # path (and raw query) sent to the backend
    headers: dict = field(default_factory=dict)   # headers the backend receives (lower-cased names)
    location: str | None = None          # the matching location's pattern, for diagnostics
    redirect: str | None = None
    zone: str | None = None              # limit_req zone applied to the request (the rate itself is not modelled)


def _blocks(text: str):
    """Yield (modifier, pattern, body) for each top-level-in-server `location`, with nested braces balanced."""
    for m in re.finditer(r"^\s*location\s+(=\s+|~\s+|@)?(\S+)\s*\{", text, re.M):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0); i += 1
        yield (m.group(1) or "").strip(), m.group(2), text[m.end():i - 1]


def normalise(raw_path: str) -> str | None:
    """nginx $uri for a request path (no query): None means nginx answers 400."""
    b = unquote_to_bytes(raw_path)                      # exactly one decoding pass: %252e stays the literal text %2e
    if b"\x00" in b:
        return None
    segs, out = b.decode("latin-1").split("/"), []
    for i, seg in enumerate(segs):
        if seg == "..":
            if len(out) <= 1:
                return None                              # above the root
            out.pop()
            if i == len(segs) - 1: out.append("")
        elif seg == ".":
            if i == len(segs) - 1: out.append("")
        elif seg == "" and 0 < i < len(segs) - 1:
            continue                                     # merge_slashes
        else:
            out.append(seg)
    return "/".join(out) or "/"


class Gateway:
    def __init__(self, host="agentsec.test", port="443", tier="enabled", users=USERS, ctf="disabled", ctf_secret=None, scheme="https"):
        """ctf_secret: the secret VALUE rendered into ctf-secret.conf (None = not rendered/mounted: enabled CTF locations then send no secret). scheme: the public scheme the Origin check expects."""
        sub = {"${AGENTSEC_PUBLIC_HOST}": host, "${AGENTSEC_PUBLIC_PORT}": port, "${AGENTSEC_ATTACK_TIER}": tier, "${AGENTSEC_CTF_GATEWAY}": ctf}
        tpl = (ROOT / "gateway/templates/gateway.conf.template").read_text()
        self.attack_conf = (ROOT / f"gateway/attack-{tier}.conf").read_text()
        self.ctf_conf = (ROOT / f"gateway/ctf-{ctf}.conf").read_text()
        self.ctf_secret, self.scheme = ctf_secret, scheme
        for k, v in sub.items(): tpl = tpl.replace(k, v)
        main = tpl[tpl.index("server_name"):]                      # the public server block (after the 8081 authz server)
        self.host, self.port, self.users, self.tier = host, port, users, tier
        self.authority_port = "" if port == "443" else f":{port}"
        self.main = main
        self.locations = [b for b in _blocks(main)] + [b for b in list(_blocks(self.ctf_conf)) + list(_blocks(self.attack_conf)) if b[0] != "@"]
        self.identity = dict(re.findall(r"^proxy_set_header\s+(\S+)\s+(\S+);", (ROOT / "gateway/identity-headers.conf").read_text(), re.M))
        assert ctf == "disabled" or tier == "enabled"          # gateway_config.py refuses the other combination
        assert ctf == "disabled" or 'if ($origin_seen != "https://$host$authority_port") { return 403; }' in self.ctf_conf
        assert tier == "disabled" or 'if ($origin_seen != "https://$host$authority_port") { return 403; }' in self.attack_conf   # the hand-coded Origin check below mirrors this

    def _match(self, uri: str):
        for mod, pat, body in self.locations:
            if mod == "=" and pat == uri: return pat, body, None
        for mod, pat, body in self.locations:
            if mod == "~":
                m = re.match(pat.replace("(?<", "(?P<"), uri)
                if m: return pat, body, m
        return "/", next(b for mod, p, b in self.locations if mod == "" and p == "/"), None

    def handle(self, method: str, target: str, headers: dict | None = None) -> Decision:
        h = {k.lower(): v for k, v in (headers or {}).items()}
        host = h.get("host", "")
        name, _, port = host.partition(":")
        if name.lower() != self.host:
            return Decision(404, location="default_server")                     # unknown host: refused, never proxied (exact nginx code not modelled)
        if (port if port != "443" else "") != self.authority_port.lstrip(":"):
            return Decision(421)
        user = self._basic(h.get("authorization"))
        if user is None:
            return Decision(401)
        path, _, query = target.partition("?")
        uri = normalise(path) if path.startswith("/") else None
        if uri is None:
            return Decision(400)
        pat, body, m = self._match(uri)
        if "internal;" in body:
            return Decision(404, location=pat)
        if method not in ("GET", "HEAD") and re.search(r"limit_except GET \{ deny all; \}", body):
            return Decision(403, location=pat)
        if re.search(r"limit_except POST \{ deny all; \}", body) and method != "POST":
            return Decision(403, location=pat)
        if re.search(r"limit_except GET POST \{ deny all; \}", body) and method not in ("GET", "HEAD", "POST"):
            return Decision(403, location=pat)
        if (r := re.search(r"return 302 (\S+);", body)): return Decision(302, location=pat, redirect=r.group(1))
        if (r := re.search(r"return (\d{3});", body)) and "proxy_pass" not in body and "auth_request" not in body:
            return Decision(int(r.group(1)), location=pat)
        if "auth_request" in body:                                                # attack tier
            public = f"{self.scheme}://{name}{self.authority_port}"
            if h.get("origin", public) != public or h.get("sec-fetch-site", "").lower() in ("cross-site", "same-site"):
                return Decision(403, location=pat)
            if user != "operator":
                return Decision(403, location=pat)
        if "proxy_pass" not in body:
            return Decision(500, location=pat)
        names = m.groupdict() if m else {}
        pp = re.search(r"proxy_pass \$attack(\S*);", body).group(1)             # "" = original raw URI; "/$asp" = rebuilt from the captures
        up_path = target if pp == "" else re.sub(r"\$(\w+)", lambda x: names[x.group(1)], pp)
        if pp: up_path += ("?" + query if query else "")                          # nginx appends the original args (static-reading; see NOT MODELLED)
        fwd_prefix = "/attack-service" if "set $fwd_prefix /attack-service;" in body else ""
        out = {k: v for k, v in h.items() if k not in {n.lower() for n in self.identity} | {"host"}}
        env = {"$remote_user": user, "$role": "operator" if user == "operator" else "learner", "$remote_addr": "203.0.113.9", "$fwd_prefix": fwd_prefix, '""': "",
               "$gw_secret": (self.ctf_secret or "") if "include /etc/nginx/ctf-secret.conf;" in body else ""}
        for n, v in self.identity.items():
            val = env.get(v, v)
            if val != "": out[n.lower()] = val                                    # nginx does not send empty-valued headers
        out["host"] = f"{name}{self.authority_port}"
        z = re.search(r"limit_req zone=(\w+)", body)
        return Decision(200, "attack_service", method, up_path, out, pat, zone=z.group(1) if z else None)

    def _basic(self, auth):
        if not auth or not auth.startswith("Basic "): return None
        try: u, _, p = base64.b64decode(auth[6:], validate=True).decode().partition(":")
        except Exception: return None
        return u if self.users.get(u) == p else None


def basic(user="learner"):
    return "Basic " + base64.b64encode(f"{user}:{USERS[user]}".encode()).decode()
