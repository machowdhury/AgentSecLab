"""Fail-closed configuration validation for the opt-in HTTPS gateway (docker-compose.gateway.yml).

Implemented modes: TLS_MODE LOCAL_DEV and ORG_CERT, AUTH_MODE LOCAL_BASIC, ATTACK_TIER enabled|disabled.
Planned and REFUSED (never silently accepted): TLS_MODE EDGE_TERMINATED, AUTH_MODE OIDC / EDGE_HEADER.
Uses the system `openssl` CLI for certificate checks. Never prints key material or password hashes, and never offers a
verification-bypass setting. Exit code 0 = valid (warnings allowed), 1 = errors, 2 = usage.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

TLS_IMPLEMENTED = {"LOCAL_DEV", "ORG_CERT"}
TLS_PLANNED = {"EDGE_TERMINATED"}
AUTH_IMPLEMENTED = {"LOCAL_BASIC"}
AUTH_PLANNED = {"OIDC", "EDGE_HEADER"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
HASH_RE = re.compile(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$5\$|\$6\$)")
WARN_DAYS = 30


@dataclass(frozen=True)
class Finding:
    level: str   # ERROR | WARN
    code: str
    message: str


def _openssl(*args, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, input=stdin, timeout=30)


def _readable(path: str | None) -> Path | None:
    p = Path(path) if path else None
    return p if p and p.is_file() and os.access(p, os.R_OK) else None


def _cert_dates(cert: Path):
    out = _openssl("x509", "-in", str(cert), "-noout", "-startdate", "-enddate").stdout
    m = {k: v for k, v in (l.split("=", 1) for l in out.splitlines() if "=" in l)}
    fmt = "%b %d %H:%M:%S %Y %Z"
    return datetime.strptime(m["notBefore"].strip(), fmt).replace(tzinfo=timezone.utc), datetime.strptime(m["notAfter"].strip(), fmt).replace(tzinfo=timezone.utc)


def _pubkey_digest(args) -> str:
    pub = _openssl(*args).stdout
    return _openssl("dgst", "-sha256", stdin=pub).stdout.strip() if pub else ""


def validate(env: dict[str, str] | None = None, now: datetime | None = None) -> list[Finding]:
    env, now, out = dict(os.environ if env is None else env), now or datetime.now(timezone.utc), []
    err = lambda c, m: out.append(Finding("ERROR", c, m))
    warn = lambda c, m: out.append(Finding("WARN", c, m))

    gdir = env.get("AGENTSEC_GATEWAY_DIR", "./.gateway")
    host = env.get("AGENTSEC_PUBLIC_HOST", "localhost")
    if not HOST_RE.match(host) or host.startswith("*"):
        err("HOST_INVALID", "AGENTSEC_PUBLIC_HOST must be a DNS name (no scheme, port, wildcard or spaces)")
    port = env.get("AGENTSEC_HTTPS_PORT", "443")
    if not (port.isdigit() and 1 <= int(port) <= 65535):
        err("PORT_INVALID", "AGENTSEC_HTTPS_PORT must be an integer from 1 to 65535 (443 by default, e.g. 8443 for local development)")
    tier = env.get("AGENTSEC_ATTACK_TIER", "enabled")
    if tier not in ("enabled", "disabled"):
        err("ATTACK_TIER_INVALID", "AGENTSEC_ATTACK_TIER must be 'enabled' or 'disabled'")
    bind = env.get("AGENTSEC_GATEWAY_BIND", "127.0.0.1")
    if bind not in ("127.0.0.1", "::1") and not env.get("AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK"):
        warn("BIND_NONLOOPBACK", f"AGENTSEC_GATEWAY_BIND={bind} makes the gateway reachable from the network; set AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK=1 to acknowledge")

    auth = env.get("AGENTSEC_AUTH_MODE", "LOCAL_BASIC")
    if auth in AUTH_PLANNED:
        err("AUTH_MODE_NOT_IMPLEMENTED", f"AGENTSEC_AUTH_MODE={auth} is planned and not implemented in this release")
    elif auth not in AUTH_IMPLEMENTED:
        err("AUTH_MODE_INVALID", f"AGENTSEC_AUTH_MODE must be one of {sorted(AUTH_IMPLEMENTED)}")
    else:
        af = _readable(env.get("AGENTSEC_AUTH_FILE", f"{gdir}/htpasswd"))
        if not af:
            err("AUTH_FILE_MISSING", "AGENTSEC_AUTH_FILE (htpasswd) is missing or unreadable")
        else:
            lines = [l for l in af.read_text().splitlines() if l.strip()]
            users = {l.split(":", 1)[0] for l in lines}
            if not lines or not all(HASH_RE.match(l) for l in lines):
                err("AUTH_FILE_INVALID", "every htpasswd line must be user:hash (apr1, bcrypt, SHA or crypt); plaintext passwords are refused")
            elif not {"learner", "operator"} <= users:
                err("AUTH_ROLES_MISSING", "htpasswd must define the users 'learner' and 'operator' (roles come from the user name)")

    mode = env.get("AGENTSEC_TLS_MODE", "LOCAL_DEV")
    if mode in TLS_PLANNED:
        err("TLS_MODE_NOT_IMPLEMENTED", f"AGENTSEC_TLS_MODE={mode} is planned and not implemented in this release")
        return out
    if mode not in TLS_IMPLEMENTED:
        err("TLS_MODE_INVALID", f"AGENTSEC_TLS_MODE must be one of {sorted(TLS_IMPLEMENTED)}")
        return out
    if _openssl("version").returncode != 0:
        err("OPENSSL_MISSING", "the openssl command is required to validate certificates")
        return out

    cert_f = env.get("AGENTSEC_TLS_CERT_FILE", f"{gdir}/tls/server.pem")
    key_f = env.get("AGENTSEC_TLS_KEY_FILE", f"{gdir}/tls/server.key")
    chain_f = env.get("AGENTSEC_TLS_CHAIN_FILE", f"{gdir}/tls/ca.pem" if mode == "LOCAL_DEV" else "")
    cert, key, chain = _readable(cert_f), _readable(key_f), _readable(chain_f)
    if not cert: err("TLS_CERT_MISSING", "AGENTSEC_TLS_CERT_FILE is missing or unreadable")
    if not key: err("TLS_KEY_MISSING", "AGENTSEC_TLS_KEY_FILE is missing or unreadable")
    if not chain: err("TLS_CHAIN_MISSING", "AGENTSEC_TLS_CHAIN_FILE (CA chain used to verify the server certificate) is missing or unreadable")
    if not (cert and key and chain):
        return out
    if key.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        warn("TLS_KEY_PERMISSIONS", "the private key is readable by group or others; use mode 0400 or 0600")
    if _openssl("x509", "-in", str(cert), "-noout").returncode != 0:
        err("TLS_CERT_INVALID", "the certificate file is not a PEM certificate")
        return out
    if _openssl("pkey", "-in", str(key), "-noout").returncode != 0:
        err("TLS_KEY_INVALID", "the private key file is not a readable PEM key (encrypted keys are not supported)")
        return out
    a, b = _pubkey_digest(["x509", "-in", str(cert), "-pubkey", "-noout"]), _pubkey_digest(["pkey", "-in", str(key), "-pubout"])
    if not a or a != b:
        err("TLS_KEY_MISMATCH", "the private key does not match the certificate")
    start, end = _cert_dates(cert)
    if now < start: err("TLS_CERT_NOT_YET_VALID", f"the certificate is not valid before {start:%Y-%m-%d}")
    elif now > end: err("TLS_CERT_EXPIRED", f"the certificate expired on {end:%Y-%m-%d}")
    elif (end - now).days < WARN_DAYS: warn("TLS_EXPIRES_SOON", f"the certificate expires in {(end - now).days} days")
    v = _openssl("verify", "-CAfile", str(chain), "-untrusted", str(cert), "-verify_hostname", host, str(cert))
    text = (v.stdout + v.stderr).lower()
    if v.returncode != 0:
        if "hostname mismatch" in text or "does not match" in text:
            err("TLS_HOSTNAME_MISMATCH", f"the certificate is not valid for AGENTSEC_PUBLIC_HOST={host}")
        elif "expired" in text:
            pass  # already reported precisely above
        else:
            err("TLS_CHAIN_UNTRUSTED", "the certificate does not verify against AGENTSEC_TLS_CHAIN_FILE (wrong CA or missing intermediate)")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] != "validate":
        print("usage: python -m agentsec.gateway_config validate"); return 2
    findings = validate()
    for f in findings:
        print(f"{f.level} {f.code}: {f.message}")
    errors = [f for f in findings if f.level == "ERROR"]
    print("gateway configuration: " + ("INVALID" if errors else "valid") + f" ({len(errors)} errors, {len(findings) - len(errors)} warnings)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
