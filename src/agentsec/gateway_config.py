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

SUPPORTED_PUBLIC_PORTS = {443, 8000}
INTERNAL_PORTS = {5000, 5001, 8088, 8089, 4317, 4318, 11434, 13133}
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


def _in_use(host: str, port: int) -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1" if host in ("0.0.0.0", "") else host, port), timeout=0.5):
            return True
    except OSError:
        return False


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
    port = env.get("AGENTSEC_PUBLIC_PORT") or env.get("AGENTSEC_HTTPS_PORT", "443")      # AGENTSEC_HTTPS_PORT is the older alias
    if not (re.fullmatch(r"[1-9][0-9]{0,4}", port) and int(port) <= 65535):          # ASCII digits, no leading zero: the gateway compares the text
        err("PORT_INVALID", "AGENTSEC_PUBLIC_PORT must be an integer from 1 to 65535: 443 (default) or 8000 are the supported values")
    elif int(port) in INTERNAL_PORTS:
        err("PORT_RESERVED", f"port {port} belongs to an internal service and must never be the public port; use 443 or 8000")
    else:
        if int(port) not in SUPPORTED_PUBLIC_PORTS:
            warn("PORT_NONSTANDARD", f"supported public ports are 443 and 8000; {port} is for local development only")
        sp = env.get("AGENTSEC_SPLUNK_LOCAL_PORT", "18000")
        if not (sp.isdigit() and 1 <= int(sp) <= 65535):
            err("SPLUNK_LOCAL_PORT_INVALID", "AGENTSEC_SPLUNK_LOCAL_PORT must be an integer from 1 to 65535")
        elif sp == port:
            err("PORT_CONFLICT", "AGENTSEC_SPLUNK_LOCAL_PORT must differ from the public port")
        if env.get("AGENTSEC_CHECK_PORT_FREE") == "1" and _in_use(env.get("AGENTSEC_GATEWAY_BIND", "127.0.0.1"), int(port)):
            err("PORT_IN_USE", f"something already listens on {env.get('AGENTSEC_GATEWAY_BIND', '127.0.0.1')}:{port}; nothing was changed. Stop that service yourself or choose the other supported port"
                + (" (an existing Splunk Web on 8000 must first be moved with the gateway overlay's loopback mapping)" if port == "8000" else ""))
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
            if any(l.split(":", 1)[1].startswith("{SHA}") for l in lines if ":" in l):
                warn("AUTH_WEAK_HASH", "an htpasswd entry uses unsalted {SHA}: anyone who reads the file can test guesses at billions per second. Use bcrypt or apr1 (the generated credentials use apr1). The gateway has no per-account lockout, so passwords must be long and random")

    mode = env.get("AGENTSEC_TLS_MODE", "LOCAL_DEV")
    if mode in TLS_PLANNED:
        err("TLS_MODE_NOT_IMPLEMENTED", f"AGENTSEC_TLS_MODE={mode} is planned and not implemented in this release")
        return out
    if mode not in TLS_IMPLEMENTED:
        err("TLS_MODE_INVALID", f"AGENTSEC_TLS_MODE must be one of {sorted(TLS_IMPLEMENTED)}")
        return out
    ver = _openssl("version")
    if ver.returncode != 0:
        err("OPENSSL_MISSING", "the openssl command is required to validate certificates")
        return out
    if "libressl" in ver.stdout.lower():
        warn("OPENSSL_LIBRESSL", "LibreSSL's openssl was not tested with this validator; OpenSSL 1.1.1 or later (3.x recommended) is the supported tool")

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
