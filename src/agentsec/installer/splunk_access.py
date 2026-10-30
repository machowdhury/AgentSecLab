"""Installer-managed, least-privilege Splunk search access for the bundled Splunk.

After the services are up, one script runs INSIDE the Splunk container (where the admin password already is, in its environment; it never appears in
an argument list or on the host). It creates a search-only role limited to the telemetry index, a user with that role, and, when the KV store allows it,
an authentication token for that user (otherwise the user's generated password is used with HTTP basic). It proves the result by searching as the new
identity (a trivial search works, another index reads zero), reads the certificate Splunk presents on its management port, and prints one result line.
The host then writes owner-only files into `.splunk-access/`, which the Attack Service mounts read-only. The Attack Service reads them on every request,
so no restart is needed. Nothing here is a free-form SPL path, and a failure leaves search access UNAVAILABLE (fail closed), never half-configured.

The result line contains the credential; it is parsed in memory and never printed or logged.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable

ACCESS_DIR = ".splunk-access"
CONTAINER_DIR = "/run/secrets/agentsec_splunk_access"
REST_URL = "https://splunk:8089"                       # the Compose service name; resolves inside the lab's network only
USER = ROLE = "agentsec_search"
FILES = ("auth", "credential", "user", "server_name", "ca.pem", "provisioned.json")
NOT_READY = 75

Compose = Callable[[list], "tuple[int, str]"]          # (arguments after `docker compose ...`) -> (return code, combined output)

SCRIPT = r'''
import base64, http.client, json, os, re, secrets, ssl, subprocess, sys, tempfile, urllib.parse
HOST = os.environ.get("AGENTSEC_ACCESS_HOST", "localhost"); PORT = int(os.environ.get("AGENTSEC_ACCESS_PORT", "8089"))
OPENSSL = os.environ.get("AGENTSEC_ACCESS_OPENSSL", "/opt/splunk/bin/openssl")
ADMIN, ADMIN_PW = os.environ.get("AGENTSEC_ACCESS_ADMIN_USER", "admin"), os.environ.get("SPLUNK_PASSWORD", "")
INDEX, MODE = sys.argv[1], sys.argv[2]
ROLE = USER = "agentsec_search"
def fail(code, detail="", rc=1):
    print("AGENTSEC_ERROR %s %s" % (code, detail)); sys.exit(rc)
def step(msg):
    print("STEP " + msg, flush=True)
if not re.match(r"^[A-Za-z0-9_-]{1,64}$", INDEX) or MODE not in ("auto", "bearer", "basic"):
    fail("bad_arguments")
if not ADMIN_PW:
    fail("no_admin_password", "SPLUNK_PASSWORD is not set in the Splunk container")
try:
    pem = ssl.get_server_certificate((HOST, PORT))
except OSError:
    fail("not_ready", "the management port is not answering yet", 75)
tmp = tempfile.mkdtemp(); anchor = os.path.join(tmp, "anchor.pem")
with open(anchor, "w") as fh:
    fh.write(pem)
subj = subprocess.run([OPENSSL, "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-in", anchor], capture_output=True, text=True).stdout
m = re.search(r"CN=([^,\n]+)", subj)
name = m.group(1).strip() if m else ""
if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,251}$", name):
    fail("bad_certificate_name", "the management certificate has no usable common name")
ctx = ssl.create_default_context(cafile=anchor)
ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0x80000)     # Python before 3.10 has no name for the flag
ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)                  # Splunk's default certificate lacks key identifiers that strict mode (3.13+) requires
class Conn(http.client.HTTPSConnection):
    def connect(self):
        self.sock = self._create_connection((self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=name)
def basic(u, p):
    return "Basic " + base64.b64encode(("%s:%s" % (u, p)).encode()).decode()
def call(method, path, form=None, auth=None):
    headers = {"Authorization": auth or basic(ADMIN, ADMIN_PW), "Accept": "application/json"}
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
    c = Conn(HOST, PORT, timeout=40, context=ctx)
    try:
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse(); return r.status, r.read(1 << 20).decode("utf-8", "replace")
    except ssl.SSLError as e:
        fail("tls_self_check_failed", e.__class__.__name__ + " " + str(getattr(e, "reason", "")))
    except OSError as e:
        fail("not_ready", e.__class__.__name__, 75)
    finally:
        c.close()
step("management certificate recorded as the trust anchor (name %s)" % name)
role = {"capabilities": "search", "imported_roles": "", "srchIndexesAllowed": INDEX, "srchIndexesDefault": INDEX, "srchJobsQuota": "4",
        "cumulativeSrchJobsQuota": "8", "srchDiskQuota": "200", "rtSrchJobsQuota": "0", "cumulativeRTSrchJobsQuota": "0", "output_mode": "json"}
st, rbody = call("POST", "/services/authorization/roles", dict(role, name=ROLE))
if st == 409 or (st == 400 and "already exists" in rbody):             # a real Splunk answers an existing user (and possibly role) with 400 and a message, not 409
    st, _ = call("POST", "/services/authorization/roles/" + ROLE, role)
if st not in (200, 201):
    fail("role_failed", "HTTP %d" % st)
st, body = call("GET", "/services/authorization/roles/%s?output_mode=json" % ROLE)
try:
    content = json.loads(body)["entry"][0]["content"]
except (ValueError, KeyError, IndexError):
    fail("role_unreadable")
caps, imported, allowed = set(content.get("capabilities") or []), list(content.get("imported_roles") or []), list(content.get("srchIndexesAllowed") or [])
if caps - {"search"} or imported or allowed != [INDEX]:
    fail("role_not_least_privilege", "capabilities=%s imported=%s indexes=%s" % (sorted(caps), imported, allowed))
step("search-only role %s limited to index %s" % (ROLE, INDEX))
password = secrets.token_urlsafe(32)
user = {"password": password, "roles": ROLE, "realname": "AgentSec search", "email": "agentsec-search@localhost.invalid", "force-change-pass": "0", "output_mode": "json"}
st, ubody = call("POST", "/services/authentication/users", dict(user, name=USER))
if st == 409 or (st == 400 and "already exists" in ubody):
    st, _ = call("POST", "/services/authentication/users/" + USER, user)
if st not in (200, 201):
    fail("user_failed", "HTTP %d" % st)
st, body = call("GET", "/services/authentication/users/%s?output_mode=json" % USER)
try:
    roles = list(json.loads(body)["entry"][0]["content"].get("roles") or [])
except (ValueError, KeyError, IndexError, AttributeError):
    roles = None
if st != 200 or roles != [ROLE]:
    fail("user_not_least_privilege", "roles=%s" % (roles,))
step("user %s created or updated, with only the role %s" % (USER, ROLE))
auth, credential, fallback, expires = "basic", password, "", ""
if MODE in ("auto", "bearer"):
    st, body = call("POST", "/services/authorization/tokens", {"name": USER, "audience": "agentsec-attack-service", "expires_on": "+180d", "output_mode": "json"})
    token = ""
    if st in (200, 201):
        try:
            token = json.loads(body)["entry"][0]["content"]["token"]
        except (ValueError, KeyError, IndexError):
            token = ""
    if token:
        import datetime
        auth, credential = "bearer", token
        expires = (datetime.datetime.utcnow() + datetime.timedelta(days=180)).strftime("%Y-%m-%d")
        step("authentication token created (valid until %s)" % expires)
    else:
        reason = "kvstore_not_ready" if "KVStore" in body else "http_%d" % st
        if MODE == "bearer":
            fail("token_unavailable", reason)
        fallback = reason
        step("tokens unavailable (%s): using the search-only user's password with HTTP basic" % reason)
who = ("Bearer " + credential) if auth == "bearer" else basic(USER, credential)
def csv_rows(text):
    import csv, io
    return list(csv.reader(io.StringIO(text)))
st, body = call("POST", "/services/search/v2/jobs/export", {"search": "| makeresults count=1 | eval ok=1 | table ok", "output_mode": "csv"}, who)      # makeresults adds _time: table keeps the proof to one known column
rows = csv_rows(body) if st == 200 else []
if st != 200 or rows[:2] != [["ok"], ["1"]]:
    fail("identity_cannot_search", "HTTP %d" % st)
st, body = call("POST", "/services/search/v2/jobs/export", {"search": "search index=_internal earliest=-1h | head 1 | stats count", "output_mode": "csv"}, who)
rows = csv_rows(body) if st == 200 else []
denied = st in (400, 401, 403)                                    # a refusal is also proof; anything else must be an explicit zero count, never silence or an error
if not denied and rows[:2] != [["count"], ["0"]]:
    fail("index_not_restricted", "the other-index probe did not return an explicit zero (HTTP %d); not treating that as proof" % st)
step("verified as the new identity: it can search and cannot read other indexes")
print("AGENTSEC_RESULT " + json.dumps({"auth": auth, "credential": credential, "user": USER, "server_name": name, "ca_pem": pem, "token_expires": expires, "fallback": fallback}))
'''


def _atomic_private(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    try:
        os.unlink(tmp)                                  # a leftover temp file must not keep a wider mode while the secret is written
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def write_access(root: Path, doc: dict, now: float | None = None) -> None:
    """Owner-only files, one at a time and credential last, so a reader never sees a credential without the certificate it must be checked against."""
    d = root / ACCESS_DIR
    if d.is_symlink():
        raise OSError(f"{ACCESS_DIR} is a symbolic link; refusing to write through it")
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    meta = {"provisioned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now or time.time())), "auth": doc["auth"], "user": doc["user"], "server_name": doc["server_name"],
            "token_expires": doc.get("token_expires", ""), "fallback": doc.get("fallback", "")}
    for name, text in (("ca.pem", doc["ca_pem"]), ("server_name", doc["server_name"]), ("user", doc["user"]), ("auth", doc["auth"]),
                       ("provisioned.json", json.dumps(meta, indent=2) + "\n"), ("credential", doc["credential"])):
        _atomic_private(d / name, text if text.endswith("\n") or name == "credential" else text + "\n")


def read_status(root: Path) -> dict | None:
    """What was provisioned (never the credential), or None."""
    try:
        meta = json.loads((root / ACCESS_DIR / "provisioned.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return meta if isinstance(meta, dict) and all((root / ACCESS_DIR / n).is_file() for n in ("credential", "auth", "ca.pem", "server_name")) else None


def _lines(out: str, prefix: tuple) -> list:
    return [ln.strip() for ln in out.splitlines() if ln.startswith(prefix)]


def provision(root: Path, compose: Compose, say: Callable[[str], None], *, index: str = "agentsec_telemetry", auth: str = "auto", wait_s: int = 600,
              sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> bool:
    """True when search access is provisioned and proven. False (after saying why, without a secret) otherwise; the caller must not treat that as fatal."""
    if auth not in ("auto", "bearer", "basic") or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", index):
        say("WARN  SPLUNK_ACCESS_ARGUMENTS: invalid authentication mode or index; search access was not provisioned.")
        return False
    argv = ["exec", "-T", "splunk", "sh", "-c", 'LD_LIBRARY_PATH=/opt/splunk/lib; export LD_LIBRARY_PATH; P=/opt/splunk/bin/python3; [ -x "$P" ] || P=/opt/splunk/bin/python; exec "$P" -c "$0" "$@"', SCRIPT, index, auth]
    deadline, waited = clock() + wait_s, False
    while True:
        rc, out = compose(argv)
        if rc == 0:
            break
        errs = _lines(out, ("AGENTSEC_ERROR",))
        if rc == NOT_READY or (not errs and "is not running" in out):          # Splunk (or its container) is still starting
            if clock() >= deadline:
                say(f"WARN  SPLUNK_ACCESS_UNAVAILABLE: Splunk did not become ready within {wait_s} s, so search access was not provisioned. Run `./agentsec splunk-access` once Splunk is up.")
                return False
            if not waited:
                say("      waiting for Splunk's management port (first start takes a few minutes)...")
                waited = True
            sleep(10)
            continue
        hint = " (is Splunk's management certificate still valid? An expired default certificate must be regenerated, then run this again)" if errs and "tls_self_check_failed" in errs[-1] else ""
        say("WARN  SPLUNK_ACCESS_UNAVAILABLE: " + (errs[-1].replace("AGENTSEC_ERROR ", "") if errs else f"the provisioning step exited {rc}") + hint +
            ". The Academy notebook and evidence verification will say 'unavailable'; nothing is reported as a result. Fix the cause and run `./agentsec splunk-access`.")
        return False
    result = _lines(out, ("AGENTSEC_RESULT ",))
    for ln in _lines(out, ("STEP ",)):
        say("      " + ln[5:])
    try:
        doc = json.loads(result[-1][len("AGENTSEC_RESULT "):])
        for k in ("auth", "credential", "user", "server_name", "ca_pem"):
            if not isinstance(doc.get(k), str) or not doc[k]:
                raise ValueError(k)
    except (IndexError, ValueError):
        say("WARN  SPLUNK_ACCESS_UNAVAILABLE: the provisioning step gave no usable result; nothing was written.")
        return False
    try:
        write_access(root, doc)
    except OSError as exc:
        say(f"WARN  SPLUNK_ACCESS_UNAVAILABLE: could not write {ACCESS_DIR}/: {exc}")
        return False
    say(f"OK    Splunk search access provisioned ({doc['auth']}{', token' if doc['auth'] == 'bearer' else ', password: ' + (doc.get('fallback') or 'by request')}); "
        "files are in .splunk-access/ (owner-only) and mounted read-only into the Attack Service.")
    return True
