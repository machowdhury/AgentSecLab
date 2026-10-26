"""Shared helpers for the disposable gateway POC tests. Results are recorded per matrix id into evidence/results.json."""
import json, os, subprocess, tempfile
from pathlib import Path
import pytest

POC = Path(__file__).resolve().parents[1]
RT = Path(os.environ.get("POC_RUNTIME", POC / ".runtime"))
EVID = POC / "evidence"
PORT = int(os.environ.get("POC_HTTPS_PORT", "18443"))
CERTS = RT / "certs"
PROJECT = "agentsec-gw-poc"
MATRIX = {
    "T01": "Exactly one published application ingress port", "T02": "No direct external access to backend service ports",
    "T03": "Academy loads through HTTPS", "T04": "Canonical URL and redirects work", "T05": "Valid LOCAL_DEV certificate succeeds",
    "T06": "Valid simulated ORG_CERT succeeds", "T07": "Expired certificate fails", "T08": "Wrong-hostname certificate fails",
    "T09": "Wrong-CA certificate fails", "T10": "Mismatched certificate/key fails", "T11": "Anonymous attack request is denied",
    "T12": "Unauthorized role cannot execute privileged operations", "T13": "Unknown routes fail closed",
    "T14": "Spoofed identity headers do not grant access", "T15": "Splunk Web login works through gateway",
    "T16": "Splunk cookies and CSRF function correctly", "T17": "Splunk redirects and static assets work",
    "T18": "External Splunk mock accepts valid CA configuration", "T19": "Invalid external CA fails closed",
    "T20": "Invalid external token fails authentication", "T21": "Existing running AgentSecLab containers remain unchanged",
    "T22": "Existing Splunk volumes and indexes remain unchanged", "T23": "No private keys, credentials or tokens in Git changes or logs",
    "T24": "POC resources can be removed independently without touching the existing lab", "T25": "Rate limit applies to privileged attack operations",
}
RES = EVID / "results.json"


def rec(tid, status, note=""):
    data = json.loads(RES.read_text()) if RES.exists() else {}
    data[tid] = {"status": status, "note": note}
    RES.write_text(json.dumps(data, indent=1, sort_keys=True))
    return status


def check(tid, cond, note=""):
    rec(tid, "PASS" if cond else "FAIL", note)
    assert cond, f"{tid} {note}"


def creds():
    return dict(l.split("=", 1) for l in (RT / "creds.env").read_text().split("\n") if "=" in l)


class R:
    def __init__(self, rc, status, headers, body, err):
        self.rc, self.status, self.headers, self.body, self.err = rc, status, headers, body, err
    def h(self, name):
        return self.headers.get(name.lower(), [])


def curl(host, path, *, user=None, method="GET", headers=(), data=None, ca=None, port=PORT, jar=None, follow=False, extra=()):
    """TLS is ALWAYS verified: --cacert is mandatory and there is no insecure option in this helper."""
    ca = ca or (CERTS / "local" / "ca.pem")
    cmd = ["curl", "-sS", "-m", "20", "-D", "-", "-w", "\nHTTPCODE:%{http_code}", "--cacert", str(ca), "--resolve", f"{host}:{port}:127.0.0.1", "-X", method]
    if user: cmd += ["-u", f"{user}:{creds()['POC_' + user.upper() + '_PASSWORD']}"]
    for h in headers: cmd += ["-H", h]
    if data is not None: cmd += ["--data", data]
    if jar: cmd += ["-b", str(jar), "-c", str(jar)]
    if follow: cmd += ["-L"]
    cmd += list(extra) + [f"https://{host}:{port}{path}"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout
    status = int(out.rsplit("HTTPCODE:", 1)[1].strip() or 0) if "HTTPCODE:" in out else 0
    text = out.rsplit("\nHTTPCODE:", 1)[0].replace("\r\n", "\n")      # text mode already folds CRLF
    head, _, body = text.partition("\n\n")
    hd = {}
    for line in head.split("\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1); hd.setdefault(k.strip().lower(), []).append(v.strip())
    return R(p.returncode, status, hd, body, p.stderr)


def sh(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)


def protected_snapshot():
    """Metadata of every container/volume that is NOT part of the POC (the real lab)."""
    names = [n for n in sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split() if n.startswith("agentsec_")]
    cont = {}
    for n in sorted(names):
        i = json.loads(sh("docker", "inspect", n).stdout)[0]
        cont[n] = {"id": i["Id"], "image": i["Image"], "started": i["State"]["StartedAt"], "status": i["State"]["Status"], "restarts": i["RestartCount"],
                   "mounts": sorted((m.get("Name") or m.get("Source"), m["Destination"]) for m in i["Mounts"]),
                   "networks": sorted(i["NetworkSettings"]["Networks"])}
    vols = sorted(v for v in sh("docker", "volume", "ls", "-q").stdout.split() if "agentsec-gw-poc" not in v)
    vinfo = {v: json.loads(sh("docker", "volume", "inspect", v).stdout)[0]["CreatedAt"] for v in vols}
    nets = sorted(n for n in sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split() if "agentsec-gw-poc" not in n)
    return {"containers": cont, "volume_created": vinfo, "networks": nets}


@pytest.fixture(scope="session", autouse=True)
def _dirs():
    EVID.mkdir(exist_ok=True); (EVID / ".snap").mkdir(exist_ok=True)
    yield


def pytest_sessionfinish(session, exitstatus):
    if not RES.exists():
        return
    data = json.loads(RES.read_text())
    rows = [f"| {t} | {MATRIX[t]} | {data.get(t, {'status': 'NOT VERIFIED', 'note': 'not executed'})['status']} | {data.get(t, {'note': 'not executed'})['note']} |" for t in MATRIX]
    (EVID / "MATRIX.md").write_text("| ID | Test | Result | Evidence / note |\n|---|---|---|---|\n" + "\n".join(rows) + "\n")
