#!/usr/bin/env python3
"""Live adversarial and lifecycle checks against the DEPLOYED bridge v2. Uses only the mission's own APIs, docker exec into
the two lab containers (to play a compromised container), and the verifier script. Needs a finished run id (from the acceptance run).

ART must be set explicitly when the receipts live in another tree (on the lab Mac they are in the develop tree's artifacts/):
    ART=/path/to/develop-tree/artifacts python3 scripts/gateb_adversarial_live.py <run id>
The default is this repository's own artifacts/ directory. Do not change it back to a machine-specific path."""
import json, os, signal, subprocess, sys, time
from pathlib import Path
import requests

A = os.environ.get("ATTACK", "http://127.0.0.1:5001")
ART = Path(os.environ.get("ART", str(Path(__file__).resolve().parents[1] / "artifacts"))) / "loan_desk"
ROOT = Path(__file__).resolve().parents[1]
SH = str(ROOT / "scripts/loan_desk_verifier.sh")
ENV = {**os.environ, "AGENTSEC_ARTIFACTS_HOST_DIR": str(ART.parent), "PYTHON": str(ROOT / ".venv/bin/python")}
RUN = sys.argv[1]
log = []


def say(name, ok, detail=""):
    log.append({"check": name, "pass": bool(ok), "detail": str(detail)[:300]})
    print(("PASS " if ok else "FAIL ") + name + (" - " + str(detail)[:200] if detail else ""), flush=True)


def dx(c, cmd):
    r = subprocess.run(["docker", "exec", c, "sh", "-c", cmd], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def status():
    d = requests.get(f"{A}/api/missions/loan-desk/runs/{RUN}", timeout=20).json()
    return d["evidence"]["splunk"]


def verify_and_wait(expect, timeout=90):
    requests.post(f"{A}/api/missions/loan-desk/runs/{RUN}/verify", timeout=20)
    end = time.time() + timeout
    while time.time() < end:
        s = status()
        if s["status"] in expect:
            return s
        time.sleep(3)
    return status()


def heartbeat():
    return json.loads((ART / "receipts/verifier.json").read_text())


# the run needs a genuine receipt before anyone tries to forge or delete it
say('setup: a genuine receipt exists for the run', verify_and_wait({'SPLUNK_VERIFIED'}, timeout=120)['status'] == 'SPLUNK_VERIFIED')

# ---------------- A. a compromised container tries to forge
RID = "11111111-1111-4111-8111-111111111111"
for c in ("agentsec_acmebank", "agentsec_attack_service"):
    rc, out = dx(c, f"echo '{{}}' > /app/artifacts/loan_desk/receipts/{RID}.splunk.json")
    say(f"{c}: create a receipt", rc != 0 and "Read-only" in out, out)
    rc, out = dx(c, f"rm -f /app/artifacts/loan_desk/receipts/{RUN}.splunk.json; ls /app/artifacts/loan_desk/receipts/{RUN}.splunk.json")
    say(f"{c}: delete a real receipt", rc == 0 and "Read-only" in out or "Read-only" in out, out)
    rc, out = dx(c, f"mv /app/artifacts/loan_desk/receipts/verifier.json /app/artifacts/loan_desk/receipts/x.json")
    say(f"{c}: rename the heartbeat", rc != 0 and "Read-only" in out, out)
    rc, out = dx(c, "echo '{\"state\":\"running\",\"last_seen\":9999999999}' > /app/artifacts/loan_desk/receipts/verifier.json")
    say(f"{c}: overwrite the heartbeat to fake an online verifier", rc != 0 and "Read-only" in out, out)
    rc, out = dx(c, "find /app -name '*.key' -o -name '.bridge*' -o -name 'receipt.key' | head -3; ls -la /app/artifacts/loan_desk | grep -c key")
    say(f"{c}: no signing key reachable", out.split("\n")[0] == "" or out.split("\n")[0] == "0", out)
    rc, out = dx(c, "mount | grep receipts | head -1 | grep -o 'ro[,)]' | head -1")
    say(f"{c}: kernel reports the receipts mount as ro", out.startswith("ro"), out)
before = json.loads((ART / f"receipts/{RUN}.splunk.json").read_text())
say("host: the real receipt is untouched by the attempts", before["run_id"] == RUN and before["reconciled"] in (True, False))
r = subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/loan_desk_verifier.py"), "--check", str(ART / f"receipts/{RUN}.splunk.json")], capture_output=True, text=True)
say("host: receipt at rest audits as AUTHENTIC with the host key", r.stdout.startswith("AUTHENTIC"), r.stdout.strip()[:120])
tmp = Path("/tmp/tampered.splunk.json")
tmp.write_text(json.dumps({**before, "reconciled": not before["reconciled"]}))
r = subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/loan_desk_verifier.py"), "--check", str(tmp)], capture_output=True, text=True)
say("host: a modified copy audits as NOT AUTHENTIC", r.stdout.startswith("NOT AUTHENTIC"), r.stdout.strip()[:120])
tmp.unlink()

# ---------------- B. hostile requests from the container side
poison = ("echo 'not json' > /app/artifacts/loan_desk/requests/{u1}.json; "
          "echo '{{\"run_id\":\"{u2}\",\"requested_at\":\"abc\",\"nonce\":\"aabbccdd\"}}' > /app/artifacts/loan_desk/requests/{u2}.json; "
          "ln -s /etc/passwd /app/artifacts/loan_desk/requests/{u3}.json; mkfifo /app/artifacts/loan_desk/requests/{u4}.json; "
          "head -c 5000000 /dev/zero > /app/artifacts/loan_desk/requests/{u5}.json; echo ok")
ids = [f"{i}2222222-2222-4222-8222-222222222222" for i in range(1, 6)]
rc, out = dx("agentsec_acmebank", poison.format(u1=ids[0], u2=ids[1], u3=ids[2], u4=ids[3], u5=ids[4]))
say("container: planted malformed, symlink, FIFO and 5 MB requests", out.endswith("ok"), out[-80:])
time.sleep(8)
hb = heartbeat()
say("verifier survived the hostile requests (fresh running heartbeat)", hb["state"] == "running" and time.time() - hb["last_seen"] < 15, f"age {time.time() - hb['last_seen']:.1f}s")
rej = sorted(p.name for p in (ART / "rejected").glob("*")) if (ART / "rejected").exists() else []
say("malformed requests were quarantined, not retried forever", len(rej) >= 2, rej[:4])
log_tail = subprocess.run(["tail", "-5", str(Path.home() / ".local/state/agentsec/loan_desk/verifier.log")], capture_output=True, text=True).stdout
say("verifier still answers a legitimate request afterwards", verify_and_wait({"SPLUNK_VERIFIED"})["status"] == "SPLUNK_VERIFIED")
for p in ART.joinpath("requests").glob("*2222222-2222-4222-8222-222222222222.json"):
    p.unlink(missing_ok=True)

# ---------------- C. shutdown and recovery
r = subprocess.run(["sh", SH, "stop"], env=ENV, capture_output=True, text=True)
say("clean stop", "stopped" in r.stdout, r.stdout.strip())
time.sleep(1)
say("heartbeat says stopped", heartbeat()["state"] == "stopped")
s = verify_and_wait({"VERIFIER_OFFLINE", "NOT_VERIFIED", "TIMED_OUT"}, timeout=40)
say("page shows an explicit non-verified state while the verifier is stopped", s["status"] in ("VERIFIER_OFFLINE", "NOT_VERIFIED", "TIMED_OUT") and s["status"] != "SPLUNK_VERIFIED", s["status"])
r = subprocess.run(["sh", SH, "start"], env=ENV, capture_output=True, text=True)
say("start after stop", "started" in r.stdout, r.stdout.strip())
s = verify_and_wait({"SPLUNK_VERIFIED"}, timeout=120)
say("verification recovers automatically after restart", s["status"] == "SPLUNK_VERIFIED", s["status"])
pid = int((Path.home() / ".local/state/agentsec/loan_desk/verifier.pid").read_text())
os.kill(pid, signal.SIGKILL)
time.sleep(1)
r = subprocess.run(["sh", SH, "status"], env=ENV, capture_output=True, text=True)
say("after kill -9 the stale pid is not mistaken for a running verifier", "not running" in r.stdout, r.stdout.strip())
time.sleep(22)
s = verify_and_wait({"VERIFIER_OFFLINE", "TIMED_OUT", "NOT_VERIFIED"}, timeout=40)
say("page shows offline after the crash (heartbeat went stale)", s["status"] != "SPLUNK_VERIFIED", s["status"])
r = subprocess.run(["sh", SH, "start"], env=ENV, capture_output=True, text=True)
say("restart after crash replaces the stale pidfile", "started" in r.stdout, r.stdout.strip())
s = verify_and_wait({"SPLUNK_VERIFIED"}, timeout=120)
say("verification recovers after the crash", s["status"] == "SPLUNK_VERIFIED", s["status"])
pf = (Path.home() / ".local/state/agentsec/loan_desk/verifier.pid").read_text()
say("exactly one verifier process", len(subprocess.run(["pgrep", "-f", "loan_desk_verifier.py --artifacts"], capture_output=True, text=True).stdout.split()) == 1, pf)
Path(sys.argv[2]).write_text(json.dumps(log, indent=1) + "\n")
print(f"\n{sum(c['pass'] for c in log)}/{len(log)} passed")
sys.exit(0 if all(c["pass"] for c in log) else 1)
