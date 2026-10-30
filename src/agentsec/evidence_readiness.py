"""Bounded evidence-readiness probe. HEC success is not EVIDENCE_READY."""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

from agentsec.search_handoff import completeness_spl

logger = logging.getLogger("agentsec.evidence_readiness")

DEFAULT_TIMEOUT_SEC = 60
DEFAULT_INTERVAL_SEC = 2
MAX_TIMEOUT_SEC = 120
MAX_INTERVAL_SEC = 15
SPLUNK_CONTAINER = "agentsec_splunk"
STATE_UNAVAILABLE = "EVIDENCE_CHECK_UNAVAILABLE"
PROBE_CANNOT_EXECUTE = frozenset(
    {"docker_not_available", "probe_misconfigured", "tls_verification_failed", "probe_auth_failed"}
)
# The REST probe is DISABLED unless this is "true". Its TLS, credential and least-privilege design
# is pending separate approval; nothing in the lab enables it.
REST_PROBE_FLAG = "AGENTSEC_SPLUNK_PROBE_ENABLED"


def count_local_events(artifacts_dir: Path, run_id: str) -> int | None:
    path = artifacts_dir / run_id / "events.jsonl"
    if not path.is_file():
        return None
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def read_export_doc(artifacts_dir: Path, run_id: str) -> dict | None:
    path = artifacts_dir / run_id / "export.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def clamp_timeout(raw: object, default: int = DEFAULT_TIMEOUT_SEC) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(0, min(MAX_TIMEOUT_SEC, value))


def clamp_interval(raw: object, default: int = DEFAULT_INTERVAL_SEC) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(1, min(MAX_INTERVAL_SEC, value))


def probe_splunk_count(
    run_id: str,
    *,
    container: str = SPLUNK_CONTAINER,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> dict:
    """Count indexed events for run.id. Password stays in the Splunk container env."""

    from agentsec import spl_policy
    spl = completeness_spl(run_id)
    collapsed = " ".join(line.strip() for line in spl.splitlines() if line.strip())
    try:
        collapsed = spl_policy.checked(collapsed, backend="docker-exec")      # admin-credential path: same read-only policy as REST
    except spl_policy.SplPolicyViolation:
        return {"splunk_attempted": False, "splunk_ok": False, "splunk_count": None, "error": "forbidden_spl"}
    # The search travels as an environment variable through an argument list; the in-container script is a constant (no shell ever sees the search text).
    inner = 'exec /opt/splunk/bin/splunk search "$AGENTSEC_SPL" -auth "admin:${SPLUNK_PASSWORD}" -output csv'
    run = runner or subprocess.run
    try:
        proc = run(
            ["docker", "exec", "-u", "splunk", "-e", "AGENTSEC_SPL=" + collapsed, container, "bash", "-lc", inner],
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
    except FileNotFoundError:
        return {
            "splunk_attempted": False,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "docker_not_available",
        }
    except subprocess.TimeoutExpired:
        return {
            "splunk_attempted": True,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "splunk_probe_timeout",
        }
    if proc.returncode != 0:
        logger.info("splunk evidence probe failed rc=%s", proc.returncode)
        return {
            "splunk_attempted": True,
            "splunk_ok": False,
            "splunk_count": None,
            "error": "splunk_probe_failed",
        }
    return _count_from_csv(proc.stdout or "")


def _count_from_csv(text: str) -> dict:
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("WARNING:")]
    count = 0
    if lines:
        rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
        if rows and "n" in rows[0]:
            try:
                count = int(rows[0]["n"])
            except (TypeError, ValueError):
                count = 0
    return {"splunk_attempted": True, "splunk_ok": True, "splunk_count": count, "error": None}


def _probe_failure(error: str, *, attempted: bool = True) -> dict:
    return {"splunk_attempted": attempted, "splunk_ok": False, "splunk_count": None, "error": error}


def probe_splunk_count_rest(
    run_id: str,
    *,
    env: dict | None = None,
    opener: Callable[..., object] | None = None,
) -> dict:
    """Count indexed events over the Splunk REST API with a least-privilege token.

    Disabled by default. When enabled it fails closed: TLS verification and host name
    checks stay on (an explicit CA file is required), there is no skip-verify path, and a
    missing setting is probe_misconfigured, never an empty success. The Attack Service
    needs no Docker access and no admin password for this probe.
    """
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    env = os.environ if env is None else env
    if str(env.get(REST_PROBE_FLAG, "")).lower() != "true":
        return _probe_failure("probe_disabled", attempted=False)
    url, token, ca_file = (env.get(k, "") for k in (
        "AGENTSEC_SPLUNK_PROBE_URL", "AGENTSEC_SPLUNK_PROBE_TOKEN", "AGENTSEC_SPLUNK_PROBE_CA_FILE"))
    if not (url.startswith("https://") and token and ca_file and Path(ca_file).is_file()):
        return _probe_failure("probe_misconfigured", attempted=False)
    from agentsec import spl_policy
    try:
        spl = spl_policy.checked(" ".join(line.strip() for line in completeness_spl(run_id).splitlines() if line.strip()), backend="rest-legacy")
    except spl_policy.SplPolicyViolation:
        return _probe_failure("forbidden_spl", attempted=False)
    body = urllib.parse.urlencode({"search": "search " + spl if not spl.lstrip().startswith(("search", "|")) else spl,
                                   "output_mode": "csv", "earliest_time": "0"}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/services/search/v2/jobs/export", data=body,
                                 headers={"Authorization": "Bearer " + token}, method="POST")
    try:
        ctx = ssl.create_default_context(cafile=ca_file)  # check_hostname and CERT_REQUIRED stay on
        resp = (opener or urllib.request.urlopen)(req, timeout=30, context=ctx)
        return _count_from_csv(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return _probe_failure("probe_auth_failed" if exc.code in (401, 403) else "splunk_probe_failed")
    except (ssl.SSLError, ssl.CertificateError):
        return _probe_failure("tls_verification_failed")
    except urllib.error.URLError as exc:
        return _probe_failure("tls_verification_failed" if isinstance(exc.reason, ssl.SSLError) else "splunk_probe_failed")
    except TimeoutError:
        return _probe_failure("splunk_probe_timeout")


def probe_splunk_count_client(run_id: str, *, env: dict | None = None, client=None) -> dict:
    """External Splunk modes: the shared strict-TLS client. Same result shape and error words as the legacy REST probe."""
    from agentsec.splunk_client import SplunkError, client_for_mode
    try:
        client = client or client_for_mode(env)
        if client is None:
            return _probe_failure("probe_disabled", attempted=False)
        text = client.export_csv(" ".join(line.strip() for line in completeness_spl(run_id).splitlines() if line.strip()))
    except SplunkError as exc:
        words = {"config_invalid": "probe_misconfigured", "tls_verification_failed": "tls_verification_failed", "auth_failed": "probe_auth_failed",
                 "forbidden": "probe_auth_failed", "timeout": "splunk_probe_timeout"}
        return _probe_failure(words.get(exc.code, "splunk_probe_failed"), attempted=exc.code != "config_invalid")
    return _count_from_csv(text)


def select_probe(env: dict | None = None) -> Callable[[str], dict]:
    """Order: shared REST client (external mode, or REST URL + token file set), legacy flag-gated REST probe, then the docker-exec probe."""
    env = os.environ if env is None else env
    from agentsec.splunk_client import rest_configured
    if str(env.get("AGENTSEC_SPLUNK_MODE", "BUNDLED")).strip().upper() in ("EXTERNAL_ENTERPRISE", "CLOUD") or rest_configured(env):
        return lambda run_id: probe_splunk_count_client(run_id, env=env)     # authenticated, strict-TLS REST; no Docker needed
    if str(env.get(REST_PROBE_FLAG, "")).lower() == "true":
        return lambda run_id: probe_splunk_count_rest(run_id, env=env)
    return probe_splunk_count


def wait_for_searchable_evidence(
    run_id: str,
    *,
    artifacts_dir: Path,
    timeout_seconds: int = DEFAULT_TIMEOUT_SEC,
    interval_seconds: int = DEFAULT_INTERVAL_SEC,
    probe_fn: Callable[[str], dict] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> dict:
    """Poll until Splunk has at least one event for run.id, or the budget expires.

    Does not treat local export.json hec.ok / otlp.ok as EVIDENCE_READY.
    """

    timeout_seconds = clamp_timeout(timeout_seconds)
    interval_seconds = clamp_interval(interval_seconds)
    local_count = count_local_events(artifacts_dir, run_id)
    export_doc = read_export_doc(artifacts_dir, run_id) or {}
    probe = probe_fn or select_probe()
    deadline = monotonic_fn() + timeout_seconds
    last: dict = {
        "splunk_attempted": False,
        "splunk_ok": False,
        "splunk_count": None,
        "error": None,
    }
    timed_out = False
    while True:
        last = probe(run_id)
        count = last.get("splunk_count")
        if isinstance(count, int) and count >= 1:
            timed_out = False
            break
        if last.get("error") in PROBE_CANNOT_EXECUTE:
            timed_out = False
            break
        if timeout_seconds <= 0:
            timed_out = False
            break
        if monotonic_fn() >= deadline:
            timed_out = True
            break
        sleep_fn(interval_seconds)

    splunk_count = last.get("splunk_count") if isinstance(last.get("splunk_count"), int) else None
    searchable = isinstance(splunk_count, int) and splunk_count >= 1
    completeness_ok = (
        searchable and local_count is not None and splunk_count == local_count
    )
    if searchable:
        evidence_state = "EVIDENCE_READY"
    elif last.get("error") in PROBE_CANNOT_EXECUTE:
        evidence_state = STATE_UNAVAILABLE
    else:
        evidence_state = "WAITING_FOR_EVIDENCE"
    return {
        "run_id": run_id,
        "evidence_state": evidence_state,
        "verification": verification_label(evidence_state),
        "splunk_verified": searchable,
        "splunk_attempted": bool(last.get("splunk_attempted")),
        "splunk_ok": bool(last.get("splunk_ok")),
        "splunk_count": splunk_count,
        "local_event_count": local_count,
        "completeness_ok": completeness_ok,
        "evidence_timeout": timed_out and evidence_state == "WAITING_FOR_EVIDENCE",
        "probe_error": last.get("error"),
        "otlp.ok": export_doc.get("otlp.ok"),
        "hec.ok": export_doc.get("hec.ok"),
        "note": (
            "EVIDENCE_READY means Splunk returned dc(_raw)>=1 for this run.id. "
            "otlp.ok and HEC HTTP 200 are not EVIDENCE_READY. "
            "Timeout is not a failed attack, DENY, SAFE, or BLOCKED."
        ),
    }


def verification_label(evidence_state: str) -> str:
    """The three words a learner sees. Unavailable is never 'not verified' and never zero rows."""
    return {"EVIDENCE_READY": "VERIFIED", STATE_UNAVAILABLE: "VERIFICATION UNAVAILABLE"}.get(evidence_state, "NOT VERIFIED")


def rollup_evidence(probes: list[dict]) -> dict:
    """Combine independent run probes without treating a dead probe as zero rows."""

    states = [str(probe.get("evidence_state") or "") for probe in probes]
    if states and all(state == "EVIDENCE_READY" for state in states):
        state = "EVIDENCE_READY"
    elif any(state == STATE_UNAVAILABLE for state in states):
        state = STATE_UNAVAILABLE
    else:
        state = "WAITING_FOR_EVIDENCE"
    errors = [probe.get("probe_error") for probe in probes if probe.get("probe_error")]
    timed_out = any(bool(probe.get("evidence_timeout")) for probe in probes)
    return {
        "evidence_state": state,
        "evidence_timeout": timed_out and state == "WAITING_FOR_EVIDENCE",
        "probe_error": errors[0] if state == STATE_UNAVAILABLE and errors else None,
        "verification": verification_label(state),
        "splunk_verified": state == "EVIDENCE_READY",
    }


def env_timeout() -> int:
    return clamp_timeout(os.environ.get("AGENTSEC_EVIDENCE_TIMEOUT_SEC"), DEFAULT_TIMEOUT_SEC)


def env_interval() -> int:
    return clamp_interval(os.environ.get("AGENTSEC_EVIDENCE_INTERVAL_SEC"), DEFAULT_INTERVAL_SEC)
