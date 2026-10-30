"""CTF orchestration: attempts, server-side verification, receipts, redemption, reset, scoreboard.

Success is decided here and only here, from bundles of events this process recorded while it drove the scenario itself. A client can
choose scenario parameters; it cannot submit a flag, an answer, a run id to be trusted, or text to be scored.
"""

from __future__ import annotations

import collections
import hashlib
import json
import logging
import os
import threading
import time
from typing import Callable

from agentsec.ctf import receipts
from agentsec.ctf.scenario import ParamError, Scenario
from agentsec.ctf.store import ATTEMPT_ID, CtfStore, StoreError, new_attempt_id
from agentsec.loan_desk import verify_bridge as vb
from agentsec.search_handoff import search_url, starter_spl
from agentsec import spl_policy

log = logging.getLogger("agentsec.ctf")
Result = tuple[int, dict]

ATTEMPT_TTL_S = 3600
MAX_LIVE = 40                                    # in-memory evidence bundles kept (attempts), oldest dropped
LIMITS = {"start": (20, 3600), "run": (60, 3600), "verify": (120, 3600), "reset": (20, 3600), "redeem": (60, 3600)}  # (count, window seconds)
STATES = ("NEW", "RUNNING", "VERIFIED", "FAILED", "RESET")
SCORE_POLICY = "One score per challenge: the first redeemed, verified receipt counts; later ones are history and award 0. No time or speed bonus."
SPLUNK_NOT_VERIFIED = ("NOT VERIFIED in Splunk. These events were recorded in memory by this CTF server and are not exported by it; "
                       "a search only finds them if your lab separately forwarded them, and even then it would show indexing, not truth.")
LABELS = {"tenancy": "NOT MULTI-USER", "hosting": "NOT PUBLIC HOSTING", "exposure": "LOCAL ONLY (loopback)",
          "authentication": "NOT PRODUCTION AUTHENTICATION", "participants": "ONE LOCAL PARTICIPANT"}


class Limiter:
    def __init__(self, clock: Callable[[], float]) -> None:
        self.clock, self.hits = clock, {k: collections.deque() for k in LIMITS}

    def allow(self, kind: str) -> int:
        """0 when allowed (and counted), else seconds until the oldest hit leaves the window."""
        n, window = LIMITS[kind]
        q, now = self.hits[kind], self.clock()
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= n:
            return max(1, int(window - (now - q[0])))
        q.append(now)
        return 0


def _digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class CtfService:
    def __init__(self, store: CtfStore, scenarios: dict[str, Scenario], *, clock: Callable[[], float] = time.time) -> None:
        self.store, self.scenarios, self.clock = store, scenarios, clock
        self._lock = threading.RLock()
        self._live: collections.OrderedDict[str, dict[str, dict]] = collections.OrderedDict()   # attempt -> run_id -> bundle
        self._limits = Limiter(clock)
        self.gateway_mode = os.environ.get("AGENTSEC_GATEWAY_MODE") == "1"

    # ---------------------------------------------------------------- helpers
    def _now(self) -> int:
        return int(self.clock())

    def _limited(self, kind: str) -> Result | None:
        wait = self._limits.allow(kind)
        return (429, {"error": "rate_limited", "retry_after_seconds": wait}) if wait else None

    def _load(self, attempt_id: object) -> dict | None:
        rec = self.store.load(attempt_id) if isinstance(attempt_id, str) and ATTEMPT_ID.match(attempt_id) else None
        return rec if rec and rec.get("challenge_id") in self.scenarios else None

    def _expired(self, rec: dict) -> bool:
        return rec["state"] in ("NEW", "RUNNING") and self._now() - rec["created_at"] > ATTEMPT_TTL_S

    def _drop_live(self, attempt_id: str) -> None:
        self._live.pop(attempt_id, None)

    def _splunk(self, rec: dict, splunk_web: str | None) -> dict:
        runs = []
        for r in rec["runs"]:
            spl = spl_policy.check(starter_spl(r["run_id"]))     # server-built from a server-minted UUID; never from input
            link = None if (self.gateway_mode or not splunk_web) else search_url(r["run_id"], splunk_web=splunk_web)
            runs.append({"run_id": r["run_id"], "search": spl, "link": link})
        return {"status": "NOT VERIFIED", "detail": SPLUNK_NOT_VERIFIED, "runs": runs,
                "link_note": "Splunk Web is not published behind the gateway, so no link is shown." if self.gateway_mode else None}

    def view(self, rec: dict, splunk_web: str | None = None) -> dict:
        sc = self.scenarios[rec["challenge_id"]]
        expired = self._expired(rec)
        receipt = rec.get("receipt")
        return {"attempt_id": rec["attempt_id"], "challenge_id": rec["challenge_id"], "state": rec["state"], "expired": expired,
                "created_at": rec["created_at"], "expires_at": rec["created_at"] + ATTEMPT_TTL_S,
                "steps_done": [r["step"] for r in rec["runs"]], "steps_total": sc.challenge.max_steps,
                "runs": [{"step": r["step"], "run_id": r["run_id"]} for r in rec["runs"]], "params": rec["params"],
                "verdict": rec.get("verdict"), "receipt": receipt,
                "redeemable": bool(receipt) and rec["state"] == "VERIFIED" and not rec.get("redeemed"),
                "redeemed": bool(rec.get("redeemed")), "splunk": self._splunk(rec, splunk_web), "labels": LABELS}

    def _save(self, rec: dict) -> None:
        rec["updated_at"] = self._now()
        self.store.save(rec)

    # ---------------------------------------------------------------- challenges
    def list_challenges(self) -> dict:
        board = self.scoreboard()
        scored = {r["challenge_id"] for r in board["rows"]}
        latest: dict[str, dict] = {}
        for rec in self.store.all_attempts():
            if rec["challenge_id"] in self.scenarios and rec["created_at"] >= latest.get(rec["challenge_id"], {"created_at": -1})["created_at"]:
                latest[rec["challenge_id"]] = rec
        out = []
        for cid, sc in self.scenarios.items():
            rec = latest.get(cid)
            status = ("SCORED" if cid in scored else "NOT STARTED" if rec is None else
                      {"NEW": "IN PROGRESS", "RUNNING": "IN PROGRESS", "VERIFIED": "VERIFIED, NOT REDEEMED", "FAILED": "NOT ACHIEVED", "RESET": "RESET"}[rec["state"]])
            out.append({**sc.challenge.public(), "status": status, "scored": cid in scored})
        return {"challenges": out, "total": board["total"], "labels": LABELS}

    def challenge(self, cid: object) -> Result:
        sc = self.scenarios.get(cid) if isinstance(cid, str) else None
        if sc is None:
            return 404, {"error": "unknown_challenge"}
        mine = [r for r in self.store.all_attempts() if r["challenge_id"] == cid]
        cur = max(mine, key=lambda r: r["created_at"], default=None)
        return 200, {**sc.challenge.public(), "materials": sc.materials(), "labels": LABELS,
                     "scored": any(r["challenge_id"] == cid for r in self.scoreboard()["rows"]),
                     "current_attempt": cur["attempt_id"] if cur and cur["state"] in ("NEW", "RUNNING") else None}

    def hint(self, cid: object) -> Result:
        sc = self.scenarios.get(cid) if isinstance(cid, str) else None
        if sc is None:
            return 404, {"error": "unknown_challenge"}
        if sc.challenge.hint_policy == "none" or not sc.challenge.hint:
            return 404, {"error": "no_hint"}
        return 200, {"hint": sc.challenge.hint, "cost_points": 0}

    # ---------------------------------------------------------------- lifecycle
    def start(self, cid: object, splunk_web: str | None = None) -> Result:
        sc = self.scenarios.get(cid) if isinstance(cid, str) else None
        if sc is None:
            return 404, {"error": "unknown_challenge"}
        with self._lock:
            if (lim := self._limited("start")):
                return lim
            if not self.store.make_room(self._now(), ATTEMPT_TTL_S):
                return 503, {"error": "attempt_store_full"}
            for old in self.store.all_attempts():                      # one open attempt per challenge: starting again is a retry
                if old["challenge_id"] == cid and old["state"] in ("NEW", "RUNNING"):
                    old["state"] = "RESET"
                    self._drop_live(old["attempt_id"])
                    self._save(old)
            now = self._now()
            rec = {"v": 1, "attempt_id": new_attempt_id(), "challenge_id": cid, "participant": receipts.PARTICIPANT, "state": "NEW",
                   "created_at": now, "updated_at": now, "params": [], "runs": [], "verdict": None, "receipt": None, "redeemed": False}
            self._save(rec)
            log.info("ctf attempt started challenge=%s attempt=%s", cid, rec["attempt_id"][:6])
            return 201, self.view(rec, splunk_web)

    def get(self, attempt_id: object, splunk_web: str | None = None) -> Result:
        rec = self._load(attempt_id)
        return (200, self.view(rec, splunk_web)) if rec else (404, {"error": "unknown_attempt"})

    def run(self, attempt_id: object, params: object, splunk_web: str | None = None) -> Result:
        with self._lock:
            rec = self._load(attempt_id)
            if rec is None:
                return 404, {"error": "unknown_attempt"}
            sc = self.scenarios[rec["challenge_id"]]
            if rec["state"] not in ("NEW", "RUNNING") or self._expired(rec):
                return 409, {"error": "attempt_not_active", "state": rec["state"]}
            if len(rec["runs"]) >= sc.challenge.max_steps:
                return 409, {"error": "all_steps_done"}
            try:
                clean = sc.validate(params, [r["step"] for r in rec["runs"]])
            except ParamError as exc:
                return 400, {"error": str(exc) or "bad_parameters"}
            if (lim := self._limited("run")):
                return lim
            created = self._now()
            try:
                run_id, bundle = sc.execute(clean, len(rec["runs"]))
            except Exception as exc:  # noqa: BLE001 - generic to the client; the type is enough for the operator
                log.warning("ctf scenario failed challenge=%s type=%s", rec["challenge_id"], type(exc).__name__)
                return 502, {"error": "scenario_failed"}
            if not isinstance(run_id, str) or not vb.RUN_ID.match(run_id):
                return 502, {"error": "scenario_failed"}
            bundle.update(attempt_id=rec["attempt_id"], challenge_id=rec["challenge_id"], run_id=run_id, created_at=created)
            self._live.setdefault(rec["attempt_id"], {})[run_id] = bundle
            while len(self._live) > MAX_LIVE:
                self._live.popitem(last=False)
            rec["params"].append(clean)
            rec["runs"].append({"step": clean.get("step", "run"), "run_id": run_id, "created_at": created})
            rec["state"] = "RUNNING"
            self._save(rec)
            return 200, self.view(rec, splunk_web)

    def _bundles(self, rec: dict, claimed: object) -> tuple[list[dict] | None, Result | None]:
        """Ownership and isolation. Every recorded run must be bound to THIS attempt and challenge, minted after it began, carry only its
        own events, and not appear in any other attempt. Returns (bundles in order, None) or (None, error)."""
        ids = [r["run_id"] for r in rec["runs"]]
        if claimed is not None and (not isinstance(claimed, list) or sorted(map(str, claimed)) != sorted(ids)):
            return None, (403, {"error": "run_not_owned"})
        others = {r["run_id"] for o in self.store.all_attempts() if o["attempt_id"] != rec["attempt_id"] for r in o["runs"]}
        live = self._live.get(rec["attempt_id"], {})
        out = []
        for r in rec["runs"]:
            b = live.get(r["run_id"])
            if b is None:
                return None, (410, {"error": "evidence_unavailable", "detail": "The server no longer holds this attempt's recorded events (restart or eviction). Reset and retry."})
            if (r["run_id"] in others or b.get("attempt_id") != rec["attempt_id"] or b.get("challenge_id") != rec["challenge_id"]
                    or b.get("run_id") != r["run_id"] or not isinstance(b.get("created_at"), int) or b["created_at"] < rec["created_at"]
                    or any(e.get("agentsec.run.id") != r["run_id"] for e in b.get("events", []))):
                return None, (403, {"error": "run_not_owned"})
            out.append(b)
        return out, None

    def verify(self, attempt_id: object, run_ids: object = None, splunk_web: str | None = None) -> Result:
        with self._lock:
            rec = self._load(attempt_id)
            if rec is None:
                return 404, {"error": "unknown_attempt"}
            sc = self.scenarios[rec["challenge_id"]]
            if rec["state"] in ("VERIFIED", "FAILED"):                 # the verdict is final: a repeat never re-decides
                if rec["state"] == "VERIFIED" and not rec.get("redeemed"):
                    # an unredeemed receipt may have lapsed: re-sign the SAME verdict with a fresh nonce/time. Still one score per challenge.
                    old = rec["receipt"]
                    rec["receipt"] = receipts.issue(self.store.key, attempt_id=rec["attempt_id"], challenge_id=rec["challenge_id"], run_ids=old["run_ids"],
                                                    points=old["points"], evidence_sha256=old["evidence_sha256"], now=self._now())
                    self._save(rec)
                return 200, {**self.view(rec, splunk_web), "replay": True}
            if rec["state"] != "RUNNING" or self._expired(rec):
                return 409, {"error": "attempt_not_active", "state": rec["state"]}
            if len(rec["runs"]) < sc.challenge.max_steps:
                return 409, {"error": "steps_incomplete", "steps_done": len(rec["runs"]), "steps_total": sc.challenge.max_steps}
            bundles, err = self._bundles(rec, run_ids)
            if err:
                return err
            if (lim := self._limited("verify")):
                return lim
            verdict = sc.verify(bundles)
            rec["verdict"] = verdict.public()
            rec["evidence_sha256"] = _digest([b["events"] for b in bundles])
            if verdict.ok:
                rec["state"] = "VERIFIED"
                rec["receipt"] = receipts.issue(self.store.key, attempt_id=rec["attempt_id"], challenge_id=rec["challenge_id"],
                                                run_ids=[r["run_id"] for r in rec["runs"]], points=sc.challenge.points,
                                                evidence_sha256=rec["evidence_sha256"], now=self._now())
            else:
                rec["state"] = "FAILED"
            self._save(rec)
            log.info("ctf verdict challenge=%s attempt=%s state=%s", rec["challenge_id"], rec["attempt_id"][:6], rec["state"])
            return 200, self.view(rec, splunk_web)

    def redeem(self, attempt_id: object, receipt: object) -> Result:
        with self._lock:
            if (lim := self._limited("redeem")):
                return lim
            rec = self._load(attempt_id)
            if rec is None:
                return 404, {"error": "unknown_attempt"}
            if not receipts.authentic(self.store.key, receipt):
                return 400, {"error": "invalid_receipt"}                # shape, key id or MAC: deliberately not distinguished
            if receipt["attempt_id"] != rec["attempt_id"] or receipt["challenge_id"] != rec["challenge_id"]:
                return 409, {"error": "receipt_mismatch"}
            sc = self.scenarios.get(rec["challenge_id"])
            if sc is None or receipt["points"] != sc.challenge.points:
                return 409, {"error": "receipt_mismatch"}
            stored = rec.get("receipt") or {}
            if rec.get("redeemed"):
                return 409, {"error": "already_redeemed"}
            if rec["state"] != "VERIFIED" or stored.get("nonce") != receipt["nonce"]:
                return 409, {"error": "attempt_not_redeemable", "state": rec["state"]}
            if not receipts.fresh(receipt, self._now()):
                return 410, {"error": "receipt_expired"}
            try:
                code, entry = self.store.consume(receipt, now=self._now())
            except (OSError, StoreError):
                return 503, {"error": "ledger_unavailable"}
            if code == "REPLAY":
                if not (entry and entry["receipt"]["nonce"] == receipt["nonce"]):
                    return 409, {"error": "already_redeemed"}
                # same receipt already in the ledger but this record never got marked (crash after append, or another instance won the race): finish, never spend again
                code = "OK"
            if code == "CORRUPT":
                return 503, {"error": "ledger_integrity_failed"}
            if code != "OK" or entry is None:
                return 503, {"error": "ledger_full"}
            rec["redeemed"] = True
            rec["awarded"] = entry["awarded"]
            self._save(rec)
            return 200, {"redeemed": True, "awarded": entry["awarded"], "seq": entry["seq"],
                         "note": "Points count once per challenge; a later verified attempt is recorded as history and awards 0.",
                         "scoreboard": self.scoreboard()}

    def reset(self, attempt_id: object, splunk_web: str | None = None) -> Result:
        with self._lock:
            rec = self._load(attempt_id)
            if rec is None:
                return 404, {"error": "unknown_attempt"}
            if rec["state"] != "RESET":
                if (lim := self._limited("reset")):
                    return lim
                rec["state"] = "RESET"       # receipt stays in the record as history; redemption requires state VERIFIED, so it is now dead
                self._drop_live(rec["attempt_id"])
                self._save(rec)
            return 200, self.view(rec, splunk_web)

    # ---------------------------------------------------------------- scoreboard
    def scoreboard(self) -> dict:
        """Derived ONLY from ledger entries whose own MAC and chain verify AND whose embedded receipt verifies again now. No counter exists."""
        entries, intact = self.store.read_ledger()
        rows, bad = {}, 0
        for e in entries:
            r = e.get("receipt")
            sc = self.scenarios.get(r.get("challenge_id")) if isinstance(r, dict) else None
            if not receipts.authentic(self.store.key, r) or sc is None or r["points"] != sc.challenge.points:
                bad += 1
                continue
            rows.setdefault(r["challenge_id"], {"challenge_id": r["challenge_id"], "title": sc.challenge.title, "difficulty": sc.challenge.difficulty,
                                                "points": r["points"], "attempt_id": r["attempt_id"], "run_ids": r["run_ids"], "issued_at": r["issued_at"],
                                                "consumed_at": e["consumed_at"], "key_id": r["key_id"]})
        listed = sorted(rows.values(), key=lambda x: x["consumed_at"])
        if not (intact and bad == 0):      # fail closed: a damaged, truncated or rolled-back ledger scores nothing
            return {"participant": receipts.PARTICIPANT, "rows": [], "total": 0, "ledger_intact": False, "invalid_entries": bad,
                    "error": "Ledger integrity check failed (a line is invalid, or the ledger was truncated or rolled back). Nothing is counted until it is repaired or reset.",
                    "policy": SCORE_POLICY, "labels": LABELS}
        return {"participant": receipts.PARTICIPANT, "rows": listed, "total": sum(x["points"] for x in listed), "ledger_intact": intact and bad == 0,
                "invalid_entries": bad, "policy": SCORE_POLICY,
                "labels": LABELS}

    def health(self) -> dict:
        return {"service": "ctf", "status": "healthy", "challenges": sorted(self.scenarios), "gateway_mode": self.gateway_mode, **LABELS}
