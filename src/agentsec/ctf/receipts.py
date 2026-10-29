"""Signed, non-replayable scoring receipts.

HMAC-SHA256 over the canonical JSON (sorted keys, no whitespace) of every field below, using the same sign/verify primitives as the Loan
Desk verifier receipts (agentsec.loan_desk.verify_bridge) with a separate CTF key. A receipt proves only that THIS server's verifier
reached this verdict from events THIS server recorded; it is not proof the events are true and it says nothing about Splunk.
Times are integer seconds; points are a plain int taken from the registry, never from the client.
"""

from __future__ import annotations

import re
import secrets

from agentsec.ctf.store import ATTEMPT_ID, key_id
from agentsec.loan_desk import verify_bridge as vb

TYP, VERSION = "agentsec.ctf.receipt", 1
PARTICIPANT = "local-participant"      # single local participant model
RECEIPT_TTL_S = 900                    # a receipt must be redeemed within 15 minutes of issue
MAX_SKEW_S = 60
FIELDS = {"typ", "v", "attempt_id", "challenge_id", "participant", "run_ids", "verdict", "points", "issued_at", "key_id",
          "nonce", "evidence_sha256", "splunk", "mac"}
_HEX = re.compile(r"^[0-9a-f]+$")


def issue(key: bytes, *, attempt_id: str, challenge_id: str, run_ids: list[str], points: int, evidence_sha256: str, now: int) -> dict:
    return vb.sign(key, {"typ": TYP, "v": VERSION, "attempt_id": attempt_id, "challenge_id": challenge_id, "participant": PARTICIPANT,
                         "run_ids": list(run_ids), "verdict": "VERIFIED", "points": points, "issued_at": int(now), "key_id": key_id(key),
                         "nonce": secrets.token_hex(16), "evidence_sha256": evidence_sha256, "splunk": "NOT VERIFIED"})


def shape_ok(r: object) -> bool:
    """Strict shape, checked BEFORE the MAC so garbage never reaches canonicalisation. Floats, bools and extra keys are rejected."""
    if not isinstance(r, dict) or set(r) != FIELDS:
        return False

    def i(x):
        return isinstance(x, int) and not isinstance(x, bool)

    return (r["typ"] == TYP and r["v"] == VERSION and isinstance(r["attempt_id"], str) and bool(ATTEMPT_ID.match(r["attempt_id"]))
            and isinstance(r["challenge_id"], str) and 3 <= len(r["challenge_id"]) <= 40 and r["participant"] == PARTICIPANT
            and isinstance(r["run_ids"], list) and 1 <= len(r["run_ids"]) <= 4
            and all(isinstance(x, str) and vb.RUN_ID.match(x) for x in r["run_ids"])
            and r["verdict"] == "VERIFIED" and i(r["points"]) and 0 < r["points"] <= 1000 and i(r["issued_at"]) and r["issued_at"] > 0
            and isinstance(r["key_id"], str) and len(r["key_id"]) == 8 and isinstance(r["nonce"], str) and len(r["nonce"]) == 32
            and bool(_HEX.match(r["nonce"])) and isinstance(r["evidence_sha256"], str) and len(r["evidence_sha256"]) == 64
            and r["splunk"] == "NOT VERIFIED" and isinstance(r["mac"], str) and len(r["mac"]) == 64)


def authentic(key: bytes, r: object) -> bool:
    """Shape and constant-time MAC. Says nothing about freshness or whether the attempt is still redeemable."""
    return shape_ok(r) and r["key_id"] == key_id(key) and vb.verify(key, r)


def fresh(r: dict, now: int) -> bool:
    return -MAX_SKEW_S <= now - r["issued_at"] <= RECEIPT_TTL_S
