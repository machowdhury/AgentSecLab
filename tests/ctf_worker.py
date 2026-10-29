"""Importable (spawn-safe) helpers for the multi-process CTF ledger tests: each process builds its OWN CtfService over the same state directory."""
from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from agentsec.ctf.service import CtfService
from agentsec.ctf.store import CtfStore
from tests.ctf_support import FAKE, FakeScenario

FAKE2 = dataclasses.replace(FAKE, id="fake-two", title="Fake two")
NOW = 1_800_000_000.0


class FakeScenario2(FakeScenario):
    challenge = FAKE2


def clock() -> float:
    return NOW


def service(state_dir) -> CtfService:
    return CtfService(CtfStore(Path(state_dir)), {FAKE.id: FakeScenario(), FAKE2.id: FakeScenario2()}, clock=clock)


def redeem_worker(state_dir, aid, receipt, barrier, out) -> None:
    svc = service(state_dir)                 # construction happens before the barrier: only redeem() is raced
    barrier.wait(30)
    out.put((aid, *svc.redeem(aid, receipt)))


def crash_worker(state_dir, aid, receipt, stage) -> None:
    """Redeem, but die (os._exit, no cleanup, no flush) at the test seam: stage 'before_head' = after the ledger line is fsynced, before the head is written."""
    svc = service(state_dir)
    if stage == "before_head":
        CtfStore._write_head = lambda self, count, last: os._exit(97)    # test-only patch of the class in THIS process; production code is unchanged
    svc.redeem(aid, receipt)
    os._exit(0)
