"""Shared CTF test helpers: an isolated service on a temp state dir, and a tiny fake scenario for the core tests."""

from __future__ import annotations

import uuid

from agentsec.ctf.registry import Challenge
from agentsec.ctf.scenario import ParamError, Verdict, posture, strict_params
from agentsec.ctf.service import CtfService
from agentsec.ctf.store import CtfStore

FAKE = Challenge(id="fake-one", title="Fake", difficulty="Beginner", points=10, technique="t", control_boundary="b", objective="o",
                 learning_outcome="l", simulation="SIMULATED", simulation_note="n", engine="fake", hint="try baseline")


class FakeScenario:
    """Success iff the recorded events say baseline. The 'events' are what the engine recorded, never client text."""
    challenge = FAKE
    runs_executed = 0

    def validate(self, params, prior_steps):
        return strict_params(params, {"posture": posture})

    def execute(self, params, step_index):
        FakeScenario.runs_executed += 1
        rid = str(uuid.uuid4())
        return rid, {"events": [{"agentsec.run.id": rid, "event.name": "x", "agentsec.defense.posture": params["posture"]}]}

    def verify(self, bundles):
        ok = all(e.get("agentsec.defense.posture") == "baseline" for b in bundles for e in b["events"])
        return Verdict(ok, "objective met" if ok else "objective not met", (("baseline", ok),))

    def materials(self):
        return {}


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def make_service(tmp_path, scenarios=None, clock=None):
    clock = clock or Clock()
    return CtfService(CtfStore(tmp_path / "ctf"), scenarios if scenarios is not None else {FAKE.id: FakeScenario()}, clock=clock), clock
