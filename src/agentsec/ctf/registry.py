"""Challenge registry: static metadata only.

There is NO flag, answer or expected-output material here or anywhere in the static assets. Success is decided by the server
from events it recorded itself (agentsec.ctf.verifiers); nothing in this file can be submitted to earn points.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CHALLENGE_ID = re.compile(r"^[a-z][a-z0-9-]{2,39}$")
DIFFICULTIES = ("Beginner", "Intermediate", "Advanced")
SIMULATION = ("SIMULATED", "REAL")
HINT_POLICIES = ("none", "one_free_hint")


@dataclass(frozen=True)
class Challenge:
    id: str
    title: str
    difficulty: str
    points: int
    technique: str
    control_boundary: str          # the control this attack is expected to meet
    objective: str
    learning_outcome: str          # the defensive lesson
    simulation: str                # SIMULATED or REAL
    simulation_note: str           # honest label shown on every page of the challenge
    engine: str                    # scenario engine binding (key in agentsec.ctf.engines)
    hint_policy: str = "one_free_hint"
    hint: str = ""
    max_steps: int = 1             # scenario executions per attempt

    def public(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "title", "difficulty", "points", "technique", "control_boundary", "objective",
                                              "learning_outcome", "simulation", "simulation_note", "engine", "hint_policy", "max_steps")}


def validate(c: Challenge) -> None:
    if not CHALLENGE_ID.match(c.id) or c.difficulty not in DIFFICULTIES or c.simulation not in SIMULATION or c.hint_policy not in HINT_POLICIES:
        raise ValueError(f"bad challenge definition {c.id!r}")
    if not isinstance(c.points, int) or isinstance(c.points, bool) or not 0 < c.points <= 1000 or not 1 <= c.max_steps <= 4:
        raise ValueError(f"bad points/steps {c.id!r}")


# Challenge definitions are appended by agentsec.ctf.challenges (one module per challenge) so each is self-contained.
CHALLENGES: dict[str, Challenge] = {}


def register(c: Challenge) -> Challenge:
    validate(c)
    if c.id in CHALLENGES:
        raise ValueError("duplicate challenge id")
    CHALLENGES[c.id] = c
    return c
