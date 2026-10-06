"""Canonical REPLAY specimens: the run.ids a workshop may present without a live run.

A dashboard that offers a run.id in an "Investigate specimen" dropdown is making
a promise: choose this and you will see evidence. Before this module the promise
had no owner. The specimen ids were literals in the build script, the event
bodies lived only under the gitignored ``artifacts/`` tree on one workstation,
and nothing in deployment carried them to a new Splunk index. A clean install
therefore shipped a dropdown pointing at nothing.

The contract this module owns:

    A run.id presented as a canonical REPLAY specimen MUST have a committed
    event pack in this repository, and deployment MUST seed that pack into the
    index before the workshop claims the specimen is available.

The packs are genuine historical runs. They are REPLAYED evidence, never
MEASURED evidence: the events are a recording, re-indexed verbatim with their
original timestamps and original bodies. Nothing here synthesises an event, and
nothing re-stamps one to look recent.

Seeding itself lives in ``scripts/splunk_hec_init.sh`` because that is the
component that already owns the index and the HEC token. This module is the
definition the seeder and the tests both read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SPECIMEN_FILE_SUFFIX = ".jsonl"
SPECIMEN_DIR_NAME = "specimens"

#: Where a lab's specimen packs live, relative to the repository root.
LAB_ROOT = Path("learning") / "level_1"


@dataclass(frozen=True)
class Specimen:
    """One committed REPLAY pack."""

    lab_id: str
    run_id: str
    path: Path
    events: tuple[dict, ...]

    @property
    def event_count(self) -> int:
        return len(self.events)

    def field(self, name: str) -> str | None:
        """First non-empty value of ``name`` across the pack."""
        for event in self.events:
            value = event.get(name)
            if value not in (None, ""):
                return str(value)
        return None

    @property
    def mode(self) -> str | None:
        return self.field("agentsec.testbed.mode")

    @property
    def profile(self) -> str | None:
        return self.field("agentsec.security.profile")

    @property
    def decision(self) -> str | None:
        return self.field("agentsec.control.decision")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def specimen_dir(lab_id: str, root: Path | None = None) -> Path:
    return (root or repo_root()) / LAB_ROOT / lab_id / SPECIMEN_DIR_NAME


def _read_pack(lab_id: str, path: Path) -> Specimen:
    run_id = path.name[: -len(SPECIMEN_FILE_SUFFIX)]
    events: list[dict] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:  # pragma: no cover - corrupt pack
            raise ValueError(f"{path.name} line {number} is not JSON: {exc}") from exc
        events.append(event)
    return Specimen(lab_id=lab_id, run_id=run_id, path=path, events=tuple(events))


def load_specimens(lab_id: str, root: Path | None = None) -> dict[str, Specimen]:
    """Every committed REPLAY pack for ``lab_id``, keyed by run.id."""
    directory = specimen_dir(lab_id, root)
    if not directory.is_dir():
        return {}
    packs = {}
    for path in sorted(directory.glob(f"*{SPECIMEN_FILE_SUFFIX}")):
        specimen = _read_pack(lab_id, path)
        packs[specimen.run_id] = specimen
    return packs


def validate(specimen: Specimen) -> list[str]:
    """Problems that would make this pack unsafe to present as evidence.

    A pack is only usable as a REPLAY specimen if every event really belongs to
    the run.id the filename claims. Otherwise seeding it would put one run's
    evidence under another run's name, which is evidence fabrication even when
    every individual event is genuine.
    """
    problems: list[str] = []
    if not specimen.events:
        problems.append(f"{specimen.run_id}: pack is empty")
        return problems
    for index, event in enumerate(specimen.events, start=1):
        actual = event.get("agentsec.run.id")
        if actual != specimen.run_id:
            problems.append(
                f"{specimen.run_id}: event {index} carries agentsec.run.id={actual!r}"
            )
        if not event.get("event.name"):
            problems.append(f"{specimen.run_id}: event {index} has no event.name")
        if not event.get("timestamp"):
            # The sourcetype extracts _time from this field. Without it the
            # event would be stamped at index time and misrepresent when the
            # run happened.
            problems.append(f"{specimen.run_id}: event {index} has no timestamp")
    return problems


__all__ = [
    "LAB_ROOT",
    "SPECIMEN_DIR_NAME",
    "SPECIMEN_FILE_SUFFIX",
    "Specimen",
    "load_specimens",
    "repo_root",
    "specimen_dir",
    "validate",
]
