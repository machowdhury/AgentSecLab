"""The shipped challenge set. One module per challenge; each exposes SCENARIO (agentsec.ctf.scenario.Scenario)."""

from __future__ import annotations

from agentsec.ctf.scenario import Scenario


def default_scenarios() -> dict[str, Scenario]:
    from agentsec.ctf import ch_confused_deputy, ch_note_smuggler, ch_poisoned_catalog

    mods: list = [ch_note_smuggler, ch_poisoned_catalog, ch_confused_deputy]
    return {m.SCENARIO.challenge.id: m.SCENARIO for m in mods}
