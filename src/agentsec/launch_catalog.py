"""Closed allowlist for Attack Service launches. Not an authorization engine."""

from __future__ import annotations

from dataclasses import dataclass

from agentsec.experiment_context import EXPERIMENT_DEFINITIONS, ExperimentDefinition

RETEST_SUPPORT = "LIVE"


@dataclass(frozen=True)
class LaunchSpecimen:
    lab_id: str
    specimen_id: str
    profile: str
    mode: str
    execution: str
    user_id: str
    payload: str
    attack_id: str
    experiment_id: str
    live_supported: bool
    intentionally_vulnerable: bool
    retest_support: str
    runtime_route: str


def _from_definition(definition: ExperimentDefinition) -> LaunchSpecimen:
    return LaunchSpecimen(
        lab_id=definition.lab_id,
        specimen_id=definition.specimen_id,
        profile=definition.profile,
        mode=definition.mode,
        execution="live",
        user_id=definition.user_id,
        payload=definition.payload,
        attack_id=definition.attack_id,
        experiment_id=definition.experiment_id,
        live_supported=definition.live_supported,
        intentionally_vulnerable=definition.intentionally_vulnerable,
        retest_support=RETEST_SUPPORT,
        runtime_route=definition.runtime_route,
    )


LAUNCH_ALLOWLIST: tuple[LaunchSpecimen, ...] = tuple(
    _from_definition(row) for row in EXPERIMENT_DEFINITIONS
)

_INDEX = {
    (row.lab_id, row.specimen_id, row.mode, row.execution): row for row in LAUNCH_ALLOWLIST
}


def lookup_launch(
    *,
    lab_id: str,
    specimen_id: str,
    mode: str,
    execution: str,
    profile: str | None = None,
) -> LaunchSpecimen | None:
    del profile
    return _INDEX.get((lab_id, specimen_id, mode, execution))


def known_lab_ids() -> frozenset[str]:
    return frozenset(row.lab_id for row in LAUNCH_ALLOWLIST)


def known_specimen_ids(lab_id: str) -> frozenset[str]:
    return frozenset(row.specimen_id for row in LAUNCH_ALLOWLIST if row.lab_id == lab_id)


def allowlist_public_rows() -> list[dict]:
    return [
        {
            "lab_id": row.lab_id,
            "specimen_id": row.specimen_id,
            "mode": row.mode,
            "execution": row.execution,
            "experiment_id": row.experiment_id,
            "live_supported": row.live_supported,
            "intentionally_vulnerable": row.intentionally_vulnerable,
            "retest_support": row.retest_support,
            "attack_id": row.attack_id,
            "runtime_route": row.runtime_route,
            "profile_is_server_owned": True,
        }
        for row in LAUNCH_ALLOWLIST
    ]
