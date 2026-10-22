"""Lab registry: curriculum.json joined with the approved taxonomy and lab_registry_data.json.

One entry per curriculum entry (19 labs + 12 checkpoints). The registry never invents
membership: every id comes from curriculum.json, and tests fail if any entry, Splunk
view, domain or pillar link is missing. Tier describes what the learner can do today,
not what is planned. Pillar status "implemented" is only claimed where a lab exercises it.
"""

from __future__ import annotations

import json
from pathlib import Path

TIERS = ("GUIDED MISSION", "WORKBENCH", "REPLAY", "CONTENT-ONLY")
PILLAR_STATUSES = ("implemented", "partial", "planned")
DOMAIN_CONFIDENCE = ("content-verified", "review")
TIER_FOR_MODE = {"LIVE": ("GUIDED MISSION", "WORKBENCH"), "REPLAY": ("REPLAY", "CONTENT-ONLY")}

ROOT = Path(__file__).resolve().parents[2]
ACADEMY = Path("learning/academy")
VIEWS = Path("splunk_app/agentsec/default/data/ui/views")


class RegistryError(ValueError):
    pass


def _load(root: Path, rel: Path) -> dict:
    return json.loads((root / rel).read_text(encoding="utf-8"))


def load_registry(root: Path = ROOT) -> dict:
    curriculum = _load(root, ACADEMY / "curriculum.json")
    taxonomy = _load(root, ACADEMY / "taxonomy.json")
    data = {e["lab_id"]: e for e in _load(root, ACADEMY / "lab_registry_data.json")["entries"]}
    domains = {d["id"]: d for d in taxonomy["domains"]}
    pillars = {p["id"] for p in taxonomy["pillars"]}

    rows = [
        {"lab_id": lab["lab_id"], "title": lab["title"], "kind": "lab", "level": level["id"],
         "mode": lab["mode"], "view": lab["view"]}
        for level in curriculum["levels"] for lab in level["labs"]
    ] + [
        {"lab_id": cp["lab_id"], "title": cp["title"], "kind": "checkpoint", "level": cp["placement"],
         "mode": cp["mode"], "view": cp["view"]}
        for cp in curriculum["checkpoints"]
    ]

    entries, seen = [], set()
    for row in rows:
        lab_id = row["lab_id"]
        if lab_id in seen:
            raise RegistryError(f"duplicate curriculum entry {lab_id}")
        seen.add(lab_id)
        meta = data.get(lab_id)
        if meta is None:
            raise RegistryError(f"no registry data for {lab_id}")
        if meta["tier"] not in TIER_FOR_MODE[row["mode"]]:
            raise RegistryError(f"{lab_id}: tier {meta['tier']} is not valid for mode {row['mode']}")
        if meta["primary_domain"] not in domains:
            raise RegistryError(f"{lab_id}: unknown domain {meta['primary_domain']}")
        if meta["secondary_domain"] is not None and meta["secondary_domain"] not in domains:
            raise RegistryError(f"{lab_id}: unknown secondary domain {meta['secondary_domain']}")
        for link in meta["pillars"]:
            if link["id"] not in pillars or link["status"] not in PILLAR_STATUSES:
                raise RegistryError(f"{lab_id}: bad pillar link {link}")
        if not (root / VIEWS / f"{row['view']}.xml").is_file():
            raise RegistryError(f"{lab_id}: Splunk view {row['view']} is missing")
        entries.append({
            **row,
            "tier": meta["tier"],
            "primary_domain": meta["primary_domain"],
            "secondary_domain": meta["secondary_domain"],
            "domain_confidence": meta["domain_confidence"],
            "pillars": meta["pillars"],
        })
    unknown = set(data) - seen
    if unknown:
        raise RegistryError(f"registry data for entries not in the curriculum: {sorted(unknown)}")
    return {"schema_version": "1.0.0", "entries": entries, "domains": taxonomy["domains"], "pillars": taxonomy["pillars"]}


def coverage(registry: dict) -> dict:
    """Plain counts for reports. Gaps are reported, never papered over."""
    entries = registry["entries"]
    by_domain = {d["id"]: [] for d in registry["domains"]}
    for e in entries:
        by_domain[e["primary_domain"]].append(e["lab_id"])
    pillar_status = {p["id"]: {s: 0 for s in PILLAR_STATUSES} for p in registry["pillars"]}
    for e in entries:
        for link in e["pillars"]:
            pillar_status[link["id"]][link["status"]] += 1
    tiers = {t: sum(1 for e in entries if e["tier"] == t) for t in TIERS}
    return {
        "entries": len(entries),
        "tiers": tiers,
        "domains_without_primary_entry": sorted(d for d, labs in by_domain.items() if not labs),
        "pillars_without_implemented_link": sorted(p for p, c in pillar_status.items() if c["implemented"] == 0),
        "pillar_status": pillar_status,
        "domains": {d: len(labs) for d, labs in by_domain.items()},
    }
