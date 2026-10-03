#!/usr/bin/env python3
"""Shared Dashboard Studio helpers for AgentSec learner-facing workshops.

Does not generate SPL. Does not change authorization. Tokens remain bind-only
substitutions of already-validated hunt files.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

BG = "#F6F8FB"
NAVY = "#0B1F33"
TEXT = "#17202A"
SECONDARY = "#3D4654"
TEAL = "#007F86"
WHITE = "#FFFFFF"
BORDER = "#D9E0E7"

CANVAS_W = 1440
FULL = 1440
HALF = 720
THIRD = 480

EMPTY_STANDARD = (
    "No indexed event matched this evidence question. That is not SAFE, not TRUSTED, "
    "not blocked, not prevented, and not proof there was no attack."
)

HUNT_DROPDOWN_TITLE = "Investigate specimen"

PATH_B_GATE = (
    "This is **Path B — show solution**. Open it only after you tried Path A in "
    "Search. It is an answer key, not policy. Splunk does not enforce."
)

CAPSTONE_PATH_B_GATE = (
    "This is a **review key**, not the default path. Reconstruct the chain in "
    "Search first. Path B does not authorize, detect, or prove completeness."
)

REPLAY_HUNT_BANNER = """**REPLAY workshop.** There is no Attack Service launcher here. This is historical evidence, not a launch you just minted.

**WHY search this?** Reconstruct a canonical experiment in Search. Practice Path A without minting a new run.id.

**Path A — try it yourself:** [Open Splunk Search](/en-US/app/search/search). Copy a canonical Investigate specimen run.id. Start with `index=agentsec_telemetry sourcetype=otel:agentic:json` and quoted `agentsec.run.id`. Construct the hunt before you treat the tables as the answer. If zero rows, this volume may not contain that specimen. Empty is not DENY.

**Path B — show solution:** the bound tables on this tab are the expected shape for that specimen. Read them after Path A. They are not policy and not LIVE launch evidence.

**YOU SHOULD SEE** control.id, decision, reason, and whether execution events exist.
**THAT MEANS** this is the expected shape of a historical copy.
**IT DOES NOT MEAN** Splunk enforced the decision.
**NEXT** COMPARE ATTACK vs RETEST on the same fields, then PROVE.
"""

LIVE_INVESTIGATE_GATE = """**Guided path.** Paste the fresh LIVE run.id into the workshop **LIVE run.id** box and read the inline table. Studio does not receive that id from Attack Service by itself.

**Advanced.** Splunk Search remains available when you want to edit the SPL. Path B is optional and is an answer key, not policy. Splunk does not enforce.

If the inline table or Search returns zero rows, wait until Attack Service says **EVIDENCE READY**. Empty is not DENY, not prevention, and not a broken lab.
"""


def fingerprint_block(h: str) -> str:
    algo, digest = h.split(":", 1)
    return f"{algo}:\n{digest[:32]}\n{digest[32:]}"


def bind_run_id(spl: str, token: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError(f"expected __RUN_ID__ in query for token {token}")
    return spl.replace("__RUN_ID__", f'"${token}$"')


def bind_literal(spl: str, run_id: str) -> str:
    if "__RUN_ID__" not in spl:
        raise ValueError("expected __RUN_ID__ in query")
    if not run_id:
        raise ValueError("canonical run.id is empty")
    return spl.replace("__RUN_ID__", f'"{run_id}"')


def block(item: str, x: int, y: int, w: int, h: int) -> dict:
    return {"item": item, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}


def markdown(viz_id: str, body: str, title: str | None = None) -> tuple[str, dict]:
    viz = {
        "type": "splunk.markdown",
        "options": {
            "markdown": textwrap.dedent(body).strip() + "\n",
            "fontColor": TEXT,
            "backgroundColor": WHITE,
            "fontSize": "large",
        },
    }
    if title:
        viz["title"] = title
    return viz_id, viz


def table(
    viz_id: str,
    ds: str,
    title: str,
    description: str,
    *,
    no_data: str,
) -> tuple[str, dict]:
    return viz_id, {
        "type": "splunk.table",
        "title": title,
        "description": description,
        "dataSources": {"primary": ds},
        "showProgressBar": True,
        "showLastUpdated": False,
        "hideWhenNoData": False,
        "options": {
            "count": 50,
            "showRowNumbers": False,
            "backgroundColor": WHITE,
            "headerBackgroundColor": NAVY,
            "headerTextColor": WHITE,
            "noDataMessage": no_data,
            "columnFormat": {
                "decision": {
                    "rowBackgroundColors": '> table | seriesByName("decision") | matchValue(decisionBackgrounds)',
                    "rowColors": '> table | seriesByName("decision") | matchValue(decisionText)',
                },
                "executed": {
                    "rowBackgroundColors": '> table | seriesByName("executed") | matchValue(executedBackgrounds)',
                    "rowColors": '> table | seriesByName("executed") | matchValue(executedText)',
                },
            },
        },
        "context": {
            "decisionBackgrounds": [
                {"match": "ALLOW", "value": "#E8EEF5"},
                {"match": "DENY", "value": "#F6EBD8"},
                {"match": "ERROR", "value": "#F8E6E6"},
                {"match": "OBSERVE", "value": "#F0F3F6"},
            ],
            "decisionText": [
                {"match": "ALLOW", "value": "#3568A8"},
                {"match": "DENY", "value": "#B7791F"},
                {"match": "ERROR", "value": "#C62828"},
                {"match": "OBSERVE", "value": SECONDARY},
            ],
            "executedBackgrounds": [
                {"match": "true", "value": NAVY},
                {"match": "false", "value": "#EEF1F4"},
                {"match": "1", "value": NAVY},
                {"match": "0", "value": "#EEF1F4"},
            ],
            "executedText": [
                {"match": "true", "value": WHITE},
                {"match": "false", "value": SECONDARY},
                {"match": "1", "value": WHITE},
                {"match": "0", "value": SECONDARY},
            ],
        },
    }


def search_ds(ds_id: str, name: str, query: str) -> tuple[str, dict]:
    return ds_id, {
        "type": "ds.search",
        "name": name,
        "options": {"query": query},
    }


def layout(structure: list[dict], height: int) -> dict:
    return {
        "type": "grid",
        "options": {
            "backgroundColor": BG,
            "display": "auto-scale",
            "gutterSize": 8,
            "width": CANVAS_W,
            "height": height,
        },
        "structure": structure,
    }


def input_block(item: str, x: int, y: int, w: int, h: int) -> dict:
    """Place a Studio input on a tab canvas. Not a globalInputs hunt token."""
    return {"item": item, "type": "input", "position": {"x": x, "y": y, "w": w, "h": h}}


def show_when(*condition_ids: str) -> dict:
    """Native Studio visibility (Splunk 10.2 expressions.conditions + containerOptions).

    Hidden when the listed showConditions are false. Multiple ids require all-true.
    Custom JavaScript is not used.
    """
    if not condition_ids:
        raise ValueError("show_when requires at least one condition id")
    visibility: dict = {"showConditions": list(condition_ids)}
    if len(condition_ids) > 1:
        visibility["showWhenConditions"] = "all-true"
    return {"containerOptions": {"visibility": visibility}}


def token_equals_condition(cond_id: str, *, name: str, token: str, value: str) -> tuple[str, dict]:
    escaped = json.dumps(value)
    return cond_id, {"name": name, "value": f"${token}$ = {escaped}"}


def token_in_condition(cond_id: str, *, name: str, token: str, values: list[str]) -> tuple[str, dict]:
    parts = " or ".join(f"${token}$ = {json.dumps(value)}" for value in values)
    return cond_id, {"name": name, "value": parts}


def specimen_dropdown(
    input_id: str,
    *,
    token: str,
    default: str,
    items: list[tuple[str, str]],
    title: str = HUNT_DROPDOWN_TITLE,
) -> tuple[str, dict]:
    """Human-readable hunt selector. Values remain canonical LIVE run.id strings."""
    return input_id, {
        "type": "input.dropdown",
        "title": title,
        "options": {
            "token": token,
            "defaultValue": default,
            "items": [{"label": label, "value": value} for label, value in items],
        },
    }


def workshop_header(
    *,
    title: str,
    purpose: str,
    lab_id: str,
    evidence: str = "LIVE EVIDENCE",
    extra: str = "",
) -> str:
    extra_line = f"\n{extra}" if extra else ""
    return f"""
# {title}

{purpose}

**{evidence}** · `{lab_id}`{extra_line}

Workshop: LEARN · BASELINE · ATTACK · OBSERVE · HUNT · DETECT · DEFEND · RETEST · COMPARE · PROVE
"""


def studio_defaults() -> dict:
    return {
        "visualizations": {
            "splunk.table": {
                "options": {
                    "backgroundColor": WHITE,
                    "headerBackgroundColor": NAVY,
                    "headerTextColor": WHITE,
                }
            },
            "splunk.markdown": {"options": {"fontColor": TEXT, "fontSize": "large"}},
        }
    }


def layout_options() -> dict:
    return {
        "submitButton": False,
        "submitOnDashboardLoad": True,
        "showTitleAndDescription": True,
    }


def ensure_browser_title(definition: dict, *, label: str, description: str) -> dict:
    """Splunk Studio uses definition.title for the browser tab.

    A missing title renders as "undefined | Splunk". The XML label is not that field.
    The title is always the view label so a pre-existing root title cannot diverge.
    """
    definition["title"] = label
    definition.setdefault("description", description)
    return definition


def write_studio_xml(
    path: Path,
    definition: dict,
    *,
    label: str,
    description: str,
    definition_path: Path | None = None,
) -> None:
    ensure_browser_title(definition, label=label, description=description)
    if definition_path is not None:
        write_definition(definition_path, definition)
    payload = json.dumps(definition, indent=2, ensure_ascii=False)
    if "]]>" in payload:
        raise ValueError("definition contains CDATA terminator")
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<dashboard version="2" theme="light">\n'
        f"  <label>{label}</label>\n"
        f"  <description>{description}</description>\n"
        "  <definition><![CDATA[\n"
        f"{payload}\n"
        "  ]]></definition>\n"
        "</dashboard>\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml, encoding="utf-8")


def write_definition(path: Path, definition: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(definition, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
