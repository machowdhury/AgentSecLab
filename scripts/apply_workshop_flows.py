#!/usr/bin/env python3
"""Stamp the architecture flow image and evidence table formatting onto views.

This is stage 2 of the dashboard pipeline:

    1. scripts/build_lab_*_dashboard.py   rebuild a definition from scratch
    2. scripts/apply_workshop_flows.py    <- this script
    3. scripts/apply_guided_learning.py   must run last

The logic lives in agentsec.workshop_flows and was previously reachable only by
running that module directly. Nothing in the pipeline invoked it, so every
build script silently deleted viz_flow_diagram and the decision/executed colour
semantics from its view, and the loss was invisible until an unrelated test
happened to read them. Giving the stage a name is what makes it re-runnable.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agentsec.workshop_flows import apply_dashboards, write_svgs  # noqa: E402


def main() -> None:
    svgs = write_svgs()
    result = apply_dashboards()
    print(f"wrote {len(svgs)} flow SVGs")
    print(f"updated {result['views_updated']} views, {result['tables_changed']} tables reformatted")


if __name__ == "__main__":
    main()
