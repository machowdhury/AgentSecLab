"""The guided-learning generator must not clobber hand-maintained Your Path code.

`scripts/apply_guided_learning.py` derives the Your Path catalog from the
curriculum. The surrounding rendering, styling and Splunk dashboard-ready
lifecycle in `agentsec_learner_path.js` are maintained by hand. The generator
used to emit the whole file from a template, so running it silently reverted
that work and shipped the regression under the app build then in force.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Hand-maintained behaviour the generator must leave alone.
HAND_MAINTAINED_MARKERS = (
    'require(["splunkjs/mvc/simplexml/ready!"]',  # Splunk dashboard-ready lifecycle
    "MAX_WAIT_ATTEMPTS",
    "data-agentsec-mounted",
    "agentsec-path-hero",
    "nextWorkshop",
)


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "apply_guided_learning", ROOT / "scripts" / "apply_guided_learning.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_write_path_is_idempotent_and_preserves_hand_maintained_code():
    generator = load_generator()
    curriculum = json.loads(generator.CURRICULUM_PATH.read_text(encoding="utf-8"))
    rows = generator.workshop_rows(curriculum)

    outputs = (generator.PATH_JS, generator.PATH_XML)
    before = {path: path.read_bytes() for path in outputs}
    try:
        generator.write_path(rows)
        after = {path: path.read_bytes() for path in outputs}
    finally:
        for path, data in before.items():
            path.write_bytes(data)

    for path in outputs:
        assert after[path] == before[path], f"{path.relative_to(ROOT)} drifted from its generator"

    source = before[generator.PATH_JS].decode("utf-8")
    for marker in HAND_MAINTAINED_MARKERS:
        assert marker in source, marker


def test_generated_catalog_covers_every_guided_workshop_with_relative_hrefs():
    generator = load_generator()
    curriculum = json.loads(generator.CURRICULUM_PATH.read_text(encoding="utf-8"))
    views = [row["view"] for row in generator.workshop_rows(curriculum)]
    source = generator.PATH_JS.read_text(encoding="utf-8")
    for view in views:
        assert f'"href": "/app/agentsec/{view}"' in source, view
    assert source.count('"href":') == len(views)
