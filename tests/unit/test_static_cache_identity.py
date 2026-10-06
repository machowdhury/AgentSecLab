"""The Splunk app-static cache identity must change when browser assets change.

These tests are a repository contract. They do not prove a deployed Splunk URL.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "splunk_app" / "static_cache_identity.json"
APP_CONF = ROOT / "splunk_app" / "agentsec" / "default" / "app.conf"
STATIC_DIR = ROOT / "splunk_app" / "agentsec" / "appserver" / "static"

# The asset digest Splunk was serving under app build 3 on the deployed lab.
# A later candidate must not reuse build 3 for a different set of assets.
BUILD_3_DEPLOYED_DIGEST = "e50fe6fcbc68a418f38b6ccffb6bfdcf8e980cad92bca6af3113ab9c5ef1001d"


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "static_cache_identity", ROOT / "scripts" / "static_cache_identity.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_lock_matches_current_assets_and_app_build():
    tool = load_tool()
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["app_build"] == tool.app_build()
    assert lock["assets_sha256"] == tool.assets_digest()
    assert tool.check_lock() == 0


def test_app_build_advanced_past_the_deployed_build_3_assets():
    tool = load_tool()
    history = {entry["app_build"]: entry["assets_sha256"] for entry in json.loads(LOCK.read_text(encoding="utf-8"))["history"]}
    assert history[3] == BUILD_3_DEPLOYED_DIGEST
    assert tool.assets_digest() != BUILD_3_DEPLOYED_DIGEST
    assert tool.app_build() > 3


def test_history_never_reuses_a_build_or_a_digest():
    history = json.loads(LOCK.read_text(encoding="utf-8"))["history"]
    builds = [entry["app_build"] for entry in history]
    digests = [entry["assets_sha256"] for entry in history]
    assert builds == sorted(builds)
    assert len(set(builds)) == len(builds)
    assert len(set(digests)) == len(digests)
    assert history[-1]["app_build"] == json.loads(LOCK.read_text(encoding="utf-8"))["app_build"]


def test_changed_asset_under_an_unchanged_build_is_detected(tmp_path: Path, capsys):
    """This is the defect the lock exists to catch. It must fail loudly."""
    tool = load_tool()
    static = tmp_path / "static"
    static.mkdir()
    (static / "agentsec_learner_path.js").write_text("// one\n", encoding="utf-8")
    conf = tmp_path / "app.conf"
    conf.write_text("[install]\nbuild = 9\n", encoding="utf-8")
    lock = tmp_path / "lock.json"
    tool.STATIC_DIR = static
    tool.APP_CONF = conf
    tool.LOCK = lock
    lock.write_text(
        json.dumps({"app_build": 9, "assets_sha256": tool.assets_digest(), "history": []}),
        encoding="utf-8",
    )
    assert tool.check_lock() == 0

    (static / "agentsec_learner_path.js").write_text("// two\n", encoding="utf-8")
    assert tool.check_lock() == 1
    assert "Bump [install] build" in capsys.readouterr().err

    conf.write_text("[install]\nbuild = 10\n", encoding="utf-8")
    tool.write_lock()
    assert tool.check_lock() == 0
    assert json.loads(lock.read_text(encoding="utf-8"))["app_build"] == 10


def test_app_build_is_not_the_product_version():
    text = APP_CONF.read_text(encoding="utf-8")
    assert "version = 1.1.0" in text
    # CONTRACT CHANGE (P0-F): the LAB-MCP-001 flow diagram (a packaged static
    # asset) changed, so the repository contract requires the app build to move
    # 4 -> 5. The product version above is unchanged.
    assert "build = 5" in text


def test_every_browser_served_asset_is_covered_by_the_digest():
    tool = load_tool()
    present = {p.relative_to(STATIC_DIR).as_posix() for p in STATIC_DIR.rglob("*") if p.is_file()}
    assert "agentsec_learner_path.js" in present
    assert "agentsec_open_attack.js" in present
    assert any(name.startswith("flows/") for name in present)
    baseline = tool.assets_digest()
    extra = STATIC_DIR / "flows" / "zz-temporary-probe.svg"
    extra.write_text("<svg/>", encoding="utf-8")
    try:
        assert tool.assets_digest() != baseline
    finally:
        extra.unlink()
    assert tool.assets_digest() == baseline
