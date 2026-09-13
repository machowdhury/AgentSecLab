"""Contract tests for LOCAL Splunk app staging.

These tests do not start Docker and do not prove a live Splunk boot.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_INIT = ROOT / "scripts" / "splunk_app_init.sh"
APP_SRC = ROOT / "splunk_app" / "agentsec"


def test_splunk_app_init_copies_to_writable_dest(tmp_path: Path):
    dest = tmp_path / "dest"
    dest.mkdir()
    stale = dest / "stale.txt"
    stale.write_text("remove me", encoding="utf-8")
    env = os.environ.copy()
    env["SPLUNK_APP_SRC"] = str(APP_SRC)
    env["SPLUNK_APP_DEST"] = str(dest)
    proc = subprocess.run(["/bin/sh", str(APP_INIT)], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert not stale.exists()
    assert (dest / "default" / "app.conf").is_file()
    assert (dest / "default" / "indexes.conf").is_file()
    assert (dest / "default" / "data" / "ui" / "views" / "ws_lab_pi_001.xml").is_file()
    assert (dest / "default" / "data" / "ui" / "views" / "ws_lab_mcp_001.xml").is_file()
    assert (dest / "default" / "data" / "ui" / "views" / "ws_lab_mcp_003.xml").is_file()
    assert (dest / "default" / "data" / "ui" / "views" / "ws_lab_mcp_004.xml").is_file()
    assert "Staged AgentSec app" in proc.stdout


def test_splunk_app_init_fails_when_view_missing(tmp_path: Path):
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    dest.mkdir()
    (src / "default").mkdir(parents=True)
    (src / "default" / "app.conf").write_text("[install]\n", encoding="utf-8")
    (src / "default" / "indexes.conf").write_text("[agentsec_telemetry]\n", encoding="utf-8")
    env = os.environ.copy()
    env["SPLUNK_APP_SRC"] = str(src)
    env["SPLUNK_APP_DEST"] = str(dest)
    proc = subprocess.run(["/bin/sh", str(APP_INIT)], env=env, capture_output=True, text=True)
    assert proc.returncode != 0
    assert "ws_lab_pi_001.xml missing" in proc.stdout + proc.stderr
