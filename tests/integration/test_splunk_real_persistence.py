"""Opt-in: a REAL Splunk keeps its configuration and indexed events across the intended restart and recreation workflows.

Starts a throwaway Splunk (unique Compose project, no published ports, the Splunk image already present locally, a random per-run admin
password that is never printed) on the same two named volumes the real docker-compose.yml gives the Splunk service. It indexes a marker
event and creates a marker user, then proves both are still there after:
  1. stop, then start            2. up --force-recreate (container replaced)      3. down, then up (container removed)
It only ever removes volumes its own containers mounted. A first Splunk boot can take many minutes, so it is skipped unless
AGENTSEC_REAL_SPLUNK_PERSISTENCE=1:   AGENTSEC_REAL_SPLUNK_PERSISTENCE=1 pytest tests/integration/test_splunk_real_persistence.py
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("SPLUNK_IMAGE", "splunk/splunk:10.2")
PLATFORM = os.environ.get("SPLUNK_PLATFORM", "linux/amd64")
READY_TIMEOUT = int(os.environ.get("AGENTSEC_REAL_SPLUNK_TIMEOUT", "1200"))
COMPOSE_TEXT = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def _ready() -> bool:
    if os.environ.get("AGENTSEC_REAL_SPLUNK_PERSISTENCE") != "1" or shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _ready(), reason="set AGENTSEC_REAL_SPLUNK_PERSISTENCE=1 and have the Splunk image locally (nothing is pulled)")


class RealSplunk:
    def __init__(self, tmp_path: Path):
        lines = re.findall(r"^\s+- (splunk_(?:etc|var):/opt/splunk/(?:etc|var))\s*$", COMPOSE_TEXT, re.M)
        assert len(lines) == 2
        self.name = f"agentsec_realsplunk_{uuid.uuid4().hex[:8]}"
        self.admin_pw = secrets.token_urlsafe(18)          # never printed
        self.user_pw = secrets.token_urlsafe(18) + "9aA!"  # marker user, never printed
        self.marker = f"persist-marker-{uuid.uuid4().hex}"
        self.file = tmp_path / "compose.yml"
        mounts = "\n".join(f"      - {v}" for v in lines)
        self.file.write_text(f"""services:
  splunk:
    image: {IMAGE}
    platform: {PLATFORM}
    stop_grace_period: 180s
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
      - SPLUNK_PASSWORD=${{TEST_SPLUNK_PASSWORD}}
      - TEST_USER_PW=${{TEST_USER_PASSWORD}}
    volumes:
{mounts}
volumes:
  splunk_etc:
  splunk_var:
""", encoding="utf-8")
        self.env = {**os.environ, "TEST_SPLUNK_PASSWORD": self.admin_pw, "TEST_USER_PASSWORD": self.user_pw}
        self.seen: set[str] = set()

    def compose(self, *args: str, timeout: int = 600) -> str:
        r = subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), *args], capture_output=True, text=True, timeout=timeout, env=self.env)
        assert r.returncode == 0, r.stderr.replace(self.admin_pw, "<pw>").replace(self.user_pw, "<pw>")[-1500:]
        if args[0] in ("up", "start"):
            cid = self.compose("ps", "-q", "splunk").strip()
            if cid:
                self.seen |= set(subprocess.run(["docker", "inspect", "-f", "{{range .Mounts}}{{.Name}} {{end}}", cid], capture_output=True, text=True).stdout.split())
        return r.stdout

    def rest(self, path: str, *curl_args: str) -> str:
        """curl against the management port from INSIDE the container; the password is read from the container's own environment."""
        cmd = f'curl -sk -m 60 -u "admin:$SPLUNK_PASSWORD" -w "\\n%{{http_code}}" "https://127.0.0.1:8089{path}" {" ".join(curl_args)}'
        r = subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), "exec", "-T", "splunk", "sh", "-c", cmd],
                           capture_output=True, text=True, timeout=120, env=self.env)
        return r.stdout

    def wait_ready(self) -> None:
        deadline = time.time() + READY_TIMEOUT
        while time.time() < deadline:
            out = self.rest("/services/server/info", "-G", "-d output_mode=json").strip().splitlines()  # -G: a real GET (a bare -d would POST)
            if out and out[-1] == "200":
                return
            time.sleep(15)
        raise AssertionError(f"Splunk not ready within {READY_TIMEOUT}s")

    def create_markers(self) -> None:
        user = self.rest("/services/authentication/users", "-d name=persistuser", '-d password="$TEST_USER_PW"', "-d roles=user", "-d output_mode=json").strip().splitlines()[-1]
        assert user == "201", f"creating the marker user returned HTTP {user}"
        # the simple receiver takes the event as the POST body
        r = subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), "exec", "-T", "splunk", "sh", "-c",
                            f'curl -sk -m 60 -u "admin:$SPLUNK_PASSWORD" "https://127.0.0.1:8089/services/receivers/simple?index=main&source=persist_test" -d "{self.marker}" -w "\\n%{{http_code}}"'],
                           capture_output=True, text=True, timeout=120, env=self.env)
        assert r.stdout.strip().splitlines()[-1] == "200", "indexing the marker event failed"

    def marker_count(self) -> int:
        search = f'search index=main \\"{self.marker}\\" | stats count'
        out = self.rest("/services/search/jobs/export", f'--data-urlencode "search={search}"', "-d output_mode=csv", "-d earliest_time=-1d")
        nums = [ln.strip('"') for ln in out.strip().splitlines() if ln.strip('"').isdigit()]
        return int(nums[0]) if nums else 0

    def user_exists(self) -> bool:
        return self.rest("/services/authentication/users/persistuser", "-G", "-d output_mode=json").strip().splitlines()[-1] == "200"

    def wait_marker(self, expected: int = 1) -> int:
        deadline = time.time() + 180
        n = 0
        while time.time() < deadline:
            n = self.marker_count()
            if n == expected:
                return n
            time.sleep(10)
        return n

    def cleanup(self) -> None:
        subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), "down", "-v", "-t", "120"], capture_output=True, timeout=600, env=self.env)
        for v in sorted(self.seen):  # only volumes this test's own containers mounted
            subprocess.run(["docker", "volume", "rm", v], capture_output=True)


@pytest.fixture()
def splunk(tmp_path):
    s = RealSplunk(tmp_path)
    yield s
    s.cleanup()


def verify(s: RealSplunk, stage: str) -> None:
    s.wait_ready()
    assert s.user_exists(), f"{stage}: Splunk CONFIGURATION (the marker user) did not survive"
    assert s.wait_marker() == 1, f"{stage}: the indexed EVENT did not survive (or was duplicated)"


def test_real_splunk_keeps_config_and_events_through_stop_recreate_and_down_up(splunk):
    splunk.compose("up", "-d")
    splunk.wait_ready()
    splunk.create_markers()
    assert splunk.wait_marker() == 1, "the marker event never became searchable on first start"
    before = splunk.seen.copy()

    splunk.compose("stop", timeout=300)
    splunk.compose("start")
    verify(splunk, "stop/start")

    splunk.compose("up", "-d", "--force-recreate", timeout=900)
    verify(splunk, "up --force-recreate")

    splunk.compose("down", "-t", "180", timeout=900)
    splunk.compose("up", "-d")
    verify(splunk, "down then up (named volumes)")
    assert splunk.seen == before, "no new volumes were created at any point: the same two named volumes were reattached"
