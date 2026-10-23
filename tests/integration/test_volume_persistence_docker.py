"""Behavioural proof, with a real Docker daemon, that state in the Splunk volume layout survives the intended workflows.

A throwaway Compose project (unique name, no ports, the locally present busybox image, nothing pulled) mounts the SAME two volume lines the
real docker-compose.yml gives the Splunk service. Each scenario writes a marker into /opt/splunk/etc and /opt/splunk/var and checks it
after the workflow. A control project uses the old ANONYMOUS layout to show the failure these tests guard against. The tests only ever
remove volumes of their own unique project. Skipped when Docker or busybox is unavailable.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "busybox:1.36"
COMPOSE_TEXT = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=True, timeout=30)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="needs a Docker daemon and a local busybox:1.36 (nothing is pulled)")


def real_splunk_volume_lines() -> list[str]:
    """The exact etc and var mount lines of the real Splunk service (so this test cannot drift from the product)."""
    lines = re.findall(r"^\s+- (splunk_(?:etc|var):/opt/splunk/(?:etc|var))\s*$", COMPOSE_TEXT, re.M)
    assert sorted(lines) == ["splunk_etc:/opt/splunk/etc", "splunk_var:/opt/splunk/var"]
    return lines


class Project:
    def __init__(self, tmp_path: Path, volumes: list[str], top_level: list[str]):
        self.name = f"agentsec_persist_{uuid.uuid4().hex[:8]}"
        self.file = tmp_path / "compose.yml"
        mounts = "\n".join(f"      - {v}" for v in volumes)
        tops = ("volumes:\n" + "\n".join(f"  {t}:" for t in top_level) + "\n") if top_level else ""
        self.file.write_text(f"services:\n  s:\n    image: {IMAGE}\n    command: [\"sleep\", \"600\"]\n    volumes:\n{mounts}\n{tops}", encoding="utf-8")
        self.orphans: list[str] = []
        self.seen: set[str] = set()  # every volume this project's containers ever mounted

    def compose(self, *args: str) -> str:
        r = subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), *args], capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr
        if args[0] in ("up", "start"):
            self.seen |= set(self.mount_names())
        return r.stdout

    def sh(self, script: str) -> str:
        return self.compose("exec", "-T", "s", "sh", "-c", script).strip()

    def container_id(self) -> str:
        return self.compose("ps", "-q", "s").strip()

    def volume_names(self) -> list[str]:
        out = subprocess.run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={self.name}"], capture_output=True, text=True).stdout
        return sorted(out.split())

    def mount_names(self) -> list[str]:
        out = subprocess.run(["docker", "inspect", "-f", '{{range .Mounts}}{{.Name}} {{end}}', self.container_id()], capture_output=True, text=True).stdout
        return sorted(out.split())

    def cleanup(self) -> None:
        subprocess.run(["docker", "compose", "-p", self.name, "-f", str(self.file), "down", "-v"], capture_output=True, timeout=120)
        for v in sorted(set(self.orphans) | self.seen):  # only volumes this test's own containers mounted, never anything else
            subprocess.run(["docker", "volume", "rm", v], capture_output=True)


@pytest.fixture()
def named(tmp_path):
    p = Project(tmp_path, real_splunk_volume_lines(), ["splunk_etc", "splunk_var"])
    yield p
    p.cleanup()


@pytest.fixture()
def anonymous(tmp_path):
    p = Project(tmp_path, ["/opt/splunk/etc", "/opt/splunk/var"], [])
    yield p
    p.cleanup()


def write_markers(p: Project) -> None:
    p.sh("echo CONFIG > /opt/splunk/etc/marker && echo EVENTS > /opt/splunk/var/marker")


def markers(p: Project) -> str:
    return p.sh("cat /opt/splunk/etc/marker /opt/splunk/var/marker 2>&1 | tr '\\n' ' '")


def test_state_survives_stop_then_start(named):
    named.compose("up", "-d")
    write_markers(named)
    cid = named.container_id()
    named.compose("stop")
    named.compose("start")
    assert named.container_id() == cid and markers(named) == "CONFIG EVENTS"


def test_state_survives_recreating_the_container_in_place(named):
    named.compose("up", "-d")
    write_markers(named)
    cid = named.container_id()
    named.compose("up", "-d", "--force-recreate")
    assert named.container_id() != cid, "the container really was recreated"
    assert markers(named) == "CONFIG EVENTS"


def test_state_survives_down_then_up_with_named_volumes(named):
    named.compose("up", "-d")
    write_markers(named)
    before = named.mount_names()
    named.compose("down")
    assert named.volume_names() == sorted(f"{named.name}_{v}" for v in ("splunk_etc", "splunk_var")), "named volumes outlive down"
    named.compose("up", "-d")
    assert named.mount_names() == before and markers(named) == "CONFIG EVENTS"


def test_down_v_is_the_only_thing_that_deletes_the_named_volumes(named):
    named.compose("up", "-d")
    write_markers(named)
    named.compose("down", "-v")
    assert named.volume_names() == []


def test_control_anonymous_volumes_are_orphaned_by_down_then_up(anonymous):
    """The original defect, reproduced: this is what the named volumes prevent."""
    anonymous.compose("up", "-d")
    write_markers(anonymous)
    old = anonymous.mount_names()
    anonymous.orphans += old
    anonymous.compose("down")
    anonymous.compose("up", "-d")
    assert anonymous.mount_names() != old, "down then up attached new volumes"
    assert "No such file" in markers(anonymous), "and the data is not visible"
    assert all(subprocess.run(["docker", "volume", "inspect", v], capture_output=True).returncode == 0 for v in old), "old data still on disk, orphaned"


def test_control_anonymous_volumes_do_survive_recreate_in_place_and_stop_start(anonymous):
    anonymous.compose("up", "-d")
    write_markers(anonymous)
    anonymous.compose("stop")
    anonymous.compose("start")
    anonymous.compose("up", "-d", "--force-recreate")
    assert markers(anonymous) == "CONFIG EVENTS"
