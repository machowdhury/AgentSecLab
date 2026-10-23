"""Regression: the preflight disk check must measure real disk, not a RAM-backed /tmp (it once read 15.5 GB free on a 95%-full host)."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("preflight_disk", ROOT / "scripts" / "preflight_disk.py")
pd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pd)

GIB = 1024 * 1024
MOUNTS = "\n".join([
    "/dev/root / ext4 rw,relatime 0 0",
    "tmpfs /mnt/ram tmpfs rw,nosuid,nodev 0 0",
    "tmpfs /dev/shm tmpfs rw 0 0",
    "/dev/nvme1n1 /srv/data ext4 rw 0 0",
])


def fake(table):
    return lambda path: next(v for k, v in table.items() if path.startswith(k))


def verdict(rows):
    return [r.split(None, 1)[0] for r in rows if r.split(None, 1)[0] in {"PASS", "WARN", "FAIL"}]


def test_longest_mount_wins_and_tmpfs_is_detected():
    assert pd.mount_fstype("/mnt/ram/agentsec_pf", MOUNTS) == "tmpfs"
    assert pd.mount_fstype("/mnt/ram", MOUNTS) == "tmpfs"
    assert pd.mount_fstype("/home/ubuntu/AgentSecLab", MOUNTS) == "ext4"
    assert pd.mount_fstype("/srv/data/x", MOUNTS) == "ext4"
    assert pd.mount_fstype("/mnt/ramfoo", MOUNTS) == "ext4"  # prefix of a name is not a path prefix
    assert pd.mount_fstype("/x", "") == ""


def test_ramdisk_root_with_full_real_disk_is_not_a_pass(monkeypatch):
    """The original defect: ROOT on a 16 GB tmpfs, Docker's real disk at 5.2 GB."""
    monkeypatch.setattr(pd.os.path, "isdir", lambda p: True)
    rows = pd.evaluate("/mnt/ram/agentsec_pf", "/var/lib/docker", MOUNTS, avail=fake({"/mnt/ram": 16 * GIB, "/var/lib/docker": int(5.2 * GIB)}))
    assert verdict(rows) == ["WARN"]
    text = "\n".join(rows)
    assert "RAM-backed tmpfs" in text and "5.2 GB" in text and "16.0 GB" not in text.replace("RAM-backed", "")
    assert "Splunk's default minimum free space is 5000 MB" in text


def test_only_ramdisk_known_means_not_measured_never_pass(monkeypatch):
    monkeypatch.setattr(pd.os.path, "isdir", lambda p: False)
    rows = pd.evaluate("/mnt/ram/x", "", MOUNTS, avail=fake({"/mnt/ram": 16 * GIB}))
    assert verdict(rows) == ["WARN"] and "could NOT be measured" in "\n".join(rows)


def test_tightest_real_filesystem_decides(monkeypatch):
    monkeypatch.setattr(pd.os.path, "isdir", lambda p: True)
    table = {"/srv/data": 100 * GIB, "/var/lib/docker": 3 * GIB}
    assert verdict(pd.evaluate("/srv/data/lab", "/var/lib/docker", MOUNTS, avail=fake(table))) == ["WARN"]
    table["/var/lib/docker"] = 1 * GIB
    assert verdict(pd.evaluate("/srv/data/lab", "/var/lib/docker", MOUNTS, avail=fake(table))) == ["FAIL"]
    table["/var/lib/docker"] = 50 * GIB
    assert verdict(pd.evaluate("/srv/data/lab", "/var/lib/docker", MOUNTS, avail=fake(table))) == ["PASS"]


def test_docker_root_not_on_host_is_reported_not_measured(monkeypatch):
    monkeypatch.setattr(pd.os.path, "isdir", lambda p: p == "/srv/data/lab")
    rows = pd.evaluate("/srv/data/lab", "/var/lib/docker", MOUNTS, avail=fake({"/srv/data": 100 * GIB}))
    assert any("NOT MEASURED" in r and "Docker" in r for r in rows) and verdict(rows) == ["PASS"]


def test_cli_runs_on_a_real_path_and_the_script_calls_it():
    out = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "preflight_disk.py"), "--root", str(ROOT)],
                         capture_output=True, text=True, timeout=30, check=True).stdout
    assert "CURRENTLY AVAILABLE disk" in out and any(v in out for v in ("PASS ", "WARN ", "FAIL "))
    sh = (ROOT / "scripts" / "lab-preflight.sh").read_text(encoding="utf-8")
    assert "preflight_disk.py" in sh and "DockerRootDir" in sh
    assert 'df -Pk "$ROOT"' not in sh  # the single-path df that read a tmpfs is gone
