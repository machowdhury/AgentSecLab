"""Splunk data must survive pause/resume and container recreation, and no script may silently orphan it.

Background: /opt/splunk/etc and /opt/splunk/var were ANONYMOUS volumes. `compose down` then `up` replaced them with empty ones and
left the old data orphaned. These tests need no Docker daemon (a fake `docker` on PATH records what the scripts would run).
The Docker-backed behavioural proof is in tests/integration/test_volume_persistence_docker.py.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
LAB_UP = (ROOT / "scripts" / "lab-up.sh").read_text(encoding="utf-8")
LAB_DOWN = (ROOT / "scripts" / "lab-down.sh").read_text(encoding="utf-8")
ANON = "3f9ae5b1c2d44e0a8f1c7b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f"  # what a legacy anonymous volume is called

spec = importlib.util.spec_from_file_location("splunk_volumes", ROOT / "scripts" / "splunk_volumes.py")
sv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv)


# ---------- compose contract ----------
def test_compose_names_the_splunk_etc_and_var_volumes():
    assert re.search(r"^\s+- splunk_etc:/opt/splunk/etc\s*$", COMPOSE, re.M)
    assert re.search(r"^\s+- splunk_var:/opt/splunk/var\s*$", COMPOSE, re.M)
    top = COMPOSE.split("\nvolumes:\n", 1)[1].split("\nservices:", 1)[0]
    assert re.search(r"^  splunk_etc:\s*$", top, re.M) and re.search(r"^  splunk_var:\s*$", top, re.M)
    # the staged app is still its own named volume nested under etc
    assert "splunk_app_agentsec:/opt/splunk/etc/apps/agentsec" in COMPOSE


def test_no_splunk_path_is_left_anonymous_in_compose():
    for line in COMPOSE.splitlines():
        s = line.strip()
        assert s not in {"- /opt/splunk/var", "- /opt/splunk/etc"}, "an anonymous Splunk volume would orphan data on down/up"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_rendered_compose_mounts_named_volumes_for_splunk_state():
    out = subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "--env-file", ".env.example", "--profile", "local", "config", "--format", "json"],
                         cwd=ROOT, capture_output=True, text=True, timeout=60, check=True).stdout
    cfg = json.loads(out)
    mounts = {v["target"]: v for v in cfg["services"]["splunk"]["volumes"]}
    for target, name in (("/opt/splunk/etc", "splunk_etc"), ("/opt/splunk/var", "splunk_var")):
        assert mounts[target]["type"] == "volume" and mounts[target]["source"] == name
    assert {"splunk_etc", "splunk_var"} <= set(cfg["volumes"])


# ---------- lab-down.sh: pause by default, never orphan silently ----------
def sandbox(tmp_path: Path, script: str, var_volume: str):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "bin").mkdir()
    shutil.copy(ROOT / "scripts" / script, tmp_path / "scripts" / script)
    (tmp_path / ".env").write_text("", encoding="utf-8")
    verifier = tmp_path / "scripts" / "loan_desk_verifier.sh"
    verifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shim = tmp_path / "bin" / "docker"
    shim.write_text('#!/bin/sh\necho "docker $*" >> "$LOG"\ncase "$1" in inspect) printf "%s" "$FAKE_VAR_VOLUME";; esac\nexit 0\n', encoding="utf-8")
    for p in (verifier, shim):
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "LOG": str(tmp_path / "log"), "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "FAKE_VAR_VOLUME": var_volume}
    (tmp_path / "log").write_text("", encoding="utf-8")
    return env


def sub(tmp_path: Path, name: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    return d


def run_down(tmp_path: Path, var_volume: str, *args: str):
    env = sandbox(tmp_path, "lab-down.sh", var_volume)
    r = subprocess.run(["sh", str(tmp_path / "scripts" / "lab-down.sh"), *args], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    calls = [c for c in (tmp_path / "log").read_text().splitlines() if not c.startswith("docker inspect")]
    verbs = [re.sub(r".*--env-file \S+ ", "", c).replace("docker compose ", "") for c in calls]
    return r.returncode, verbs, r.stdout + r.stderr


def test_lab_down_defaults_to_pause_and_removes_nothing(tmp_path):
    rc, verbs, out = run_down(tmp_path, ANON)
    assert rc == 0 and verbs == ["stop"]
    assert "Nothing is removed" in out and "untouched" in out


def test_lab_down_never_runs_a_bare_down_by_default():
    # the default branch is the first case arm; `down` only appears under explicit modes
    assert "MODE=stop" in LAB_DOWN and "$COMPOSE stop" in LAB_DOWN
    assert LAB_DOWN.count("$COMPOSE down") == 2  # remove and purge only


def test_remove_containers_refuses_on_legacy_anonymous_splunk_volume(tmp_path):
    rc, verbs, out = run_down(tmp_path, ANON, "--remove-containers")
    assert rc == 3 and verbs == []
    assert "ANONYMOUS" in out and "EMPTY" in out and "SPLUNK_VOLUME_MIGRATION" in out


def test_remove_containers_is_allowed_with_named_volumes_and_keeps_them(tmp_path):
    rc, verbs, _ = run_down(tmp_path, "agentseclab_splunk_var", "--remove-containers")
    assert rc == 0 and verbs == ["down"]  # no -v


def test_remove_containers_on_legacy_volume_needs_an_explicit_override(tmp_path):
    rc, verbs, _ = run_down(tmp_path, ANON, "--remove-containers", "--allow-orphan-splunk-data")
    assert rc == 0 and verbs == ["down"]


def test_remove_containers_with_no_splunk_container_is_allowed(tmp_path):
    rc, verbs, _ = run_down(tmp_path, "", "--remove-containers")
    assert rc == 0 and verbs == ["down"]


def test_purge_needs_a_second_explicit_confirmation_flag(tmp_path):
    rc, verbs, out = run_down(sub(tmp_path, "unconfirmed"), "agentseclab_splunk_var", "--purge")
    assert rc == 2 and verbs == [] and "yes-delete-all-lab-data" in out
    rc, verbs, _ = run_down(sub(tmp_path, "confirmed"), "agentseclab_splunk_var", "--purge", "--yes-delete-all-lab-data")
    assert rc == 0 and verbs == ["down -v"]


def test_confirmation_flag_alone_does_not_delete_anything(tmp_path):
    rc, verbs, _ = run_down(tmp_path, "agentseclab_splunk_var", "--yes-delete-all-lab-data")
    assert rc == 0 and verbs == ["stop"]


def test_lab_down_rejects_unknown_arguments(tmp_path):
    rc, verbs, _ = run_down(tmp_path, "x", "--bogus")
    assert rc == 1 and verbs == []


# ---------- lab-up.sh: never recreate Splunk onto empty volumes without saying so ----------
def guard_function() -> str:
    m = re.search(r"^guard_splunk_volumes\(\) \{.*?^\}", LAB_UP, re.S | re.M)
    assert m, "guard_splunk_volumes missing from lab-up.sh"
    return m.group(0)


def run_guard(tmp_path: Path, var_volume: str, fresh: int):
    env = sandbox(tmp_path, "lab-down.sh", var_volume)  # only the docker shim is needed
    script = f"log() {{ printf '%s\\n' \"$*\"; }}\nFRESH_SPLUNK={fresh}\n{guard_function()}\nguard_splunk_volumes\necho REACHED\n"
    r = subprocess.run(["sh", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout


def test_guard_blocks_recreation_over_legacy_anonymous_volumes(tmp_path):
    rc, out = run_guard(tmp_path, ANON, 0)
    assert rc == 1 and "REACHED" not in out
    assert "ANONYMOUS" in out and "--fresh-splunk-data" in out and "start" in out and "splunk_volumes.py inventory" in out


def test_guard_allows_named_volumes_and_first_installs(tmp_path):
    assert run_guard(sub(tmp_path, "named"), "agentseclab_splunk_var", 0) == (0, "REACHED\n")
    assert run_guard(sub(tmp_path, "first-install"), "", 0) == (0, "REACHED\n")


def test_guard_override_warns_and_names_the_orphaned_volume(tmp_path):
    rc, out = run_guard(tmp_path, ANON, 1)
    assert rc == 0 and "REACHED" in out and "orphaned, not deleted" in out and ANON in out


def test_guard_runs_before_every_compose_up_that_can_recreate_splunk():
    assert len(re.findall(r"guard_splunk_volumes\n\s+\$COMPOSE up -d\n", LAB_UP)) == 2
    assert "--no-recreate" in LAB_UP  # the healthy path still never recreates Splunk
    assert "--fresh-splunk-data" in LAB_UP


# ---------- scripts/splunk_volumes.py ----------
COLLECTED = """VOL 0 var 6554112
IDX 0 agentsec_telemetry buckets=60 hot=1 events=2036 earliest=1789182309 latest=1791584246 kb=6144
IDX 0 _internaldb buckets=78 hot=1 events=7785987 earliest=1789182309 latest=1791584246 kb=867328
VOL 1 etc 1126400
ETC 1 version=10.2.7 build=c0bff5b0fac3 users=1 instance_cfg=yes agentsec_app=empty_mountpoint hec=inputs_without_http apps=SplunkForwarder,agentsec,
VOL 2 other 4
"""


def test_collector_output_parses_into_facts():
    v = sv.parse_collector(COLLECTED, ["vA", "vB", "vC"])
    assert v["vA"]["kind"] == "var" and v["vA"]["indexes"]["agentsec_telemetry"]["events"] == 2036
    assert v["vB"]["etc"]["version"] == "10.2.7" and v["vB"]["etc"]["agentsec_app"] == "empty_mountpoint"
    assert v["vC"]["kind"] == "other"


def test_var_and_etc_volumes_are_paired_by_creation_time():
    var = {"v1": "2026-10-02T12:51:36Z", "v2": "2026-10-23T15:12:35Z"}
    etc = {"e1": "2026-10-23T15:12:35Z", "e2": "2026-10-02T12:51:36Z", "e3": "2026-10-09T18:27:32Z"}
    assert sv.pair_by_creation(var, etc) == {"v1": "e2", "v2": "e1"}  # e3 has no partner and is not forced onto one
    assert sv.pair_by_creation({"v": "2026-10-02T12:51:36Z"}, {"e": "2026-10-02T12:59:00Z"}) == {}  # too far apart


def test_migration_plan_names_explicit_volumes_and_never_deletes_or_modifies_sources():
    plan = sv.migration_plan("agentseclab", "SRC_ETC", "SRC_VAR", "agentseclab_splunk_etc", "agentseclab_splunk_var",
                             "docker compose stop splunk")
    assert "PLAN ONLY" in plan and "set -eu" in plan
    for name in ("SRC_ETC", "SRC_VAR", "agentseclab_splunk_etc", "agentseclab_splunk_var"):
        assert name in plan
    assert plan.count("-v SRC_ETC:/src:ro") == 1 and plan.count("-v SRC_VAR:/src:ro") == 1  # sources are read-only
    assert "REFUSING" in plan and "already exists" in plan  # never reuse an existing destination
    assert plan.index("stop splunk") < plan.index("docker volume create") < plan.index("tar cf") < plan.index("splunk_volumes.py verify")
    for forbidden in ("volume rm", "volume prune", "system prune", "rm -rf", " down", "-v SRC", "mv "):
        assert forbidden not in plan.replace("-v SRC_ETC:/src:ro", "").replace("-v SRC_VAR:/src:ro", ""), forbidden


def test_plan_cli_prints_text_and_runs_nothing():
    calls = []
    real = subprocess.run
    try:
        subprocess.run = lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("plan must not run commands"))
        assert sv.main(["plan", "--src-etc", "a", "--src-var", "b", "--dst-etc", "c", "--dst-var", "d"]) == 0
    finally:
        subprocess.run = real
    assert calls == []


def test_inventory_tool_mounts_every_volume_read_only():
    assert ":ro" in Path(ROOT / "scripts" / "splunk_volumes.py").read_text() and 'f"{n}:/v/{i}:ro"' in Path(ROOT / "scripts" / "splunk_volumes.py").read_text()


# ---------- documentation must not teach the unsafe pattern ----------
DOCS = ["README.md", "docs/OPERATIONS.md", "docs/QUICKSTART.md", "docs/REMOTE_ACCESS.md", "docs/INSTRUCTOR_GUIDE.md", "docs/LOAN_DESK_MISSION.md",
        "docs/TROUBLESHOOTING.md", "docs/PILOT_LAUNCH_CHECKLIST.md", "docs/OPERATOR_SETUP_CHECKLIST.md", "docs/demo/AGENTSEC_OCT15_TROUBLESHOOTING.md",
        "docs/ops/EC2_STORAGE_RUNBOOK.md", "docs/ops/EC2_ACCEPTANCE_CHECKLIST.md"]


def test_operations_doc_distinguishes_stop_start_down_up_and_down_v():
    ops = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    for needle in ("stop / start", "down / up", "down -v", "anonymous", "SPLUNK_VOLUME_MIGRATION", "volume prune", "--purge --yes-delete-all-lab-data"):
        assert needle in ops, needle


def test_no_doc_repeats_the_claims_that_were_wrong():
    wrong = ("says indexed Splunk data and named volumes remain", "KEEPS every Docker volume and Splunk index", "never removes volumes or evidence",
             "stops the verifier, removes the containers, KEEPS")
    for rel in DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for phrase in wrong:
            assert phrase not in text, f"{rel}: stale claim: {phrase}"


def test_docs_that_describe_lab_down_say_it_pauses_or_name_the_danger():
    for rel in ("README.md", "docs/QUICKSTART.md", "docs/OPERATIONS.md", "docs/INSTRUCTOR_GUIDE.md", "docs/LOAN_DESK_MISSION.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert re.search(r"pause|stop", text, re.I) and "lab-down.sh" in text, rel
    for rel in ("docs/REMOTE_ACCESS.md", "docs/PILOT_LAUNCH_CHECKLIST.md"):
        assert "SPLUNK_VOLUME_MIGRATION" in (ROOT / rel).read_text(encoding="utf-8") or "named-volume change" in (ROOT / rel).read_text(encoding="utf-8")


def test_the_migration_doc_has_explicit_volumes_backup_verification_and_rollback():
    doc = (ROOT / "docs" / "ops" / "SPLUNK_VOLUME_MIGRATION.md").read_text(encoding="utf-8")
    for needle in ("Back up both sources", "gzip -t", "shasum -a 256", "splunk_volumes.py plan", "VERIFIED", "Rollback", "docker-compose.rollback.yml",
                   "No two datasets are to be combined", "enableSSL", "start clean", "never modified", "docker volume prune"):
        assert needle in doc, needle
    assert "DESIGN AND PROCEDURE ONLY" in doc
