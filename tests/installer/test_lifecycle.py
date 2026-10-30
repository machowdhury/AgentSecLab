"""agentsec up / down / status / logs and the Compose-service-discovery shell helper. Fakes only: no Docker, no network, nothing started."""
import json, os, stat, subprocess, textwrap
from pathlib import Path
import pytest
from agentsec.installer import core, lifecycle, render
from agentsec.installer.cli import main
from agentsec.installer.config import Locks
from tests.installer.fakes import FakeEnv, FakeRunner, LEGACY_LAB

LOCKS = Locks.load()
REPO = Path(__file__).resolve().parents[2]
INSTALL = ["install", "--non-interactive", "--accept-warnings", "all"]


def cli(root, args, *, env=None, runner=None, config=None):
    out = []
    if config is not None:
        (root / "agentsec.install.json").write_text(json.dumps(config))
    rc = main(["--root", str(root), *args], env=env or FakeEnv(), runner=runner or FakeRunner(), ask=lambda p: "", out=out.append, locks=LOCKS, isatty=False)
    return rc, out


def installed(root, config=None):
    rc, out = cli(root, INSTALL, config=config or {"gateway": {"bind": "127.0.0.1"}})
    assert rc == 0, out
    return root


def state_json(root):
    return json.loads((root / ".agentsec/install.json").read_text())


def snapshot(root):
    return {g: (root / g).read_bytes() for g in core.GENERATED}


def verbs(runner):
    return {a for c in runner.commands for a in c}


# ---- up ----------------------------------------------------------------------------------------------------------------------------------------
def test_up_validates_then_runs_project_scoped_idempotent_commands(tmp_path):
    installed(tmp_path)
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == 0, out
    compose = [c for c in r.commands if c[:2] == ["docker", "compose"]]
    up = next(c for c in compose if "--no-recreate" in c)
    assert compose[0][-2:] == ["config", "-q"] and up[-len(state_json(tmp_path)["resolved"]["services"]) - 3:][:3] == ["up", "-d", "--no-recreate"]
    assert all(c[2:4] == ["--project-name", "agentsec"] for c in compose)
    assert all({"COMPOSE_PROJECT_NAME", "COMPOSE_FILE", "COMPOSE_PROFILES"} <= set(e) for c, e in zip(r.commands, r.envs) if c[:2] == ["docker", "compose"])
    assert ["sh", "scripts/hec-certs.sh"] in [c[:2] for c in r.commands]
    assert not (lifecycle.FORBIDDEN & verbs(r))


def test_up_twice_is_the_same_and_changes_no_file(tmp_path):
    installed(tmp_path)
    before = snapshot(tmp_path)
    r1, r2 = FakeRunner(), FakeRunner()
    assert cli(tmp_path, ["up"], runner=r1)[0] == 0 and cli(tmp_path, ["up"], runner=r2)[0] == 0
    assert r1.commands == r2.commands and snapshot(tmp_path) == before


def test_up_without_an_installation_explains_what_to_do_and_runs_nothing(tmp_path):
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_USAGE and any("NOT_INSTALLED" in l and "./agentsec install" in l for l in out) and r.commands == []


@pytest.mark.parametrize("damage,code", [
    (lambda root: (root / ".env").write_text((root / ".env").read_text() + "EXTRA=1\n"), "GENERATED_FILE_MODIFIED"),
    (lambda root: (root / ".agentsec/compose.override.yml").unlink(), "GENERATED_FILE_MISSING"),
    (lambda root: os.chmod(root / ".env", 0o644), "PERMISSIONS_TOO_OPEN"),
    (lambda root: os.chmod(root / ".agentsec", 0o755), "PERMISSIONS_TOO_OPEN"),
])
def test_up_refuses_damaged_generated_files_before_starting_anything(tmp_path, damage, code):
    installed(tmp_path)
    damage(tmp_path)
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_CHECKS and any(code in l for l in out) and r.commands == []


def test_up_refuses_a_foreign_env_file(tmp_path):
    installed(tmp_path)
    (tmp_path / ".env").write_text("SPLUNK_PASSWORD=x\n")
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_USAGE and any("ENV_NOT_GENERATED" in l for l in out) and r.commands == []


def test_up_refuses_corrupt_or_unknown_state(tmp_path):
    installed(tmp_path)
    for text in ("{not json", json.dumps({"schema": 2}), json.dumps({"schema": 1, "config": {"bogus": 1}, "resolved": {}, "files": {}})):
        (tmp_path / ".agentsec/install.json").write_text(text)
        r = FakeRunner()
        rc, out = cli(tmp_path, ["up"], runner=r)
        assert rc == core.EXIT_USAGE and any("STATE_UNREADABLE" in l for l in out) and r.commands == []


def test_up_refuses_when_the_image_pin_changed_since_install(tmp_path):
    installed(tmp_path)
    s = state_json(tmp_path)
    s["resolved"]["images"]["splunk"] = "splunk/splunk@sha256:" + "0" * 64
    (tmp_path / ".agentsec/install.json").write_text(json.dumps(s))
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_CHECKS and any("IMAGE_PIN_CHANGED" in l for l in out) and r.commands == []


def test_up_enforces_require_digests_for_unpinned_images(tmp_path):
    installed(tmp_path)
    s = state_json(tmp_path)
    s["config"]["require_digests"] = True
    (tmp_path / ".agentsec/install.json").write_text(json.dumps(s))
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_CHECKS and any("FLOATING_TAG" in l or "IMAGE_NOT_PINNED" in l for l in out) and r.commands == []


def test_up_fails_closed_on_remote_ollama_even_if_the_state_was_edited(tmp_path):
    installed(tmp_path)
    s = state_json(tmp_path)
    s["config"]["ollama"] = {"mode": "remote", "url": "https://ollama.example.org", "ca_file": ""}
    (tmp_path / ".agentsec/install.json").write_text(json.dumps(s))
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_CHECKS and any("OLLAMA_REMOTE_UNSUPPORTED" in l for l in out) and r.commands == []


def test_install_itself_refuses_remote_ollama(tmp_path):
    rc, out = cli(tmp_path, INSTALL, config={"gateway": {"bind": "127.0.0.1"}, "ollama": {"mode": "remote", "url": "https://ollama.example.org"}})
    assert rc == core.EXIT_CHECKS and any("OLLAMA_REMOTE_UNSUPPORTED" in l for l in out) and not (tmp_path / ".env").exists()


def test_up_needs_docker(tmp_path):
    installed(tmp_path)
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], env=FakeEnv(docker=False), runner=r)
    assert rc == core.EXIT_CHECKS and r.commands == []


def test_up_never_touches_an_existing_labs_containers_under_the_old_names(tmp_path):
    installed(tmp_path, {"project": "agentseclab", "gateway": {"bind": "127.0.0.1"}})
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], env=FakeEnv(**LEGACY_LAB), runner=r)
    assert rc == core.EXIT_CHECKS and any("WOULD_RECREATE_EXISTING_LAB" in l for l in out) and r.commands == []


def test_up_is_not_confused_by_another_projects_ports(tmp_path):
    installed(tmp_path)
    other = [{"name": "other-gateway", "project": "other", "image": "x", "ports": [443]}]
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], env=FakeEnv(containers=other, listeners={443: "docker"}), runner=r)
    assert rc == core.EXIT_CHECKS and r.commands == []        # the port belongs to someone else: refuse, never take it over


@pytest.mark.parametrize("fail_on", [1, 2, 3, 4, 5])
def test_a_failed_up_removes_nothing_and_a_retry_succeeds(tmp_path, fail_on):
    installed(tmp_path)
    before = snapshot(tmp_path)
    r = FakeRunner(fail_on=fail_on)
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_APPLY and any("Nothing was removed" in l for l in out)
    assert len(r.commands) == fail_on and not (lifecycle.FORBIDDEN & verbs(r)) and snapshot(tmp_path) == before
    r2 = FakeRunner()
    assert cli(tmp_path, ["up"], runner=r2)[0] == 0


def test_config_rollback_after_a_failed_up_restores_the_previous_generated_files_without_docker(tmp_path):
    installed(tmp_path, {"gateway": {"bind": "127.0.0.1", "port": 443}})
    first = snapshot(tmp_path)
    rc, _ = cli(tmp_path, INSTALL + ["--set", "gateway.port=8000"])
    assert rc == 0 and snapshot(tmp_path) != first
    assert cli(tmp_path, ["up"], runner=FakeRunner(fail_on=3))[0] == core.EXIT_APPLY
    r = FakeRunner()
    rc, _ = cli(tmp_path, ["rollback"], runner=r)
    assert rc == 0 and snapshot(tmp_path) == first and r.commands == []
    assert cli(tmp_path, ["up"], runner=FakeRunner())[0] == 0       # the restored state is consistent (hashes match)


# ---- down --------------------------------------------------------------------------------------------------------------------------------------
def test_down_removes_containers_only_and_never_a_volume(tmp_path):
    installed(tmp_path)
    r = FakeRunner()
    rc, out = cli(tmp_path, ["down"], runner=r)
    assert rc == 0 and len(r.commands) == 1
    argv = r.commands[0]
    assert argv[:4] == ["docker", "compose", "--project-name", "agentsec"] and argv[-3:-1] == ["down", "--timeout"]
    assert not (lifecycle.FORBIDDEN & set(argv)) and any("Volumes" in l and "kept" in l for l in out)


def test_down_is_idempotent_and_survives_edited_generated_files(tmp_path):
    installed(tmp_path)
    (tmp_path / ".env").write_text((tmp_path / ".env").read_text() + "EDITED=1\n")          # `up` would refuse; stopping must always be possible
    for _ in range(2):
        assert cli(tmp_path, ["down"], runner=FakeRunner())[0] == 0


def test_down_failure_is_reported_and_changes_nothing(tmp_path):
    installed(tmp_path)
    before = snapshot(tmp_path)
    rc, out = cli(tmp_path, ["down"], runner=FakeRunner(fail_on=1))
    assert rc == core.EXIT_APPLY and any("safe to run" in l for l in out) and snapshot(tmp_path) == before


def test_down_without_docker_or_installation_has_actionable_errors(tmp_path):
    assert cli(tmp_path, ["down"])[0] == core.EXIT_USAGE
    installed(tmp_path)
    r = FakeRunner()
    rc, out = cli(tmp_path, ["down"], env=FakeEnv(docker=False), runner=r)
    assert rc == core.EXIT_CHECKS and any("Docker" in l for l in out) and r.commands == []


def test_down_only_names_its_own_project(tmp_path):
    installed(tmp_path, {"project": "labone", "gateway": {"bind": "127.0.0.1"}})
    r = FakeRunner()
    cli(tmp_path, ["down"], runner=r)
    assert r.commands[0][2:4] == ["--project-name", "labone"] and r.envs[0]["COMPOSE_PROJECT_NAME"] == "labone"


def test_the_safety_guard_refuses_destructive_arguments():
    for bad in ("-v", "--volumes", "--rmi", "--remove-orphans", "prune", "rm", "volume"):
        with pytest.raises(AssertionError):
            lifecycle.safe({"argv": ["docker", "compose", "down", bad], "env": {}})


def test_no_lifecycle_source_path_can_build_a_destructive_command():
    src = (REPO / "src/agentsec/installer/lifecycle.py").read_text()
    body = src.split("def safe", 1)[1]
    assert "check_ready" in body and '"--volumes"' not in src.split("FORBIDDEN = ", 1)[1].split("\n", 1)[1]
    for c in ("down", "up", "status", "logs"):
        assert f"def {c}(" in src


# ---- status ------------------------------------------------------------------------------------------------------------------------------------
def ps(root, overrides=None, drop=()):
    rows = []
    for s in state_json(root)["resolved"]["services"]:
        if s in drop:
            continue
        once = s in ("splunk_app_init", "splunk_hec_init")
        row = {"Service": s, "State": "exited" if once else "running", "Health": "" if once else "healthy", "ExitCode": 0}
        row.update((overrides or {}).get(s, {}))
        rows.append(row)
    return "\n".join(json.dumps(r) for r in rows)


def test_status_is_read_only_and_ok_when_everything_is_up(tmp_path):
    installed(tmp_path)
    r = FakeRunner(outputs={"ps": ps(tmp_path)})
    rc, out = cli(tmp_path, ["status"], runner=r)
    assert rc == 0 and len(r.commands) == 1 and "ps" in r.commands[0] and not (lifecycle.FORBIDDEN & set(r.commands[0]))


@pytest.mark.parametrize("kw", [dict(drop=("splunk",)), dict(overrides={"acmebank": {"State": "restarting"}}), dict(overrides={"splunk": {"Health": "starting"}}),
                                dict(overrides={"splunk_hec_init": {"ExitCode": 1}})])
def test_status_reports_not_ready_with_exit_5(tmp_path, kw):
    installed(tmp_path)
    rc, out = cli(tmp_path, ["status"], runner=FakeRunner(outputs={"ps": ps(tmp_path, **kw)}))
    assert rc == lifecycle.EXIT_NOT_READY and any("FAIL" in l for l in out)


def test_status_with_no_containers_says_to_run_up(tmp_path):
    installed(tmp_path)
    rc, out = cli(tmp_path, ["status"], runner=FakeRunner(outputs={"ps": ""}))
    assert rc == lifecycle.EXIT_NOT_READY and any("./agentsec up" in l for l in out)


def test_status_accepts_the_single_array_format_of_older_compose(tmp_path):
    installed(tmp_path)
    arr = "[" + ",".join(ps(tmp_path).splitlines()) + "]"
    assert cli(tmp_path, ["status"], runner=FakeRunner(outputs={"ps": arr}))[0] == 0


# ---- logs --------------------------------------------------------------------------------------------------------------------------------------
def test_logs_scopes_to_a_known_service_and_redacts_secrets(tmp_path):
    installed(tmp_path)
    pw = render.parse_env((tmp_path / ".env").read_text())["SPLUNK_PASSWORD"]
    r = FakeRunner(outputs={"logs": f"acmebank | login with {pw}\n"})
    rc, out = cli(tmp_path, ["logs", "acmebank", "--tail", "5"], runner=r)
    assert rc == 0 and r.commands[0][-5:] == ["logs", "--no-color", "--tail", "5", "acmebank"]
    assert pw not in "\n".join(out) and "***" in "\n".join(out)


def test_logs_rejects_unknown_services_and_bad_tails_without_running_anything(tmp_path):
    installed(tmp_path)
    for args in (["logs", "nope; rm -rf /"], ["logs", "--tail", "0"], ["logs", "--tail", "99999999"]):
        r = FakeRunner()
        rc, _ = cli(tmp_path, args, runner=r)
        assert rc == core.EXIT_USAGE and r.commands == []


def test_logs_follow_streams(tmp_path):
    installed(tmp_path)
    r = FakeRunner()
    assert cli(tmp_path, ["logs", "--follow"], runner=r)[0] == 0 and "--follow" in r.commands[0]


# ---- shell helper: service discovery without fixed container names -----------------------------------------------------------------------------
STUB = textwrap.dedent("""\
    #!/bin/sh
    printf '%s\\n' "$*" >> "$STUB_LOG"
    case "$*" in *label=com.docker.compose.service=splunk*) echo abc123 ;; esac
    """)


def run_helper(tmp_path, snippet, env_file=""):
    root = tmp_path / "My Lab_Dir"
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "scripts/lab-compose.sh").write_text((REPO / "scripts/lab-compose.sh").read_text())
    if env_file:
        (root / ".env").write_text(env_file)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "docker").write_text(STUB)
    (bindir / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    p = subprocess.run(["sh", "-c", f'ROOT="{root}"; . "$ROOT/scripts/lab-compose.sh"; {snippet}'], capture_output=True, text=True,
                       env={"PATH": f"{bindir}:/usr/bin:/bin", "STUB_LOG": str(log)})
    return p.stdout, (log.read_text() if log.exists() else "")


def test_helper_finds_containers_by_project_and_service_label_from_the_env_file(tmp_path):
    out, log = run_helper(tmp_path, "svc_id splunk", "COMPOSE_PROJECT_NAME=labone\n")
    assert out.strip() == "abc123"
    assert "label=com.docker.compose.project=labone" in log and "label=com.docker.compose.service=splunk" in log and "agentsec_splunk" not in log


def test_helper_defaults_to_composes_directory_derived_project_name(tmp_path):
    out, log = run_helper(tmp_path, 'printf "%s" "$LAB_PROJECT"')
    assert out == "mylab_dir"


def test_helper_uses_the_generated_compose_configuration_only_when_installed(tmp_path):
    out, _ = run_helper(tmp_path, 'printf "%s" "$LAB_COMPOSE"')
    assert "docker-compose.local.yml" in out
    root = tmp_path / "My Lab_Dir"
    (root / ".agentsec").mkdir()
    (root / ".agentsec/install.json").write_text("{}")
    out2, _ = run_helper(tmp_path, 'printf "%s" "$LAB_COMPOSE"')
    assert out2 == "docker compose --env-file .env"


MIGRATED = ["lab-up.sh", "lab-ready.sh", "lab-down.sh", "lab-preflight.sh", "gateway-ready.sh"]


@pytest.mark.parametrize("name", MIGRATED)
def test_migrated_scripts_assume_no_fixed_container_names_and_parse(name):
    path = REPO / "scripts" / name
    text = path.read_text()
    import re
    bad = [l for l in text.splitlines() if re.search(r"docker (exec|inspect|restart|stop|rm|logs)\b[^|;]*\bagentsec_(splunk|ollama|acmebank|attack_service|otel_collector|gateway|splunk_\w+)\b", l)]
    assert not bad, bad
    assert "lab-compose.sh" in text
    assert subprocess.run(["sh", "-n", str(path)]).returncode == 0


# ---- install.json is editable: nothing in it may steer a command --------------------------------------------------------------------------------
def edit_state(root, fn):
    s = state_json(root)
    fn(s)
    (root / ".agentsec/install.json").write_text(json.dumps(s))


def test_a_tampered_service_list_never_reaches_the_command_line(tmp_path):
    installed(tmp_path)
    edit_state(tmp_path, lambda s: s["resolved"].update(services=["-V", "--force-recreate", "acmebank"]))
    r = FakeRunner()
    assert cli(tmp_path, ["up"], runner=r)[0] == 0
    up = next(c for c in r.commands if "--no-recreate" in c)
    assert not ({"-V", "--force-recreate"} & verbs(r)) and "acmebank" in up and "-V" not in up[up.index("--no-recreate"):]


@pytest.mark.parametrize("project", ["otherlab", "-v", "Bad Name", ""])
def test_a_tampered_project_is_refused_by_every_command(tmp_path, project):
    installed(tmp_path)
    edit_state(tmp_path, lambda s: s["config"].update(project=project))
    for cmd in (["up"], ["down"], ["status"], ["logs"]):
        r = FakeRunner()
        rc, out = cli(tmp_path, cmd, runner=r)
        assert rc == core.EXIT_USAGE and r.commands == [] and any("STATE_PROJECT_MISMATCH" in l for l in out)


def test_up_refuses_generated_files_whose_hashes_were_rewritten_to_match(tmp_path):
    import hashlib
    installed(tmp_path)
    ov = tmp_path / ".agentsec/compose.override.yml"
    ov.write_text(ov.read_text() + "  acmebank:\n    privileged: true\n")
    edit_state(tmp_path, lambda s: s["files"].update({".agentsec/compose.override.yml": hashlib.sha256(ov.read_bytes()).hexdigest()}))
    r = FakeRunner()
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == core.EXIT_CHECKS and any("GENERATED_FILE_MODIFIED" in l for l in out) and r.commands == []


def test_up_refuses_an_env_file_edited_to_a_public_bind_even_with_matching_hash(tmp_path):
    import hashlib
    installed(tmp_path)
    env = tmp_path / ".env"
    env.write_text(env.read_text().replace("AGENTSEC_BIND_ADDRESS=127.0.0.1", "AGENTSEC_BIND_ADDRESS=0.0.0.0"))
    edit_state(tmp_path, lambda s: s["files"].update({".env": hashlib.sha256(env.read_bytes()).hexdigest()}))
    r = FakeRunner()
    assert cli(tmp_path, ["up"], runner=r)[0] == core.EXIT_CHECKS and r.commands == []


def test_the_generated_env_is_the_process_environment_so_shell_variables_cannot_override_it(tmp_path):
    installed(tmp_path)
    r = FakeRunner()
    cli(tmp_path, ["up"], runner=r)
    assert r.envs[0]["AGENTSEC_BIND_ADDRESS"] == "127.0.0.1"


def test_a_symlinked_state_directory_is_refused(tmp_path):
    installed(tmp_path)
    (tmp_path / "elsewhere").mkdir()
    os.rename(tmp_path / ".agentsec", tmp_path / "real")
    os.symlink(tmp_path / "real", tmp_path / ".agentsec")
    assert cli(tmp_path, ["up"], runner=FakeRunner())[0] == core.EXIT_USAGE
    assert cli(tmp_path, INSTALL)[0] == core.EXIT_REFUSED


def test_every_guard_flag_is_in_the_forbidden_set():
    assert {"-V", "--force-recreate", "--renew-anon-volumes", "--build", "-v", "--volumes"} <= lifecycle.FORBIDDEN


# ---- shell helper additions ---------------------------------------------------------------------------------------------------------------------
def test_helper_reads_quoted_and_crlf_env_values(tmp_path):
    out, _ = run_helper(tmp_path, "printf '%s' \"$LAB_PROJECT\"", 'COMPOSE_PROJECT_NAME="foo"\r\n')
    assert out == "foo"


def test_lab_expects_follows_the_installer_state(tmp_path):
    out, _ = run_helper(tmp_path, "lab_expects ollama && echo yes")      # legacy lab: everything is expected
    assert out.strip() == "yes"
    root = tmp_path / "My Lab_Dir"
    (root / ".agentsec").mkdir()
    (root / ".agentsec/install.json").write_text(json.dumps({"resolved": {"services": ["acmebank", "splunk"]}}, indent=2))
    assert run_helper(tmp_path, "lab_expects splunk && echo yes")[0].strip() == "yes"
    assert run_helper(tmp_path, "lab_expects ollama && echo yes")[0].strip() == ""


def test_lab_up_hands_installer_labs_to_agentsec_up():
    text = (REPO / "scripts/lab-up.sh").read_text()
    assert "./agentsec up" in text and '"$REFRESH_APP" -ne 1' in text


def test_a_restart_after_down_is_not_a_splunk_upgrade(tmp_path):
    cfg = {"gateway": {"bind": "127.0.0.1"}, "allow_candidate_images": True, "splunk": {"version": "10.6"}}
    rc, out = cli(tmp_path, INSTALL, config=cfg, env=FakeEnv())
    assert rc == 0, out
    vols = FakeEnv(volumes=["agentsec_splunk_var", "agentsec_splunk_etc"])
    assert cli(tmp_path, ["up"], env=vols)[0] == core.EXIT_CHECKS                      # data exists and this install never started: blocked
    (tmp_path / ".agentsec/started.json").write_text(json.dumps({"splunk": state_json(tmp_path)["resolved"]["images"]["splunk"]}))
    assert cli(tmp_path, ["up"], env=vols)[0] == 0                                      # the same image started before: a restart, not an upgrade
    (tmp_path / ".agentsec/started.json").write_text(json.dumps({"splunk": "x"}))
    assert cli(tmp_path, ["up"], env=vols)[0] == core.EXIT_CHECKS


def test_a_hand_edited_secret_with_interpolation_characters_is_refused(tmp_path):
    installed(tmp_path)
    env = tmp_path / ".env"
    text = env.read_text()
    pw = render.parse_env(text)["SPLUNK_PASSWORD"]
    env.write_text(text.replace(pw, "a$b"))
    r = FakeRunner()
    assert cli(tmp_path, ["up"], runner=r)[0] == core.EXIT_CHECKS and r.commands == []


@pytest.mark.parametrize("cfg", [{}, {"ollama": {"mode": "host"}}, {"splunk": {"mode": "none"}}, {"gateway": {"enabled": False}}])
def test_lab_expects_matches_what_the_installer_renders(tmp_path, cfg):
    installed(tmp_path, {"gateway": {"bind": "127.0.0.1"}, **cfg} if "gateway" not in cfg else cfg)
    for svc in ("ollama", "splunk", "splunk_app_init", "gateway", "acmebank"):
        want = svc in state_json(tmp_path)["resolved"]["services"]
        out, _ = run_helper_at(tmp_path, f"lab_expects {svc} && echo yes")
        assert (out.strip() == "yes") == want, svc


def run_helper_at(root, snippet):
    (root / "scripts").mkdir(exist_ok=True)
    (root / "scripts/lab-compose.sh").write_text((REPO / "scripts/lab-compose.sh").read_text())
    bindir = root / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "docker").write_text("#!/bin/sh\nexit 0\n")
    (bindir / "docker").chmod(0o755)
    p = subprocess.run(["sh", "-c", f'ROOT="{root}"; . "$ROOT/scripts/lab-compose.sh"; {snippet}'], capture_output=True, text=True, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    return p.stdout, p.stderr
