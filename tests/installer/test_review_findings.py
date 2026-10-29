"""Regression tests for the independent review of the installer core (F1-F20)."""
import itertools, json, os, stat, subprocess, sys
from pathlib import Path
import pytest
from agentsec.installer import core, preflight as pf, render
from agentsec.installer.cli import main
from agentsec.installer.config import ConfigError, InstallConfig, Locks, validate
from tests.installer.fakes import FakeEnv, FakeRunner, LEGACY_LAB, READ_ONLY_CALLS

LOCKS = Locks.load()
ROOT = Path(__file__).resolve().parents[2]


def C(**kw):
    d = {"gateway": {"bind": "127.0.0.1"}}
    for k, v in kw.items():
        d[k] = {**d.get(k, {}), **v} if isinstance(v, dict) and isinstance(d.get(k), dict) else v
    return InstallConfig.from_dict(d)


def pre(cfg, env=None):
    f, facts = pf.preflight(cfg, LOCKS, env or FakeEnv(), install_dir="/tmp/x")
    return {(x.level, x.code) for x in f}


def cli(tmp_path, args, env=None, runner=None, config=None, ask=lambda p: ""):
    out = []
    if config is not None:
        (tmp_path / "agentsec.install.json").write_text(json.dumps(config))
    rc = main(["--root", str(tmp_path), *args], env=env or FakeEnv(), runner=runner, ask=ask, out=out.append, locks=LOCKS, isatty=False)
    return rc, out


OK = ["install", "--non-interactive", "--accept-warnings", "all"]


# ---- F1 injection ---------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("data", [
    {"project": "lab\n"}, {"project": "lab\nCOMPOSE_FILE=/etc/x"}, {"gateway": {"host": "a.example\n"}}, {"gateway": {"host": "a.example\nAGENTSEC_AUTH_FILE=/x"}},
    {"gateway": {"bind": "127.0.0.1\nCOMPOSE_FILE=x"}}, {"ollama": {"mode": "remote", "url": "https://o.example.org\nCOMPOSE_FILE=/tmp/evil.yml"}},
    {"splunk": {"mode": "external_enterprise", "rest_url": "https://s.example.org:8089\nX=1", "token_file": "/t"}}, {"models": {"pipeline": "llama3.2:1b\nX=1"}},
    {"splunk": {"token_file": "/a\rb"}}, {"ollama": {"ca_file": "/a\x00b"}}])
def test_control_characters_are_refused_everywhere_before_anything_is_rendered(data):
    with pytest.raises(ConfigError):
        InstallConfig.from_dict(data)


@pytest.mark.parametrize("bad", ["lab\n", "lab ", "Lab", "a", "lab/../x"])
def test_the_project_name_check_is_a_full_match(bad):
    assert any(f.code == "PROJECT_INVALID" for f in validate(InstallConfig(project=bad), LOCKS))


def test_hostile_but_syntactically_valid_values_cannot_add_env_keys():
    c = C(project="lab2", gateway={"host": "gw.example.org"}, ollama={"mode": "remote", "url": "https://o.example.org"})
    keys_normal = set(render.parse_env(render.render_env(render.env_values(c, LOCKS, {"SPLUNK_PASSWORD": "p", "SPLUNK_HEC_TOKEN": "t"}))))
    baseline = set(render.parse_env(render.render_env(render.env_values(C(), LOCKS, {"SPLUNK_PASSWORD": "p", "SPLUNK_HEC_TOKEN": "t"}))))
    assert keys_normal - baseline <= {"OLLAMA_BASE_URL"}


@pytest.mark.parametrize("url", ["https://o.example.org#x", "https://o.example.org?a=b", "https://o.example.org/x", "https://u:p@o.example.org", "https://o.example.org:abc",
                                  "https://o.example.org$X", "https://o.example .org", 'https://o.example.org"', "http://o.example.org", "https://", "ftp://o.example.org"])
def test_a_remote_ollama_url_must_be_a_plain_https_url_without_credentials(url):
    f = validate(C(ollama={"mode": "remote", "url": url}), LOCKS)
    assert any(x.level == "ERROR" and x.code == "OLLAMA_REMOTE_NOT_HTTPS" for x in f), url
    assert "u:p" not in " ".join(x.message for x in f)                                    # credentials are never echoed back


@pytest.mark.parametrize("field,val", [("ca_file", "/etc/my ca.pem"), ("token_file", "/etc/t$HOME"), ("ca_file", "/etc/'x'"), ("token_file", "/etc/t#1")])
def test_paths_with_characters_that_compose_would_interpret_are_refused(field, val):
    base = {"mode": "external_enterprise", "rest_url": "https://s.example.org:8089", "token_file": "/etc/t", "ca_file": "/etc/ca"}
    assert ("ERROR", "SPLUNK_VALUE_UNSAFE") in {(x.level, x.code) for x in validate(C(splunk={**base, field: val}), LOCKS)}


def test_the_bind_address_must_be_an_ip():
    for b in ("0.0.0.0", "::", "10.2.3.4", "127.0.0.1", "localhost"):
        assert not any(x.code == "BIND_INVALID" for x in validate(C(deployment="organization", ack_external_controls=True, gateway={"bind": b}), LOCKS)), b
    for b in ("evil.example", "1.2.3", "0.0.0.0/0", "::1]"):
        assert any(x.code == "BIND_INVALID" for x in validate(C(gateway={"bind": b}), LOCKS)), b


# ---- the acknowledgement cannot be skipped, whatever the input route ------------------------------------------------------------------------------
def test_organization_mode_in_a_config_file_needs_the_acknowledgement_key(tmp_path):
    org = {"deployment": "organization", "gateway": {"bind": "0.0.0.0"}}
    rc, out = cli(tmp_path, OK, config=org)
    assert rc == core.EXIT_CHECKS and any("ORG_ACK_REQUIRED" in l for l in out) and not (tmp_path / ".env").exists()
    rc2, _ = cli(tmp_path, OK, config={**org, "ack_external_controls": True})
    assert rc2 == 0
    rc3, _ = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--set", "ack_external_controls=false"], config={**org, "ack_external_controls": True})
    assert rc3 == core.EXIT_CHECKS                                                       # a --set can withdraw it


def test_localhost_mode_can_never_render_a_non_loopback_publish_whatever_is_set(tmp_path):
    rc, _ = cli(tmp_path, OK + ["--set", "gateway.bind=0.0.0.0"])
    assert rc == core.EXIT_CHECKS and not (tmp_path / ".env").exists()
    for gw in (True, False):
        p = render.build_plan(C(gateway={"enabled": gw}), LOCKS, {})
        env = render.parse_env(p.files[".env"])
        assert env["AGENTSEC_BIND_ADDRESS"] == "127.0.0.1" and env.get("AGENTSEC_GATEWAY_BIND", "127.0.0.1") == "127.0.0.1"
        assert "0.0.0.0" not in p.files[".agentsec/compose.override.yml"]


def test_organization_without_the_gateway_binds_splunk_web_like_the_other_learner_ports():
    o = render.render_override(C(deployment="organization", ack_external_controls=True, gateway={"enabled": False, "bind": "10.1.1.5"}, ports={"splunk_web": 18000}))
    assert '"10.1.1.5:18000:8000"' in o and '"127.0.0.1:8088:8088"' in o and "stop_grace_period: 120s" in o


# ---- F2 Splunk data safety -----------------------------------------------------------------------------------------------------------------------
DATA = ["agentsec_splunk_var", "agentsec_splunk_etc"]


def test_splunk_10_6_is_never_started_over_existing_data_and_10_4_needs_an_acknowledgement():
    c6 = C(splunk={"version": "10.6"}, allow_candidate_images=True)
    assert ("ERROR", "SPLUNK_UPGRADE_BLOCKED") in pre(c6, FakeEnv(volumes=DATA))
    assert ("ERROR", "SPLUNK_UPGRADE_BLOCKED") not in pre(c6, FakeEnv())                           # fresh volumes: fine
    c4 = C(splunk={"version": "10.4"}, allow_candidate_images=True)
    assert ("ERROR", "SPLUNK_UPGRADE_NEEDS_ACK") in pre(c4, FakeEnv(volumes=DATA))
    assert ("ERROR", "SPLUNK_UPGRADE_NEEDS_ACK") not in pre(C(splunk={"version": "10.4"}, allow_candidate_images=True, ack_splunk_upgrade=True), FakeEnv(volumes=DATA))
    assert ("ERROR", "SPLUNK_UPGRADE_NEEDS_ACK") not in pre(C(), FakeEnv(volumes=DATA))             # the tested default over its own data is not an upgrade


def test_the_splunk_override_allows_a_long_stop():
    assert "stop_grace_period: 120s" in render.render_override(C())


# ---- F6 same-project recreation ----------------------------------------------------------------------------------------------------------------
def test_up_under_new_names_in_a_project_that_already_runs_the_old_names_needs_an_acknowledgement():
    same = FakeEnv(containers=[{"name": "agentsec_acmebank", "project": "agentsec", "image": "x", "ports": [5000]}], listeners={})
    assert ("ERROR", "WOULD_RECREATE_EXISTING_LAB") in pre(C(), same)
    assert ("WARN", "WOULD_RECREATE_EXISTING_LAB") in pre(C(ack_recreate_existing=True), same)
    assert ("ERROR", "WOULD_RECREATE_EXISTING_LAB") not in pre(C(), FakeEnv(**LEGACY_LAB))        # a different project: reported, not recreated
    assert not {x for x in pre(C(naming="legacy", project="agentsec"), same) if x[1] == "WOULD_RECREATE_EXISTING_LAB"}


# ---- F4 per-port ownership -------------------------------------------------------------------------------------------------------------------------
def test_only_ports_published_by_this_install_are_assumed_to_be_its_own():
    env = FakeEnv(listeners={443: "foreign", 8088: "docker"}, containers=[{"name": "agentsec-splunk", "project": "agentsec", "image": "x", "ports": [8088]}])
    got = pre(C(), env)
    assert ("ERROR", "PORT_IN_USE") in got                                                         # 443 is a foreign process: still an error
    f, _ = pf.preflight(C(), LOCKS, env, install_dir="/tmp/x")
    assert [x.code for x in f if x.code.startswith("PORT_IN_USE") and "hec" in x.message] == ["PORT_IN_USE_BY_PROJECT"]
    assert [x.code for x in f if x.code == "PORT_IN_USE" and "gateway" in x.message] == ["PORT_IN_USE"]


# ---- F10 the shell beats .env --------------------------------------------------------------------------------------------------------------------
def test_shell_variables_that_override_the_generated_env_are_flagged():
    assert ("WARN", "SHELL_ENV_OVERRIDES_CONFIG") in pre(C(), FakeEnv(environ={"COMPOSE_FILE": "x.yml"}))
    assert ("ERROR", "SHELL_ENV_OVERRIDES_CONFIG") in pre(C(), FakeEnv(environ={"AGENTSEC_BIND_ADDRESS": "0.0.0.0"}))        # would publish a localhost install
    assert ("ERROR", "SHELL_ENV_OVERRIDES_CONFIG") not in pre(C(), FakeEnv(environ={"AGENTSEC_BIND_ADDRESS": "127.0.0.1"}))
    assert not [x for x in pre(C(), FakeEnv(environ={"PATH": "/bin"})) if x[1] == "SHELL_ENV_OVERRIDES_CONFIG"]


# ---- F16 version parsing, F17 volumes and disk ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("v,ok", [("0.35.0", True), ("0.40.12", True), ("v0.40.1", True), ("0.35", True), ("0.34.9", False), ("0.35.0-rc1", False), ("0.1.46", False), ("1.0.0", True)])
def test_ollama_version_floor_parsing(v, ok):
    cfg = C(ollama={"mode": "host"})
    got = pre(cfg, FakeEnv(ollama={"http://127.0.0.1:11434": v}))
    assert (("OK", "OLLAMA_VERSION") in got) is ok and (("ERROR", "OLLAMA_TOO_OLD") in got) is (not ok)


@pytest.mark.parametrize("v", ["", "banana", None, 5, ["0.40"]])
def test_an_unreadable_version_is_a_warning_not_a_crash(v):
    got = pre(C(ollama={"mode": "host"}), FakeEnv(ollama={"http://127.0.0.1:11434": v}))
    assert ("WARN", "OLLAMA_UNREACHABLE") in got or ("WARN", "OLLAMA_VERSION_UNREADABLE") in got


def test_an_unrelated_volume_is_not_mistaken_for_a_lab():
    f, facts = pf.preflight(C(), LOCKS, FakeEnv(volumes=["backup_splunk_var", "x_splunk_var"]), install_dir="/tmp/x")
    assert facts["volume_prefixes"] == []
    f, facts = pf.preflight(C(), LOCKS, FakeEnv(volumes=["labA_splunk_var", "labA_ollama_models"]), install_dir="/tmp/x")
    assert facts["volume_prefixes"] == ["labA"]


def test_docker_storage_inside_a_vm_is_reported_as_not_measured():
    got = pre(C(), FakeEnv(paths={}))
    assert ("WARN", "DOCKER_DISK_NOT_MEASURED") in got
    assert ("WARN", "DOCKER_DISK_NOT_MEASURED") not in pre(C(), FakeEnv(paths={"/var/lib/docker": {"exists": True, "mode": 0o755, "size": 0, "is_file": False}}))


# ---- F3, F9, F11 rollback and file handling ---------------------------------------------------------------------------------------------------
def snap(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_a_no_op_rerun_changes_nothing_and_keeps_the_real_previous_configuration(tmp_path):
    cli(tmp_path, OK)
    cli(tmp_path, OK + ["--set", "gateway.port=8000"])
    before = snap(tmp_path)
    rc, out = cli(tmp_path, OK + ["--set", "gateway.port=8000"])
    assert rc == 0 and any("nothing changed" in l for l in out) and snap(tmp_path) == before          # includes .agentsec/previous: not rotated
    rc3, _ = cli(tmp_path, ["rollback"])
    first_port = render.parse_env((tmp_path / ".env").read_text())["AGENTSEC_PUBLIC_PORT"]
    assert rc3 == 0 and first_port == "443"                                                         # rollback still reaches the config BEFORE the port change


def test_rotation_leaves_no_staging_directories_or_temp_files(tmp_path):
    cli(tmp_path, OK); cli(tmp_path, OK + ["--set", "gateway.port=8000"])
    leftovers = [p.name for p in tmp_path.rglob("*") if p.name.endswith(".tmp") or p.name == "previous.new"]
    assert leftovers == []


def test_replacing_a_foreign_env_drops_a_stale_previous_and_rollback_refuses_foreign_files(tmp_path):
    cli(tmp_path, OK); cli(tmp_path, OK + ["--set", "gateway.port=8000"])
    assert (tmp_path / ".agentsec/previous").is_dir()
    (tmp_path / ".env").write_text("SPLUNK_PASSWORD=mine\n")
    rc, _ = cli(tmp_path, OK + ["--force-env"])
    assert rc == 0 and (tmp_path / ".env.pre-agentsec").read_text() == "SPLUNK_PASSWORD=mine\n" and not (tmp_path / ".agentsec/previous").exists()
    assert cli(tmp_path, ["rollback"])[0] == core.EXIT_CHECKS                                      # nothing to restore: the foreign .env is not "previous"
    (tmp_path / ".agentsec/previous").mkdir(); (tmp_path / ".agentsec/previous/.env").write_text("EVIL=1\n")
    assert cli(tmp_path, ["rollback"])[0] == core.EXIT_CHECKS and "EVIL" not in (tmp_path / ".env").read_text()


def test_backups_are_owner_only_and_a_second_foreign_env_is_not_lost(tmp_path):
    (tmp_path / ".env").write_text("A=1\n")
    cli(tmp_path, OK + ["--force-env"])
    (tmp_path / ".env").write_text("B=2\n")
    cli(tmp_path, OK + ["--force-env"])
    names = sorted(p.name for p in tmp_path.glob(".env.pre-agentsec*"))
    assert names == [".env.pre-agentsec", ".env.pre-agentsec.1"]
    assert {(tmp_path / n).read_text() for n in names} == {"A=1\n", "B=2\n"}
    for n in names:
        assert stat.S_IMODE((tmp_path / n).stat().st_mode) == 0o600


def test_the_installer_will_not_write_through_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"; target.write_text("keep")
    (tmp_path / ".agentsec").mkdir(mode=0o700)
    (tmp_path / ".agentsec/compose.override.yml").symlink_to(target)
    rc, out = cli(tmp_path, OK)
    assert rc == core.EXIT_REFUSED and target.read_text() == "keep" and any("symbolic link" in l for l in out)


def test_gitignore_covers_the_installers_state_and_backups():
    text = (ROOT / ".gitignore").read_text()
    assert ".agentsec/" in text and ".env.pre-agentsec*" in text


# ---- F5 plan prerequisites ----------------------------------------------------------------------------------------------------------------------
def test_the_plan_creates_what_the_base_compose_file_expects_and_skips_a_second_gateway_init():
    p = render.build_plan(C(), LOCKS, {"gateway_dir_exists": False})
    argvs = [c["argv"] for c in p.commands]
    assert ["mkdir", "-p", "artifacts/loan_desk/receipts"] in argvs and ["sh", "scripts/hec-certs.sh"] in argvs and ["sh", "scripts/gateway.sh", "init"] in argvs
    p2 = render.build_plan(C(), LOCKS, {"gateway_dir_exists": True})
    assert ["sh", "scripts/gateway.sh", "init"] not in [c["argv"] for c in p2.commands]
    p3 = render.build_plan(C(splunk={"mode": "none"}, gateway={"enabled": False}), LOCKS, {})
    assert ["sh", "scripts/hec-certs.sh"] not in [c["argv"] for c in p3.commands] and not any(a[:3] == ["docker", "compose", "pull"] and "splunk" in a for a in [c["argv"] for c in p3.commands])


def test_the_dry_run_uses_the_gateway_dir_fact_from_the_machine(tmp_path):
    env = FakeEnv(paths={str(tmp_path / ".gateway"): {"exists": True, "mode": 0o700, "size": 0, "is_file": False}})
    rc, out = cli(tmp_path, ["plan", "--accept-warnings", "all"], env=env)
    assert rc == 0 and not any("gateway.sh init" in l for l in out)
    rc, out = cli(tmp_path, ["plan", "--accept-warnings", "all"])
    assert any("AGENTSEC_PUBLIC_HOST=localhost AGENTSEC_PUBLIC_PORT=443 sh scripts/gateway.sh init" in l for l in out)


# ---- F15 smaller input problems ----------------------------------------------------------------------------------------------------------------
def test_a_non_numeric_gateway_port_in_the_wizard_exits_2_not_with_a_traceback(tmp_path):
    answers = iter(["localhost", "yes", "localhost", "four hundred"])
    rc, out = cli(tmp_path, ["install", "--interactive"], ask=lambda p: next(answers, ""))
    assert rc == core.EXIT_USAGE


def test_verify_models_with_the_bundled_ollama_explains_instead_of_crashing(tmp_path):
    rc, out = cli(tmp_path, ["verify-models"])
    assert rc == 0 and any("publishes no port" in l for l in out)


def test_remote_ollama_with_a_custom_ca_is_still_refused_not_silently_ignored():
    f = validate(C(ollama={"mode": "remote", "url": "https://o.example.org", "ca_file": "/etc/o.pem"}), LOCKS)
    assert any(x.level == "ERROR" and x.code == "OLLAMA_REMOTE_UNSUPPORTED" for x in f) and not any(x.code == "OLLAMA_CA_NOT_USED" for x in f)


# ---- F19 test-quality replacements --------------------------------------------------------------------------------------------------------------
def test_no_combination_of_options_ever_plans_a_destructive_command():
    bad = {"down", "rm", "prune", "-v", "--volumes", "volume", "kill", "stop", "restart", "--force-recreate", "--remove-orphans", "--renew-anon-volumes"}
    for naming, ollama, splunk, gw in itertools.product(("project", "legacy"), ("bundled", "host"), ("bundled", "none"), (True, False)):
        c = C(naming=naming, project="agentseclab" if naming == "legacy" else "agentsec", ollama={"mode": ollama}, splunk={"mode": splunk}, gateway={"enabled": gw})
        for cmd in render.build_plan(c, LOCKS, {}).commands:
            assert not (bad & set(cmd["argv"])), (naming, ollama, splunk, gw, cmd)
            assert cmd["argv"][0] in ("docker", "sh", "mkdir")


def test_the_legacy_adoption_override_really_exists_and_renames_nothing(tmp_path):
    env = FakeEnv(**LEGACY_LAB)
    rc, _ = cli(tmp_path, OK + ["--set", "naming=legacy", "--set", "project=agentseclab", "--set", "gateway.enabled=false"], env=env)
    assert rc == 0
    o = (tmp_path / ".agentsec/compose.override.yml").read_text()
    assert o.startswith("# ") and "services:" in o and "container_name" not in o and "aliases" not in o
    assert render.parse_env((tmp_path / ".env").read_text())["COMPOSE_PROJECT_NAME"] == "agentseclab"
    assert {c[0] for c in env.calls} <= READ_ONLY_CALLS


def test_two_installs_with_different_ports_publish_disjoint_host_ports():
    def published(c):
        o = render.render_override(c)
        base = {"acmebank": c.ports.acmebank, "attack": c.ports.attack, "splunk": c.ports.splunk_web, "hec": c.ports.hec, "otel_grpc": c.ports.otel_grpc, "otel_http": c.ports.otel_http}
        return set(base.values()) | ({c.gateway.port} if c.gateway.enabled else set())
    a = published(C(gateway={"enabled": False}))
    b = published(C(project="lab2", gateway={"enabled": False}, ports={"splunk_web": 28000, "hec": 28088, "otel_grpc": 24317, "otel_http": 24318, "acmebank": 25000, "attack": 25001}))
    assert not (a & b)
    o = render.render_override(C(project="lab2", gateway={"enabled": False}, ports={"splunk_web": 28000, "hec": 28088, "otel_grpc": 24317, "otel_http": 24318, "acmebank": 25000, "attack": 25001}))
    for port in ("28000:8000", "28088:8088", "24317:4317", "24318:4318", "25000:5000", "25001:5001"):
        assert port in o


def test_the_stdlib_only_claim_holds_for_every_installer_dependency():
    code = ("import sys\nfor m in ('requests','flask','jsonschema','yaml','opentelemetry','werkzeug'): sys.modules[m] = None\n"
            f"sys.path.insert(0, {str(ROOT / 'src')!r})\n"
            "import agentsec.installer.cli, agentsec.installer.provenance, agentsec.installer.render, agentsec.installer.core, agentsec.splunk_client, agentsec.gateway_config, agentsec.model_names\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
