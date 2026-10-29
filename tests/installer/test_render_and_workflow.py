import json, os, shutil, stat, subprocess
from pathlib import Path
import pytest
from agentsec.installer import core, render
from agentsec.installer.cli import main
from agentsec.installer.config import InstallConfig, Locks
from tests.installer.fakes import FakeEnv, FakeRunner, LEGACY_LAB, READ_ONLY_CALLS

LOCKS = Locks.load()
REPO = Path(__file__).resolve().parents[2]


def cfgd(**kw):
    d = {"gateway": {"bind": "127.0.0.1"}}
    for k, v in kw.items():
        d[k] = {**d.get(k, {}), **v} if isinstance(v, dict) and isinstance(d.get(k), dict) else v
    return InstallConfig.from_dict(d)


def plan_for(cfg, prev=None, facts=None):
    return render.build_plan(cfg, LOCKS, facts or {"platform": "Linux/x86_64", "volume_prefixes": []}, prev)


def envmap(plan):
    return render.parse_env(plan.files[".env"])


def cli(tmp_path, args, *, env=None, runner=None, ask=None, out=None, config=None):
    lines = [] if out is None else out
    if config is not None:
        (tmp_path / "agentsec.install.json").write_text(json.dumps(config))
    rc = main(["--root", str(tmp_path), *args], env=env or FakeEnv(), runner=runner, ask=ask or (lambda p: ""), out=lines.append, locks=LOCKS, isatty=False)
    return rc, lines


# ---- generated files ---------------------------------------------------------------------------------------------------------------------------
def test_env_is_generated_with_secure_defaults():
    p = plan_for(InstallConfig())
    e = envmap(p)
    assert e["COMPOSE_PROJECT_NAME"] == "agentsec" and e["AGENTSEC_BIND_ADDRESS"] == "127.0.0.1" and e["COMPOSE_PROFILES"] == "local,gateway"
    assert e["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.local.yml:docker-compose.gateway.yml:.agentsec/compose.override.yml"
    assert e["SPLUNK_IMAGE"].startswith("splunk/splunk@sha256:") and e["SPLUNK_PLATFORM"] == "linux/amd64"
    assert e["SPLUNK_PASSWORD"] not in ("ChangeMeLab!2026", "") and e["SPLUNK_HEC_TOKEN"] != "lab-hec-token-change-me" and len(e["SPLUNK_PASSWORD"]) >= 16
    assert e["OLLAMA_MODEL"] == "llama3.2:1b" and e["LOANDESK_MODEL"] == "llama3.2:latest" and "OLLAMA_BASE_URL" not in e
    assert e["AGENTSEC_PUBLIC_PORT"] == "443" and e["AGENTSEC_GATEWAY_BIND"] == "127.0.0.1" and "AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK" not in e
    assert e["AGENTSEC_SPLUNK_LOCAL_PORT"] == "18000"


def test_secrets_are_random_per_install_and_never_in_the_state_file_or_the_override():
    a, b = envmap(plan_for(InstallConfig())), envmap(plan_for(InstallConfig()))
    assert a["SPLUNK_PASSWORD"] != b["SPLUNK_PASSWORD"] and a["SPLUNK_HEC_TOKEN"] != b["SPLUNK_HEC_TOKEN"]
    p = plan_for(InstallConfig())
    for key in (".agentsec/install.json", ".agentsec/compose.override.yml"):
        assert envmap(p)["SPLUNK_PASSWORD"] not in p.files[key] and envmap(p)["SPLUNK_HEC_TOKEN"] not in p.files[key]


def test_an_existing_installs_secrets_are_reused_but_the_example_defaults_never_are():
    first = envmap(plan_for(InstallConfig()))
    again = envmap(plan_for(InstallConfig(), prev=first))
    assert again["SPLUNK_PASSWORD"] == first["SPLUNK_PASSWORD"] and again["SPLUNK_HEC_TOKEN"] == first["SPLUNK_HEC_TOKEN"]
    old = {"SPLUNK_PASSWORD": "ChangeMeLab!2026", "SPLUNK_HEC_TOKEN": "lab-hec-token-change-me"}
    fresh = envmap(plan_for(InstallConfig(), prev=old))
    assert fresh["SPLUNK_PASSWORD"] != old["SPLUNK_PASSWORD"] and fresh["SPLUNK_HEC_TOKEN"] != old["SPLUNK_HEC_TOKEN"]


def test_rendering_is_deterministic_for_the_same_inputs():
    prev = envmap(plan_for(InstallConfig()))
    assert plan_for(InstallConfig(), prev=prev).files == plan_for(InstallConfig(), prev=prev).files


def test_organization_mode_publishes_where_told_and_sets_the_gateways_own_acknowledgement():
    e = envmap(plan_for(cfgd(deployment="organization", ack_external_controls=True, gateway={"bind": "0.0.0.0"})))
    assert e["AGENTSEC_GATEWAY_BIND"] == "0.0.0.0" and e["AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK"] == "1"
    assert envmap(plan_for(InstallConfig()))["AGENTSEC_BIND_ADDRESS"] == "127.0.0.1"


@pytest.mark.parametrize("mode,url,expect", [("bundled", "", None), ("host", "", "http://host.docker.internal:11434"), ("remote", "https://o.example.org", "https://o.example.org")])
def test_ollama_selection_reaches_the_environment(mode, url, expect):
    e = envmap(plan_for(cfgd(ollama={"mode": mode, "url": url})))
    assert e.get("OLLAMA_BASE_URL") == expect


def test_model_and_image_selection_are_explicit_in_the_environment():
    e = envmap(plan_for(cfgd(models={"pipeline": "granite4.1:3b-q4_K_M"}, allow_unpinned_model=True)))
    assert e["OLLAMA_MODEL"] == "granite4.1:3b-q4_K_M" and e["LOANDESK_MODEL"] == "llama3.2:latest"
    e2 = envmap(plan_for(cfgd(splunk={"version": "10.4"}, allow_candidate_images=True)))
    assert e2["SPLUNK_IMAGE"] == "splunk/splunk@" + LOCKS.images["splunk"]["versions"]["10.4"]["digest"]


def test_external_splunk_writes_only_paths_never_the_token_and_drops_the_bundled_services():
    c = cfgd(splunk={"mode": "external_enterprise", "rest_url": "https://s.example.org:8089", "token_file": "/etc/t/token", "ca_file": "/etc/t/ca.pem"})
    p = plan_for(c)
    e = envmap(p)
    assert e["AGENTSEC_SPLUNK_MODE"] == "EXTERNAL_ENTERPRISE" and e["AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE"] == "/etc/t/token" and "SPLUNK_IMAGE" not in e
    assert "splunk" not in p.services and "local" not in e["COMPOSE_PROFILES"] and "docker-compose.local.yml" not in e["COMPOSE_FILE"]


def test_override_isolates_the_project_and_keeps_the_old_names_as_aliases():
    o = plan_for(InstallConfig()).files[".agentsec/compose.override.yml"]
    assert "container_name: agentsec-acmebank" in o and "container_name: agentsec-splunk" in o and "- agentsec_splunk" in o
    assert "LOANDESK_MODEL=${LOANDESK_MODEL:-llama3.2:latest}" in o and "ports:" not in o         # all ports at their defaults: nothing to override
    two = plan_for(cfgd(project="lab2")).files[".agentsec/compose.override.yml"]
    assert "container_name: lab2-acmebank" in two and "container_name: agentsec-acmebank" not in two


def test_legacy_naming_changes_no_names():
    o = plan_for(cfgd(naming="legacy", project="agentseclab")).files[".agentsec/compose.override.yml"]
    assert "container_name" not in o and "aliases" not in o


def test_host_ollama_removes_the_dependency_on_the_bundled_one_and_non_default_ports_are_overridden():
    o = plan_for(cfgd(ollama={"mode": "host"}, gateway={"enabled": False}, ports={"acmebank": 15000, "attack": 15001, "hec": 18088})).files[".agentsec/compose.override.yml"]
    assert "depends_on: !override" in o
    assert "host.docker.internal:host-gateway" in o and '"127.0.0.1:15000:5000"' in o and '"127.0.0.1:15001:5001"' in o and '"127.0.0.1:18088:8088"' in o
    assert "ollama" not in plan_for(cfgd(ollama={"mode": "host"})).services


def test_the_plan_never_contains_a_destructive_or_data_removing_command():
    for c in (InstallConfig(), cfgd(naming="legacy", project="agentseclab"), cfgd(ollama={"mode": "host"})):
        for argv in (x["argv"] for x in plan_for(c).commands):
            assert not ({"down", "rm", "prune", "-v", "--volumes", "volume", "kill", "stop", "restart", "--force-recreate", "--remove-orphans"} & set(argv)), argv


def test_the_override_is_valid_compose_and_does_what_it_says():
    """Reads only: `docker compose config` renders the files and starts nothing. Skipped without Docker Compose."""
    try:
        ok = subprocess.run(["docker", "compose", "version"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    if not ok:
        pytest.skip("docker compose is not available")
    import tempfile
    for label, c, checks in (
        ("project names, defaults", cfgd(project="lab2"), lambda s: (
            s["acmebank"]["container_name"] == "lab2-acmebank" and "agentsec_acmebank" in s["acmebank"]["networks"]["agentsec_mesh"]["aliases"]
            and "LOANDESK_MODEL" in s["acmebank"]["environment"] and not s["acmebank"].get("ports") and s["gateway"]["container_name"] == "lab2-gateway")),
        ("host Ollama, own ports, no gateway", cfgd(ollama={"mode": "host"}, gateway={"enabled": False}, ports={"acmebank": 15000, "hec": 18088}), lambda s: (
            "ollama" not in s["acmebank"].get("depends_on", {}) and any(p["published"] == "15000" for p in s["acmebank"]["ports"])
            and {p["published"] for p in s["splunk"]["ports"]} == {"8000", "18088"})),
        ("legacy adoption", cfgd(naming="legacy", project="agentseclab"), lambda s: s["acmebank"]["container_name"] == "agentsec_acmebank"),
    ):
        with tempfile.TemporaryDirectory() as d:
            for f in ("docker-compose.yml", "docker-compose.local.yml", "docker-compose.gateway.yml"):
                shutil.copy(REPO / f, d)
            for rel, text in plan_for(c).files.items():
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True); (Path(d) / rel).write_text(text)
            r = subprocess.run(["docker", "compose", "--project-directory", d, "config", "--format", "json"], capture_output=True, text=True, cwd=d, timeout=60,
                               env={**{k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "AGENTSEC_", "SPLUNK_", "OLLAMA_"))}})
            assert r.returncode == 0, (label, r.stderr[-600:])
            services = json.loads(r.stdout)["services"]
            assert checks(services), label


# ---- workflow: dry run, write, rollback, refusal -----------------------------------------------------------------------------------------------
def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_dry_run_writes_nothing_and_prints_the_plan(tmp_path):
    env = FakeEnv()
    rc, out = cli(tmp_path, ["install", "--non-interactive", "--dry-run", "--accept-warnings", "all"], env=env)
    assert rc == 0 and snapshot(tmp_path) == {} and any("DRY RUN" in l for l in out)
    text = "\n".join(out)
    assert "Writes: .env" in text and "docker compose up -d" in text and "Download on --apply: splunk image splunk/splunk@sha256:" in text and "$ docker compose pull ollama splunk" in text
    assert envmap(plan_for(InstallConfig()))["SPLUNK_PASSWORD"] not in text            # the plan never prints a secret
    assert {c[0] for c in env.calls} <= READ_ONLY_CALLS


def test_install_writes_owner_only_files_and_applies_nothing_without_apply(tmp_path):
    runner = FakeRunner()
    rc, out = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all"], runner=runner)
    assert rc == 0 and runner.commands == []
    for rel in (".env", ".agentsec/compose.override.yml", ".agentsec/install.json"):
        assert stat.S_IMODE((tmp_path / rel).stat().st_mode) == 0o600, rel
    assert stat.S_IMODE((tmp_path / ".agentsec").stat().st_mode) == 0o700
    state = json.loads((tmp_path / ".agentsec/install.json").read_text())
    assert state["config"]["project"] == "agentsec" and "SPLUNK_PASSWORD" not in json.dumps(state)


def test_apply_runs_the_plan_in_order_and_stops_at_the_first_failure(tmp_path):
    ok = FakeRunner()
    rc, _ = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--apply"], runner=ok)
    assert rc == 0 and ok.commands[0][:4] == ["docker", "compose", "config", "-q"] and ok.commands[-1][:4] == ["docker", "compose", "up", "-d"]
    assert ["mkdir", "-p", "artifacts/loan_desk/receipts"] in ok.commands and ["sh", "scripts/hec-certs.sh"] in ok.commands          # prerequisites the base compose file needs
    gw = ok.commands.index(["sh", "scripts/gateway.sh", "init"])
    assert ok.envs[gw] == {"AGENTSEC_PUBLIC_HOST": "localhost", "AGENTSEC_PUBLIC_PORT": "443"}                                    # gateway.sh reads the process environment, not .env
    assert gw < ok.commands.index(["docker", "compose", "up", "-d", *render.services(InstallConfig())])
    bad = FakeRunner(fail_on=2)
    rc2, out = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--apply"], runner=bad)
    assert rc2 == core.EXIT_APPLY and len(bad.commands) == 2 and any("command exited 1" in l for l in out)


def test_errors_write_nothing_and_exit_3(tmp_path):
    rc, out = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all"], env=FakeEnv(docker=False))
    assert rc == core.EXIT_CHECKS and snapshot(tmp_path) == {} and any("DOCKER_UNAVAILABLE" in l for l in out)


def test_unaccepted_warnings_stop_the_install_and_name_the_codes_to_accept(tmp_path):
    rc, out = cli(tmp_path, ["install", "--non-interactive"])
    assert rc == core.EXIT_CHECKS and snapshot(tmp_path) == {}
    line = next(l for l in out if "unaccepted warnings" in l)
    codes = line.split("--accept-warnings ")[1].split(" ")[0].split(",")
    rc2, _ = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", ",".join(codes)])
    assert rc2 == 0


def test_a_foreign_env_is_never_overwritten_without_force_and_is_backed_up_with_it(tmp_path):
    (tmp_path / ".env").write_text("SPLUNK_PASSWORD=mine\n")
    rc, out = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all"])
    assert rc == core.EXIT_REFUSED and (tmp_path / ".env").read_text() == "SPLUNK_PASSWORD=mine\n" and not (tmp_path / ".agentsec").exists()
    rc2, _ = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--force-env"])
    assert rc2 == 0 and (tmp_path / ".env.pre-agentsec").read_text() == "SPLUNK_PASSWORD=mine\n" and (tmp_path / ".env").read_text().startswith(render.MARKER)


def test_reinstall_keeps_secrets_and_rollback_restores_the_previous_configuration_exactly(tmp_path):
    cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all"])
    first = snapshot(tmp_path)
    rc, _ = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--set", "gateway.port=8000", "--set", "project=lab2"])
    second = snapshot(tmp_path)
    assert rc == 0 and second[".env"] != first[".env"]
    e1, e2 = render.parse_env(first[".env"].decode()), render.parse_env(second[".env"].decode())
    assert e1["SPLUNK_PASSWORD"] == e2["SPLUNK_PASSWORD"] and e2["COMPOSE_PROJECT_NAME"] == "lab2" and e2["AGENTSEC_PUBLIC_PORT"] == "8000"
    env = FakeEnv()
    rc3, _ = cli(tmp_path, ["rollback"], env=env)
    assert rc3 == 0 and (tmp_path / ".env").read_bytes() == first[".env"] and (tmp_path / ".agentsec/compose.override.yml").read_bytes() == first[".agentsec/compose.override.yml"]
    assert env.calls == []                                                                 # rollback asks the machine nothing and changes no container, image or volume


def test_rollback_without_a_previous_configuration_says_so(tmp_path):
    rc, out = cli(tmp_path, ["rollback"])
    assert rc == core.EXIT_CHECKS and "nothing to roll back" in out[0]


# ---- project isolation, volumes, existing labs -------------------------------------------------------------------------------------------------
def test_two_installs_get_distinct_projects_and_container_names(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"; a.mkdir(); b.mkdir()
    cli(a, ["install", "--non-interactive", "--accept-warnings", "all"])
    cli(b, ["install", "--non-interactive", "--accept-warnings", "all", "--set", "project=lab2", "--set", "gateway.port=8000"])
    ea, eb = render.parse_env((a / ".env").read_text()), render.parse_env((b / ".env").read_text())
    assert ea["COMPOSE_PROJECT_NAME"] != eb["COMPOSE_PROJECT_NAME"]
    names = lambda root: set(__import__("re").findall(r"container_name: (\S+)", (root / ".agentsec/compose.override.yml").read_text()))
    assert names(a).isdisjoint(names(b)) and ea["AGENTSEC_PUBLIC_PORT"] != eb["AGENTSEC_PUBLIC_PORT"]


def test_a_new_install_beside_a_running_legacy_lab_warns_and_changes_nothing_of_it(tmp_path):
    env = FakeEnv(**LEGACY_LAB)
    rc, out = cli(tmp_path, ["preflight", "--non-interactive"], env=env)
    text = "\n".join(out)
    assert "EXISTING_LAB_LEGACY_NAMES" in text and "VOLUMES_NOT_ADOPTED" in text and "Nothing is deleted" in text
    rc2, out2 = cli(tmp_path, ["install", "--non-interactive", "--accept-warnings", "all", "--set", "naming=legacy", "--set", "project=agentseclab", "--set", "gateway.enabled=false"], env=env)
    assert rc2 == 0
    assert any("LEGACY_ADOPT" in l for l in cli(tmp_path, ["preflight", "--non-interactive", "--set", "naming=legacy", "--set", "project=agentseclab", "--set", "gateway.enabled=false"], env=env)[1])
    o = (tmp_path / ".agentsec/compose.override.yml").read_text() if (tmp_path / ".agentsec/compose.override.yml").exists() else ""
    assert "container_name" not in o                                                            # adoption renames nothing
    assert {c[0] for c in env.calls} <= READ_ONLY_CALLS   # questions only


# ---- configuration input: file, flags, interactive ---------------------------------------------------------------------------------------------
def test_configuration_file_and_set_flags_are_merged_and_malformed_input_exits_2(tmp_path):
    rc, out = cli(tmp_path, ["print-config", "--set", "gateway.port=8000", "--set", "ollama.mode=host"], config={"project": "lab3"})
    d = json.loads("\n".join(out))
    assert rc == 0 and d["project"] == "lab3" and d["gateway"]["port"] == 8000 and d["ollama"]["mode"] == "host"
    (tmp_path / "agentsec.install.json").write_text("{not json")
    assert cli(tmp_path, ["validate"])[0] == core.EXIT_USAGE
    assert cli(tmp_path, ["validate"], config={"unknown": 1})[0] == core.EXIT_USAGE
    assert cli(tmp_path, ["validate", "--set", "novalue"])[0] == core.EXIT_USAGE
    assert cli(tmp_path, ["validate", "--config", str(tmp_path / "missing.json")])[0] == core.EXIT_USAGE


def test_organization_mode_through_flags_needs_the_acknowledgement_flag(tmp_path):
    args = ["install", "--non-interactive", "--accept-warnings", "all", "--set", "deployment=organization", "--set", "gateway.bind=0.0.0.0"]
    rc, out = cli(tmp_path, args)
    assert rc == core.EXIT_CHECKS and any("ORG_ACK_REQUIRED" in l for l in out) and snapshot(tmp_path) == {}
    rc2, _ = cli(tmp_path, args + ["--ack-external-controls"])
    assert rc2 == 0 and render.parse_env((tmp_path / ".env").read_text())["AGENTSEC_GATEWAY_ALLOW_NONLOOPBACK"] == "1"


def scripted(answers):
    it = iter(answers)
    return lambda prompt: next(it, "")


def test_interactive_defaults_flow_accepts_enter_and_prefers_host_ollama_on_apple_silicon(tmp_path):
    rc, out = cli(tmp_path, ["install", "--interactive", "--accept-warnings", "all"], env=FakeEnv(os_name="Darwin", machine="arm64", ollama={"http://127.0.0.1:11434": "0.40.12"}), ask=scripted([]))
    assert rc == 0
    e = render.parse_env((tmp_path / ".env").read_text())
    assert e["OLLAMA_BASE_URL"] == "http://host.docker.internal:11434" and e["AGENTSEC_GATEWAY_BIND"] == "127.0.0.1"


def test_interactive_organization_mode_requires_the_typed_phrase(tmp_path):
    answers = ["organization", "WRONG PHRASE", "0.0.0.0"]
    rc, out = cli(tmp_path, ["install", "--interactive", "--accept-warnings", "all"], ask=scripted(answers))
    assert rc == core.EXIT_CHECKS and any("ORG_ACK_REQUIRED" in l for l in out) and snapshot(tmp_path) == {}
    text = "\n".join(out)
    assert "NO failed-login throttling" in text
    rc2, _ = cli(tmp_path, ["install", "--interactive", "--accept-warnings", "all"], ask=scripted(["organization", "I ACKNOWLEDGE", "0.0.0.0"]))
    assert rc2 == 0


def test_the_wizard_rejects_a_bad_choice_and_asks_again(tmp_path):
    answers = ["moon", "localhost"]
    prompts = []
    ask = lambda p: (prompts.append(p), next(iter([answers.pop(0)]) if answers else iter([""])))[1]
    rc, out = cli(tmp_path, ["install", "--interactive", "--accept-warnings", "all"], ask=ask)
    assert rc == 0 and any("choose one of" in l for l in out) and sum("Deployment" in p for p in prompts) == 2


def test_verify_models_and_verify_images_are_read_only_and_list_before_running(tmp_path):
    rc, out = cli(tmp_path, ["verify-images"])
    assert rc == 0 and any("would run: docker buildx imagetools inspect" in l for l in out) and any("nothing was run" in l for l in out)
    runner = FakeRunner()
    cli(tmp_path, ["verify-images"], runner=runner)
    assert runner.commands == []
    tags = {"models": [{"name": "llama3.2:1b", "digest": "abc"}, {"name": "llama3.2:latest", "digest": "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72"}]}
    rc2, out2 = cli(tmp_path, ["verify-models", "--set", "ollama.mode=host"], env=FakeEnv(tags=tags))
    assert rc2 == 0 and any("MODEL_PINNED_MATCH" in l for l in out2) and any("MODEL_UNPINNED" in l for l in out2)
    bad = {"models": [{"name": "llama3.2:latest", "digest": "f" * 64}]}
    rc3, out3 = cli(tmp_path, ["verify-models", "--set", "ollama.mode=host"], env=FakeEnv(tags=bad))
    assert rc3 == core.EXIT_CHECKS and any("MODEL_DIGEST_MISMATCH" in l for l in out3) and any("MODEL_ABSENT" in l for l in out3)


def test_the_plan_promises_a_model_download_only_where_something_downloads_it():
    refs = lambda p: sorted(d["ref"] for d in p.downloads if d["what"].startswith("model "))
    assert refs(plan_for(InstallConfig())) == ["llama3.2:1b", "llama3.2:latest"]       # the bundled Ollama container pulls both (scripts/ollama_init.sh)
    assert refs(plan_for(cfgd(ollama={"mode": "host"}))) == []                          # a host Ollama is the learner's to fill; the Academy shows the command
    assert refs(plan_for(cfgd(ollama={"mode": "bundled"}, models={"loan_desk": "llama3.2:1b"}))) == ["llama3.2:1b"]
    assert "LOANDESK_MODEL=llama3.2:latest" in plan_for(InstallConfig()).files[".env"]


REST = {"rest_url": "https://splunk.example.org:8089", "ca_file": "/etc/ssl/splunk-ca.pem", "token_file": "/home/u/splunk.token"}


def _attack_block(plan):
    o = plan.files[".agentsec/compose.override.yml"]
    i = o.index("  attack_service:")
    nxt = [k for k in (o.find("\n  otel_collector:", i), o.find("\n  splunk", i), o.find("\n  gateway:", i), o.find("\n  acmebank:", i)) if k > i]
    return o[i:min(nxt) if nxt else len(o)]


def test_a_configured_splunk_rest_check_reaches_the_attack_service_container():
    """The .env values were only read by host scripts; Compose never passed them (or the token and CA files) into the container, so the check could not run there."""
    blk = _attack_block(plan_for(cfgd(splunk={"mode": "external_enterprise", **REST})))
    for want in ('"AGENTSEC_SPLUNK_MODE=EXTERNAL_ENTERPRISE"', '"AGENTSEC_SPLUNK_REST_URL=https://splunk.example.org:8089"',
                 '"AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE=/run/secrets/agentsec_splunk_token"', '"AGENTSEC_SPLUNK_CA_BUNDLE_FILE=/run/secrets/agentsec_splunk_ca"',
                 'source: "/home/u/splunk.token"', "target: /run/secrets/agentsec_splunk_token", 'source: "/etc/ssl/splunk-ca.pem"', "target: /run/secrets/agentsec_splunk_ca"):
        assert want in blk, want
    assert blk.count("read_only: true") == 2


def test_the_bundled_splunk_gets_the_rest_check_only_when_both_url_and_token_file_are_given():
    assert "SPLUNK_REST_URL" not in _attack_block(plan_for(InstallConfig()))                                    # the default install is unchanged
    on = plan_for(cfgd(splunk={"mode": "bundled", "rest_url": "https://splunk:8089", "token_file": "/home/u/t"}))
    assert "AGENTSEC_SPLUNK_MODE=BUNDLED" in _attack_block(on) and "AGENTSEC_SPLUNK_CA_BUNDLE_FILE" not in _attack_block(on)    # no CA file: the system store
    assert envmap(on)["AGENTSEC_SPLUNK_REST_URL"] == "https://splunk:8089"
    half = cfgd(splunk={"mode": "bundled", "rest_url": "https://splunk:8089"})
    assert "SPLUNK_REST_URL" not in _attack_block(plan_for(half))
    from agentsec.installer import config as C
    assert "SPLUNK_REST_INCOMPLETE" in [x.code for x in C.validate(half, LOCKS)]


def test_a_rest_path_with_a_quote_or_space_is_refused_before_it_can_reach_the_override():
    from agentsec.installer import config as C
    bad = cfgd(splunk={"mode": "external_enterprise", **{**REST, "token_file": '/home/u/a b"c'}})
    assert "SPLUNK_VALUE_UNSAFE" in [x.code for x in C.validate(bad, LOCKS)]


@pytest.mark.parametrize("field,value", [("token_file", "/"), ("ca_file", "/a/../etc/shadow"), ("token_file", "/home/u/../../etc/shadow"), ("ca_file", '/x"y'), ("index", "a b")])
@pytest.mark.parametrize("mode", ["external_enterprise", "bundled"])
def test_unsafe_rest_values_are_refused_in_both_modes_before_they_can_be_mounted(mode, field, value):
    from agentsec.installer import config as C
    try:
        c = cfgd(splunk={"mode": mode, **REST, field: value})
    except Exception:
        return                                                  # rejected even earlier, while reading the configuration
    assert any(x.level == "ERROR" for x in C.validate(c, LOCKS))
