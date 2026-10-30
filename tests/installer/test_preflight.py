"""Read-only preflight against a fake machine. Every scenario also proves FakeEnv was only asked questions (it has no way to change anything)."""
import pytest
from agentsec.installer import preflight as pf
from agentsec.installer.config import InstallConfig, Locks
from tests.installer.fakes import FakeEnv, LEGACY_LAB, READ_ONLY_CALLS

LOCKS = Locks.load()


def run(cfg=None, env=None, tmp="/tmp/agentsec-install"):
    cfg = cfg or InstallConfig()
    env = env or FakeEnv()
    f, facts = pf.preflight(cfg, LOCKS, env, install_dir=tmp)
    return {(x.level, x.code) for x in f}, f, facts, env


def cfgd(**kw):
    d = {"gateway": {"bind": "127.0.0.1"}}
    for k, v in kw.items():
        d[k] = {**d.get(k, {}), **v} if isinstance(v, dict) and isinstance(d.get(k), dict) else v
    return InstallConfig.from_dict(d)


def test_a_clean_linux_machine_has_no_errors():
    got, f, facts, env = run()
    assert not [x for x in got if x[0] == "ERROR"] and ("OK", "DOCKER") in got and ("OK", "COMPOSE") in got and facts["platform"] == "Linux/x86_64"


def test_no_docker_is_one_clear_error():
    got, f, *_ = run(env=FakeEnv(docker=False))
    assert ("ERROR", "DOCKER_UNAVAILABLE") in got
    assert "Install Docker" in next(x.message for x in f if x.code == "DOCKER_UNAVAILABLE")


def test_old_compose_without_override_tags_is_an_error():
    assert ("ERROR", "COMPOSE_TOO_OLD") in run(env=FakeEnv(override_tags=False))[0]
    assert ("ERROR", "COMPOSE_UNAVAILABLE") in run(env=FakeEnv(compose=None))[0]


@pytest.mark.parametrize("os_name,code", [("Windows", "WINDOWS_NATIVE_UNSUPPORTED"), ("FreeBSD", "PLATFORM_UNSUPPORTED")])
def test_unsupported_platforms(os_name, code):
    assert ("ERROR", code) in run(env=FakeEnv(os_name=os_name))[0]


def test_apple_silicon_notes_emulation_and_advises_native_ollama():
    got, f, *_ = run(cfgd(ollama={"mode": "bundled"}), FakeEnv(os_name="Darwin", machine="arm64", mem_gib=6))
    assert ("WARN", "DOCKER_MEMORY_LOW") in got and ("WARN", "OLLAMA_BUNDLED_MEMORY") in got
    assert "NOT a benchmarked minimum" in next(x.message for x in f if x.code == "DOCKER_MEMORY_LOW") and any("emulation" in x.message for x in f if x.code == "PLATFORM")
    host = run(cfgd(ollama={"mode": "host"}), FakeEnv(os_name="Darwin", machine="arm64", mem_gib=6, ollama={"http://127.0.0.1:11434": "0.40.12"}))[0]
    assert ("WARN", "OLLAMA_BUNDLED_MEMORY") not in host


def test_memory_is_advisory_only_and_not_asked_without_a_bundled_splunk():
    assert ("WARN", "DOCKER_MEMORY_LOW") not in run(cfgd(splunk={"mode": "none"}), FakeEnv(mem_gib=2))[0]
    assert ("WARN", "DOCKER_MEMORY_LOW") not in run(env=FakeEnv(mem_gib=16))[0]


def test_disk_is_checked_against_the_locks_and_fails_with_numbers():
    got, f, facts, _ = run(env=FakeEnv(free_gb=5))
    assert ("ERROR", "DISK_LOW") in got and facts["disk_need_gb"] > 15
    assert "GB free" in next(x.message for x in f if x.code == "DISK_LOW")
    assert ("WARN", "DISK_NOT_MEASURED") in run(env=FakeEnv(free_gb=None))[0]
    # a remote Ollama needs no model download; no bundled Splunk needs no 7 GB image
    small = run(cfgd(ollama={"mode": "remote", "url": "https://o.example.org"}, splunk={"mode": "none"}), FakeEnv(free_gb=8))[2]["disk_need_gb"]
    assert small < 6


def test_ports_in_use_are_errors_unless_they_belong_to_this_project():
    got, f, *_ = run(env=FakeEnv(listeners={443: "something"}))
    assert ("ERROR", "PORT_IN_USE") in got and "443" in next(x.message for x in f if x.code == "PORT_IN_USE")
    mine = FakeEnv(listeners={443: "docker"}, containers=[{"name": "agentsec-gateway", "project": "agentsec", "image": "x", "ports": [443]}])
    got2 = run(env=mine)[0]
    assert ("ERROR", "PORT_IN_USE") not in got2 and ("INFO", "PORT_IN_USE_BY_PROJECT") in got2 and ("INFO", "PROJECT_EXISTS") in got2


def test_loopback_ports_are_checked_in_the_non_gateway_layout():
    got = run(cfgd(gateway={"enabled": False}), FakeEnv(listeners={5001: "x", 8000: "y"}))[0]
    assert sum(1 for x in got if x == ("ERROR", "PORT_IN_USE")) == 1          # collapsed in the set; both are reported in the list
    _, f, *_ = run(cfgd(gateway={"enabled": False}), FakeEnv(listeners={5001: "x", 8000: "y"}))
    assert len([x for x in f if x.code == "PORT_IN_USE"]) == 2


# ---- an existing lab: reported, never touched ------------------------------------------------------------------------------------------------
def test_an_existing_legacy_lab_is_reported_and_never_touched():
    env = FakeEnv(**LEGACY_LAB)
    got, f, facts, _ = run(env=env)
    assert ("WARN", "EXISTING_LAB_LEGACY_NAMES") in got and ("WARN", "VOLUMES_NOT_ADOPTED") in got
    assert facts["volume_prefixes"] == ["agentseclab"] and "agentsec_splunk" in facts["legacy_containers"]
    assert {c[0] for c in env.calls} <= READ_ONLY_CALLS
    msg = next(x.message for x in f if x.code == "EXISTING_LAB_LEGACY_NAMES")
    assert "will not be stopped, renamed or recreated" in msg


def test_legacy_adoption_requires_the_existing_project_name_and_never_creates_empty_volumes_silently():
    env = FakeEnv(**LEGACY_LAB)
    assert ("OK", "LEGACY_ADOPT") in run(cfgd(naming="legacy", project="agentseclab"), env)[0]
    got, f, *_ = run(cfgd(naming="legacy", project="other"), env)
    assert ("ERROR", "LEGACY_PROJECT_MISMATCH") in got and "never deleted" in next(x.message for x in f if x.code == "LEGACY_PROJECT_MISMATCH")
    assert ("ERROR", "LEGACY_NOTHING_TO_ADOPT") in run(cfgd(naming="legacy"), FakeEnv())[0]


# ---- Ollama and Splunk reachability and files --------------------------------------------------------------------------------------------------
def test_ollama_version_floor_and_reachability():
    host = cfgd(ollama={"mode": "host"})
    assert ("ERROR", "OLLAMA_TOO_OLD") in run(host, FakeEnv(ollama={"http://127.0.0.1:11434": "0.34.2"}))[0]
    assert ("OK", "OLLAMA_VERSION") in run(host, FakeEnv(ollama={"http://127.0.0.1:11434": "0.40.12"}))[0]
    assert ("WARN", "OLLAMA_UNREACHABLE") in run(host, FakeEnv())[0]
    remote = cfgd(ollama={"mode": "remote", "url": "https://o.example.org"})
    e = FakeEnv(ollama={"https://o.example.org": "0.1.46"})
    run(remote, e)
    assert not any(c[0].startswith("ollama") for c in e.calls)      # a refused remote endpoint is never contacted


def test_external_splunk_files_are_checked_read_only():
    ext = cfgd(splunk={"mode": "external_enterprise", "rest_url": "https://s.example.org:8089", "token_file": "/t/token", "ca_file": "/t/ca.pem"})
    got = run(ext, FakeEnv())[0]
    assert ("ERROR", "SPLUNK_CA_MISSING") in got and ("ERROR", "SPLUNK_TOKEN_MISSING") in got
    files = {"/t/token": {"exists": True, "mode": 0o644, "size": 40, "is_file": True}, "/t/ca.pem": {"exists": True, "mode": 0o644, "size": 900, "is_file": True}}
    got2 = run(ext, FakeEnv(paths=files))[0]
    assert ("WARN", "SPLUNK_TOKEN_PERMISSIONS") in got2 and not [x for x in got2 if x[0] == "ERROR"]
    files["/t/token"]["mode"] = 0o600
    assert ("WARN", "SPLUNK_TOKEN_PERMISSIONS") not in run(ext, FakeEnv(paths=files))[0]


def test_splunk_10_6_needs_avx():
    c = cfgd(splunk={"version": "10.6"}, allow_candidate_images=True)
    assert ("ERROR", "SPLUNK_NEEDS_AVX") in run(c, FakeEnv(avx=False))[0]
    assert ("ERROR", "SPLUNK_NEEDS_AVX") not in run(c, FakeEnv(avx=None))[0]       # unknown (macOS, emulation): not guessed


def test_published_port_ranges_count_port_by_port():
    """A running install's own collector shows '127.0.0.1:4317-4318->4317-4318/tcp'; reading only single ports made a re-install refuse it as 'in use'."""
    from agentsec.installer.preflight import published_ports
    ps = "8065/tcp, 127.0.0.1:8088->8088/tcp, 127.0.0.1:18000->8000/tcp, 127.0.0.1:4317-4318->4317-4318/tcp, 55678-55679/tcp, [::]:443->8443/tcp"
    assert published_ports(ps) == [443, 4317, 4318, 8088, 18000]
    assert published_ports("") == [] and published_ports("5001/tcp") == []
    assert published_ports("127.0.0.1:1-99999->1/tcp") == list(range(1, 66))      # bounded
