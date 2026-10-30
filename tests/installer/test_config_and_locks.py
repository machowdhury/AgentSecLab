import json
from pathlib import Path
import pytest
from agentsec import model_names
from agentsec.installer import config as C
from agentsec.installer.config import ConfigError, InstallConfig, Locks, validate

LOCKS = Locks.load()
ROOT = Path(__file__).resolve().parents[2]


def codes(cfg, level=None):
    return {(f.level, f.code) for f in validate(cfg, LOCKS) if level is None or f.level == level}


def cfg(**kw):
    d = {"gateway": {"bind": "127.0.0.1"}}
    for k, v in kw.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            d[k].update(v)
        else:
            d[k] = v
    return InstallConfig.from_dict(d)


def test_the_default_configuration_is_valid_with_only_warnings():
    f = validate(InstallConfig(), LOCKS)
    assert not [x for x in f if x.level == "ERROR"], f
    assert {x.code for x in f if x.level == "WARN"} >= {"OLLAMA_FLOATING_TAG", "MODEL_DIGEST_NOT_PINNED"}      # honest about what is not pinned yet


@pytest.mark.parametrize("bad", [{"nope": 1}, {"gateway": {"nope": 1}}, {"ports": {"splunk": 1}}, {"gateway": "x"}, {"gateway": {"port": "443"}}, {"gateway": {"enabled": "yes"}},
                                 {"project": 5}, {"models": {"other": "x"}}, {"models": []}, "text", [], {"ack_external_controls": 1}, {"gateway": {"port": True}}])
def test_malformed_configuration_is_refused_with_a_message_and_no_value_echo(bad):
    with pytest.raises(ConfigError) as e:
        InstallConfig.from_dict(bad)
    assert "text" != str(e.value)


def test_loading_the_same_data_twice_gives_the_same_configuration():
    d = InstallConfig(project="lab2").to_dict()
    assert InstallConfig.from_dict(d) == InstallConfig.from_dict(json.loads(json.dumps(d)))


# ---- access control: localhost default, organization needs the acknowledgement -----------------------------------------------------------------
def test_localhost_mode_refuses_any_non_loopback_bind():
    for bind in ("0.0.0.0", "10.1.2.3", "::"):
        assert ("ERROR", "BIND_NOT_LOOPBACK") in codes(cfg(gateway={"bind": bind}))
    assert ("ERROR", "BIND_INVALID") in codes(cfg(gateway={"bind": "example.org"}))                  # a publish address must be an IP
    for bind in ("127.0.0.1", "::1", "localhost"):
        assert ("ERROR", "BIND_NOT_LOOPBACK") not in codes(cfg(gateway={"bind": bind}))


def test_organization_mode_needs_the_explicit_acknowledgement():
    c = cfg(deployment="organization", gateway={"bind": "0.0.0.0"})
    assert ("ERROR", "ORG_ACK_REQUIRED") in codes(c)
    msg = next(f.message for f in validate(c, LOCKS) if f.code == "ORG_ACK_REQUIRED")
    assert "NO failed-login throttling" in msg and "public internet" in msg and "unsupported" in msg
    ok = codes(cfg(deployment="organization", ack_external_controls=True, gateway={"bind": "0.0.0.0"}))
    assert ("ERROR", "ORG_ACK_REQUIRED") not in ok and ("WARN", "ORG_BIND_ALL_INTERFACES") in ok and not {x for x in ok if x[0] == "ERROR"}


def test_the_acknowledgement_does_not_unlock_a_non_loopback_bind_in_localhost_mode():
    assert ("ERROR", "BIND_NOT_LOOPBACK") in codes(cfg(ack_external_controls=True, gateway={"bind": "0.0.0.0"}))
    assert ("WARN", "ACK_NOT_NEEDED") in codes(cfg(ack_external_controls=True))


def test_organization_mode_without_the_lab_gateway_is_flagged():
    assert ("WARN", "ORG_WITHOUT_GATEWAY") in codes(cfg(deployment="organization", ack_external_controls=True, gateway={"enabled": False, "bind": "0.0.0.0"}))


# ---- gateway, ports, project --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("port,level,code", [(443, None, None), (8000, None, None), (9443, "WARN", "GATEWAY_PORT_NONSTANDARD"), (5000, "ERROR", "GATEWAY_PORT_RESERVED"),
                                              (8088, "ERROR", "GATEWAY_PORT_RESERVED"), (0, "ERROR", "GATEWAY_PORT_INVALID"), (70000, "ERROR", "GATEWAY_PORT_INVALID")])
def test_gateway_port_rules(port, level, code):
    got = codes(cfg(gateway={"port": port}))
    if code:
        assert (level, code) in got
    else:
        assert not {x for x in got if x[1].startswith("GATEWAY_PORT")}


@pytest.mark.parametrize("host", ["", "has space", "*.example.org", "http://x", "a:8000", "x" * 300])
def test_gateway_host_must_be_a_dns_name(host):
    assert ("ERROR", "GATEWAY_HOST_INVALID") in codes(cfg(gateway={"host": host}))


@pytest.mark.parametrize("name,ok", [("agentsec", True), ("lab2", True), ("a-b_c", True), ("A", False), ("1lab", False), ("a", False), ("lab space", False), ("x" * 40, False), ("", False), ("lab/../x", False)])
def test_project_name_rules(name, ok):
    assert (("ERROR", "PROJECT_INVALID") in codes(cfg(project=name))) is (not ok)


def test_colliding_or_invalid_internal_ports_are_errors():
    assert ("ERROR", "PORTS_COLLIDE") in codes(cfg(ports={"acmebank": 5001}))
    assert ("ERROR", "PORT_INVALID") in codes(cfg(ports={"hec": 99999}))


# ---- Ollama ---------------------------------------------------------------------------------------------------------------------------------------
def test_remote_ollama_is_refused_fail_closed():
    assert ("ERROR", "OLLAMA_REMOTE_NOT_HTTPS") in codes(cfg(ollama={"mode": "remote", "url": "http://10.0.0.5:11434"}))
    assert ("ERROR", "OLLAMA_REMOTE_NOT_HTTPS") in codes(cfg(ollama={"mode": "remote", "url": ""}))
    ok = codes(cfg(ollama={"mode": "remote", "url": "https://ollama.example.org"}))
    assert ("ERROR", "OLLAMA_REMOTE_UNSUPPORTED") in ok      # fail closed: https alone is not enough while the client cannot authenticate
    assert ("WARN", "OLLAMA_URL_IGNORED") in codes(cfg(ollama={"mode": "host", "url": "https://x"}))
    assert ("ERROR", "OLLAMA_MODE_INVALID") in codes(cfg(ollama={"mode": "cloud"}))


# ---- images: digests, versions, candidates ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("v", ["10.1", "10.3", "10.5", "10.7"])
def test_unreleased_splunk_versions_are_refused(v):
    assert ("ERROR", "SPLUNK_VERSION_NOT_RELEASED") in codes(cfg(splunk={"version": v}))


def test_unknown_and_unqualified_splunk_versions():
    assert ("ERROR", "SPLUNK_VERSION_UNKNOWN") in codes(cfg(splunk={"version": "9.4"}))
    for v in ("10.4", "10.6"):
        assert ("ERROR", "SPLUNK_VERSION_NOT_QUALIFIED") in codes(cfg(splunk={"version": v}))
        c = codes(cfg(splunk={"version": v}, allow_candidate_images=True))
        assert ("WARN", "SPLUNK_CANDIDATE_IMAGE") in c and ("ERROR", "SPLUNK_VERSION_NOT_QUALIFIED") not in c


def test_the_tested_splunk_default_is_pinned_by_digest_and_the_reference_carries_it():
    ref, entry, fs = C.splunk_image(InstallConfig(), LOCKS)
    assert ref == "splunk/splunk@" + entry["digest"] and C.DIGEST_RE.match(entry["digest"]) and not [f for f in fs if f.level != "INFO"]


def test_require_digests_refuses_a_floating_tag_and_default_only_warns():
    assert ("WARN", "OLLAMA_FLOATING_TAG") in codes(InstallConfig())
    assert ("ERROR", "OLLAMA_FLOATING_TAG") in codes(cfg(require_digests=True))
    assert ("ERROR", "OLLAMA_FLOATING_TAG") not in codes(cfg(require_digests=True, ollama={"mode": "host"}))      # no Ollama image is used


def test_a_malformed_pinned_digest_is_an_error():
    bad = Locks(json.loads(json.dumps(LOCKS.images)), LOCKS.models)
    bad.images["splunk"]["versions"]["10.2"]["digest"] = "sha256:XYZ"
    assert any(f.code == "SPLUNK_DIGEST_INVALID" for f in C.splunk_image(InstallConfig(), bad)[2])


# ---- models ------------------------------------------------------------------------------------------------------------------------------------------
def test_model_selection_rules():
    assert ("ERROR", "MODEL_NAME_INVALID") in codes(cfg(models={"pipeline": "bad name"}))
    assert ("ERROR", "MODEL_NOT_IN_LOCK") in codes(cfg(models={"pipeline": "unlisted:1b"}))
    c = codes(cfg(models={"pipeline": "unlisted:1b"}, allow_unpinned_model=True))
    assert ("WARN", "MODEL_NOT_IN_LOCK") in c and ("ERROR", "MODEL_NOT_IN_LOCK") not in c
    pinned = C.resolve_models(cfg(models={"loan_desk": "llama3.2:latest"}), LOCKS)[1]
    assert not [f for f in pinned if f.code == "MODEL_DIGEST_NOT_PINNED" and "loan_desk" in f.message]          # the locked Loan Desk model has a digest
    assert C.resolve_models(InstallConfig(), LOCKS)[0] == {"pipeline": "llama3.2:1b", "loan_desk": "llama3.2:latest"}


# ---- external Splunk (reuses the strict client's own validator) -------------------------------------------------------------------------------
def test_external_splunk_is_validated_by_the_clients_own_rules():
    base = {"mode": "external_enterprise", "rest_url": "https://splunk.example.org:8089", "token_file": "/etc/agentsec/token", "ca_file": "/etc/agentsec/ca.pem"}
    assert not {x for x in codes(cfg(splunk=base)) if x[0] == "ERROR"}
    for bad_url in ("http://splunk.example.org:8089", "https://u:p@splunk.example.org:8089", "https://splunk.example.org:8089/x", "https://splunk.example.org:abc", ""):
        assert any(x[0] == "ERROR" for x in codes(cfg(splunk={**base, "rest_url": bad_url}))), bad_url
    assert ("ERROR", "SPLUNK_TOKEN_FILE_NOT_ABSOLUTE") in codes(cfg(splunk={**base, "token_file": "token"}))


# ---- the lock files ----------------------------------------------------------------------------------------------------------------------------
def test_lock_files_are_consistent_with_the_code():
    assert {r: d for r, (_, d) in model_names.ROLES.items()} == LOCKS.models["roles"]
    for name in LOCKS.models["models"]:
        model_names.normalize(name)
    for key, e in LOCKS.images["splunk"]["versions"].items():
        assert key not in LOCKS.images["splunk"]["not_released"] and (e["digest"] is None or C.DIGEST_RE.match(e["digest"]))
        assert e["status"] in ("tested", "candidate")
    assert LOCKS.images["splunk"]["versions"][LOCKS.images["splunk"]["default"]]["status"] == "tested"
    assert LOCKS.images["splunk"]["not_released"] == ["10.1", "10.3", "10.5", "10.7"]
    assert all(m.get("digest") is None or C.DIGEST_RE.match(m["digest"]) for m in LOCKS.models["models"].values())


def test_the_installer_modules_import_with_only_the_standard_library():
    import subprocess, sys
    code = ("import sys; sys.modules['requests'] = None; sys.modules['flask'] = None; sys.path.insert(0, %r);"
            "import agentsec.installer.cli, agentsec.installer.provenance, agentsec.installer.render") % str(ROOT / "src")
    assert subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).returncode == 0
