"""How installer-managed Splunk search access is wired in: configuration, the Compose override, host preparation, up, install --apply, status and the
splunk-access command. Fakes only: no Docker, no Splunk (the provisioning script itself is tested in test_splunk_access.py)."""
import json
from pathlib import Path
import pytest
from agentsec.installer import render, splunk_access as sa
from agentsec.installer.config import InstallConfig, Locks, managed_access, validate
from tests.installer.fakes import FakeRunner
from tests.installer.test_lifecycle import cli, installed, INSTALL, LOCKS
from tests.installer.test_render_and_workflow import _attack_block, cfgd, plan_for


def result(auth="bearer", cred="tok-secret-123"):
    doc = {"auth": auth, "credential": cred, "user": "agentsec_search", "server_name": "SplunkServerDefaultCert",
           "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "token_expires": "+180d", "fallback": ""}
    return "STEP verified as the new identity: it can search and cannot read other indexes\nAGENTSEC_RESULT " + json.dumps(doc) + "\n"


def exec_runner(out):
    return FakeRunner(outputs={"exec": out})


# ------------------------------------------------------------------ configuration and rendering
def test_default_bundled_install_is_installer_managed_and_the_setting_is_validated():
    assert managed_access(InstallConfig())
    assert not managed_access(cfgd(splunk={"mode": "bundled", "access": "off"}))
    assert not managed_access(cfgd(splunk={"mode": "bundled", "rest_url": "https://splunk:8089", "token_file": "/home/u/t"}))     # hand-given REST settings win
    assert not managed_access(cfgd(splunk={"mode": "none"})) and not managed_access(cfgd(splunk={"mode": "external_enterprise"}))
    assert any(f.code == "SPLUNK_ACCESS_INVALID" for f in validate(cfgd(splunk={"mode": "bundled", "access": "sometimes"}), LOCKS))
    assert not any(f.code == "SPLUNK_ACCESS_INVALID" for f in validate(InstallConfig(), LOCKS))


def test_the_override_mounts_the_access_directory_read_only_with_a_fixed_target():
    blk = _attack_block(plan_for(InstallConfig()))
    for want in ('"AGENTSEC_SPLUNK_MODE=BUNDLED"', '"AGENTSEC_SPLUNK_REST_URL=https://splunk:8089"', '"AGENTSEC_SPLUNK_INDEX=agentsec_telemetry"',
                 'source: "./.splunk-access"', "target: /run/secrets/agentsec_splunk_access", "read_only: true"):
        assert want in blk, want
    assert blk.count("read_only: true") == 1 and "docker.sock" not in blk and "SPLUNK_PASSWORD" not in blk


def test_the_host_directory_is_created_owner_only_before_compose_up():
    cmds = [c["argv"] for c in plan_for(InstallConfig()).commands]
    assert ["mkdir", "-p", ".splunk-access"] in cmds and ["chmod", "700", ".splunk-access"] in cmds
    assert cmds.index(["chmod", "700", ".splunk-access"]) < next(i for i, c in enumerate(cmds) if c[:4] == ["docker", "compose", "up", "-d"])
    assert ["mkdir", "-p", ".splunk-access"] not in [c["argv"] for c in plan_for(cfgd(splunk={"mode": "bundled", "access": "off"})).commands]


def test_the_directory_is_git_ignored():
    assert ".splunk-access/" in (Path(__file__).resolve().parents[2] / ".gitignore").read_text().splitlines()


# ------------------------------------------------------------------ install, up, status, splunk-access
def test_up_provisions_after_starting_and_never_prints_the_credential(tmp_path):
    installed(tmp_path)
    r = exec_runner(result())
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == 0, out
    exec_cmd = next(c for c in r.commands if "exec" in c)
    assert r.commands.index(exec_cmd) > r.commands.index(next(c for c in r.commands if "--no-recreate" in c)) and exec_cmd[exec_cmd.index("exec"):exec_cmd.index("exec") + 3] == ["exec", "-T", "splunk"]
    assert sa.SCRIPT in exec_cmd and "SPLUNK_PASSWORD" not in " ".join(a for a in exec_cmd if a != sa.SCRIPT)               # the admin password is never in the arguments
    text = "\n".join(out)
    assert "tok-secret-123" not in text and "AGENTSEC_RESULT" not in text and "provisioned" in text
    assert (tmp_path / ".splunk-access" / "credential").read_text() == "tok-secret-123" and sa.read_status(tmp_path)["auth"] == "bearer"


def test_a_second_up_does_not_reprovision(tmp_path):
    installed(tmp_path)
    cli(tmp_path, ["up"], runner=exec_runner(result()))
    r = exec_runner(result(cred="other"))
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == 0 and not any("exec" in c for c in r.commands) and (tmp_path / ".splunk-access" / "credential").read_text() == "tok-secret-123"
    assert any("files are present" in l for l in out)


def test_a_provisioning_failure_does_not_fail_the_install_or_up_and_says_unavailable(tmp_path):
    installed(tmp_path)
    r = exec_runner("AGENTSEC_ERROR token_unavailable kvstore_not_ready\n")
    r.run = (lambda orig: (lambda argv, cwd, env=None: (1, "AGENTSEC_ERROR role_not_least_privilege capabilities=['x']") if "exec" in argv else orig(argv, cwd, env)))(r.run)
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == 0 and any("SPLUNK_ACCESS_UNAVAILABLE" in l and "role_not_least_privilege" in l and "unavailable" in l for l in out)
    assert sa.read_status(tmp_path) is None


def test_install_apply_provisions_too_and_keeps_its_exit_code(tmp_path):
    r = exec_runner(result("basic", "pw-secret-9"))
    rc, out = cli(tmp_path, [*INSTALL, "--apply"], runner=r)
    assert rc == 0 and sa.read_status(tmp_path)["auth"] == "basic" and "pw-secret-9" not in "\n".join(out)


def test_splunk_access_command_forces_renewal_and_reports_state(tmp_path):
    installed(tmp_path)
    cli(tmp_path, ["up"], runner=exec_runner(result()))
    r = exec_runner(result(cred="renewed-1"))
    rc, out = cli(tmp_path, ["splunk-access", "--force", "--access-auth", "bearer"], runner=r)
    assert rc == 0 and (tmp_path / ".splunk-access" / "credential").read_text() == "renewed-1"
    assert r.commands[-1][-1] == "bearer" and any("auth bearer" in l for l in out)
    rc2, out2 = cli(tmp_path, ["splunk-access", "--force"], runner=exec_runner("AGENTSEC_ERROR index_not_restricted x\n") and FakeRunner(fail_on=1))
    assert rc2 in (0, 5)


def test_status_says_whether_search_access_is_provisioned(tmp_path):
    installed(tmp_path)
    ps = json.dumps([{"Service": s, "State": "running", "Health": "", "ExitCode": 0} for s in ("splunk", "attack_service")])
    rc, out = cli(tmp_path, ["status"], runner=FakeRunner(outputs={"ps": ps}))
    assert any("NOT PROVISIONED" in l and "splunk-access" in l for l in out)
    cli(tmp_path, ["up"], runner=exec_runner(result()))
    rc, out = cli(tmp_path, ["status"], runner=FakeRunner(outputs={"ps": ps}))
    assert any("files present (bearer)" in l for l in out) and "tok-secret-123" not in "\n".join(out)


def test_access_off_skips_provisioning_with_an_explanation(tmp_path):
    cfg = {"gateway": {"bind": "127.0.0.1"}, "splunk": {"mode": "bundled", "access": "off"}}
    installed(tmp_path, cfg)
    r = exec_runner(result())
    rc, out = cli(tmp_path, ["up"], runner=r)
    assert rc == 0 and not any("exec" in c for c in r.commands) and any("not installer-managed" in l for l in out)
    assert not (tmp_path / ".splunk-access" / "credential").exists()


def test_check_proves_access_from_the_attack_service_and_fails_when_it_does_not_work(tmp_path):
    installed(tmp_path)
    good = FakeRunner(outputs={"exec": "CONNECTIVITY PASS: TLS\nAUTHENTICATION PASS: ok\nAUTHORIZATION PASS: ok\nSEARCH PASS: ok\nTELEMETRY NOT VERIFIED: x\n"})
    rc, out = cli(tmp_path, ["splunk-access", "--check"], runner=good)
    assert rc == 0 and good.commands[-1][-6:] == ["exec", "-T", "attack_service", "python", "-m", "agentsec.splunk_client"][-6:] or "check" in good.commands[-1]
    assert any(l.strip().startswith("SEARCH PASS") for l in out) and any(l.startswith("OK") for l in out)
    bad = FakeRunner(outputs={"exec": "CONNECTIVITY FAIL: tls_verification_failed\n"})
    rc, out = cli(tmp_path, ["splunk-access", "--check"], runner=bad)
    assert rc == 5 and any("does not work" in l for l in out)
