"""`agentsec up` applies the CTF overlay itself, and the CTF secret has exactly one reader: the unprivileged installing user. No Docker."""
import os, re
from pathlib import Path
from types import SimpleNamespace
import pytest
from agentsec.installer import render
from agentsec.installer.config import InstallConfig, Locks, validate
from agentsec.installer.lifecycle import ctf_findings
from tests.installer.test_render_and_workflow import cfgd, envmap, plan_for

LOCKS = Locks.load()
REPO = Path(__file__).resolve().parents[2]


def test_ctf_off_by_default_and_on_adds_the_overlay_and_the_runtime_identity():
    base = envmap(plan_for(cfgd()))
    assert "docker-compose.gateway-ctf.yml" not in base["COMPOSE_FILE"] and "AGENTSEC_CTF_UID" not in base
    on = envmap(plan_for(cfgd(gateway={"ctf": True})))
    files = on["COMPOSE_FILE"].split(":")
    assert files.index("docker-compose.gateway.yml") < files.index("docker-compose.gateway-ctf.yml") < files.index(".agentsec/compose.override.yml")
    assert (on["AGENTSEC_CTF_UID"], on["AGENTSEC_CTF_GID"]) == (str(os.getuid()), str(os.getgid()))
    assert on["AGENTSEC_CTF_GATEWAY"] == "enabled" and on["AGENTSEC_CTF_SECRET_FILE"].startswith("./") and on["AGENTSEC_CTF_STATE_HOST"].startswith("./")


def test_prestart_enables_the_ctf_secret_after_gateway_init_and_only_when_asked():
    argvs = lambda c, exists: [x["argv"][1:] for x in render.prestart_commands(c, exists) if x["argv"][0] == "sh"]
    assert ["scripts/gateway.sh", "ctf-enable"] not in argvs(cfgd(), False)
    on = argvs(cfgd(gateway={"ctf": True}), False)
    assert on.index(["scripts/gateway.sh", "ctf-enable"]) > [i for i, a in enumerate(on) if a[:2] == ["scripts/gateway.sh", "init"]][0]
    assert ["scripts/gateway.sh", "ctf-enable"] in argvs(cfgd(gateway={"ctf": True}), True)       # idempotent on every `up`


def test_ctf_without_the_gateway_is_refused():
    assert "CTF_NEEDS_GATEWAY" in [f.code for f in validate(cfgd(gateway={"enabled": False, "ctf": True}), LOCKS) if f.level == "ERROR"]


def _state(tmp_path, uid=None):
    uid = os.getuid() if uid is None else uid
    return SimpleNamespace(env={"AGENTSEC_CTF_UID": str(uid)})


def _lab(tmp_path):
    g = tmp_path / ".gateway"; g.mkdir(mode=0o700)
    (g / "ctf-gateway-secret").write_text("ab" * 32); (g / "ctf-secret.conf").write_text("set $gw_secret \"x\";\n"); (g / "ctf-state").mkdir(mode=0o700)
    for n in ("ctf-gateway-secret", "ctf-secret.conf"): (g / n).chmod(0o600)
    return g


def codes(tmp_path, **kw):
    return [f.code for f in ctf_findings(tmp_path, _state(tmp_path, **kw))]


@pytest.mark.skipif(os.getuid() == 0, reason="root is the refused case")
def test_a_correct_unprivileged_layout_has_no_findings(tmp_path):
    _lab(tmp_path)
    assert codes(tmp_path) == []


@pytest.mark.skipif(os.getuid() == 0, reason="root is the refused case")
@pytest.mark.parametrize("mutate,code", [
    (lambda g: (g / "ctf-gateway-secret").chmod(0o640), "CTF_SECRET_PERMISSIONS"),        # group-readable
    (lambda g: (g / "ctf-gateway-secret").chmod(0o644), "CTF_SECRET_PERMISSIONS"),        # world-readable
    (lambda g: (g / "ctf-state").chmod(0o755), "CTF_SECRET_PERMISSIONS"),
    (lambda g: (g / "ctf-gateway-secret").write_text("not hex"), "CTF_SECRET_FORMAT"),
    (lambda g: (g / "ctf-secret.conf").unlink(), "CTF_SECRET_MISSING"),
])
def test_incompatible_permissions_or_content_fail_closed(tmp_path, mutate, code):
    g = _lab(tmp_path); mutate(g)
    assert code in codes(tmp_path)


@pytest.mark.skipif(os.getuid() == 0, reason="symlink owner check")
def test_a_symlinked_secret_and_a_different_installing_uid_are_refused(tmp_path):
    g = _lab(tmp_path); real = tmp_path / "real"; real.write_text("ab" * 32); real.chmod(0o600)
    (g / "ctf-gateway-secret").unlink(); (g / "ctf-gateway-secret").symlink_to(real)
    assert "CTF_SECRET_PERMISSIONS" in codes(tmp_path)
    assert "CTF_UID_MISMATCH" in codes(tmp_path, uid=os.getuid() + 1)


def test_root_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    assert codes(tmp_path) == ["CTF_AS_ROOT"]


def test_overlay_runs_the_attack_service_as_the_installer_not_a_guessed_uid_and_keeps_state_on_the_host():
    o = (REPO / "docker-compose.gateway-ctf.yml").read_text()
    assert 'user: "${AGENTSEC_CTF_UID:?' in o and "${AGENTSEC_CTF_GID:?" in o and "1000" not in o
    assert "${AGENTSEC_CTF_STATE_HOST:?" in o and "ctf_state" not in o
