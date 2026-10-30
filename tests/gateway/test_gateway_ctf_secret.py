"""gateway.sh ctf-enable secret handling (no docker, no nginx): format, permissions, refusal of hand-edited or symlinked material."""
import os, re, shutil, stat, subprocess
from pathlib import Path
import pytest
from gwhelpers import ROOT

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl needed")


def enable(gdir: Path):
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "AGENTSEC_GATEWAY_DIR": str(gdir), "HOME": str(gdir.parent)}
    return subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "ctf-enable"], capture_output=True, text=True, env=env, cwd=ROOT)


def test_secret_is_64_hex_owner_only_and_never_printed(tmp_path):
    g = tmp_path / "g"; g.mkdir()
    p = enable(g)
    assert p.returncode == 0, p.stdout + p.stderr
    secret = (g / "ctf-gateway-secret").read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", secret) and secret not in p.stdout + p.stderr
    for f in ("ctf-gateway-secret", "ctf-secret.conf"):
        assert stat.S_IMODE((g / f).stat().st_mode) == 0o600
    assert (g / "ctf-secret.conf").read_text() == f'set $gw_secret "{secret}";\nauth_request_set $gw_secret "{secret}";\n'
    assert secret not in (g / "gateway.env").read_text()
    again = enable(g)
    assert again.returncode == 0 and (g / "ctf-gateway-secret").read_text().strip() == secret      # idempotent: the secret is kept


@pytest.mark.parametrize("bad", ['abc";\nset $x 1', "short", "G" * 64, "a" * 63, "a" * 65])
def test_a_hand_edited_secret_is_refused_before_it_reaches_nginx_syntax(tmp_path, bad):
    g = tmp_path / "g"; g.mkdir()
    (g / "ctf-gateway-secret").write_text(bad + "\n")
    p = enable(g)
    assert p.returncode != 0 and "64 hex" in p.stdout + p.stderr and not (g / "ctf-secret.conf").exists()


def test_symlinked_secret_material_is_refused(tmp_path):
    g = tmp_path / "g"; g.mkdir()
    target = tmp_path / "elsewhere"; target.write_text("x")
    os.symlink(target, g / "ctf-secret.conf")
    p = enable(g)
    assert p.returncode != 0 and "symbolic link" in p.stdout + p.stderr and target.read_text() == "x"


def test_ctf_state_is_a_host_directory_of_the_installing_user_and_the_overlay_does_not_guess_a_uid():
    """Disposable-host run: the ledger sat in the container layer and a down/up zeroed the scoreboard; a root-owned secret was unreadable by a guessed uid 1000."""
    ovl = (ROOT / "docker-compose.gateway-ctf.yml").read_text()
    assert "${AGENTSEC_CTF_STATE_HOST:?" in ovl and "AGENTSEC_CTF_STATE_DIR=/var/lib/agentsec-ctf" in ovl and 'user: "${AGENTSEC_CTF_UID:?' in ovl
    assert "1000" not in ovl


@pytest.mark.skipif(os.getuid() == 0, reason="unprivileged-user case")
def test_ctf_enable_creates_a_0700_state_dir_and_refuses_a_group_readable_secret(tmp_path):
    g = tmp_path / "g"; env = {**os.environ, "AGENTSEC_GATEWAY_DIR": str(g)}; g.mkdir()
    run = lambda: subprocess.run(["sh", str(ROOT / "scripts/gateway.sh"), "ctf-enable"], capture_output=True, text=True, env=env, cwd=ROOT)
    assert run().returncode == 0 and stat.S_IMODE((g / "ctf-state").stat().st_mode) == 0o700
    (g / "ctf-gateway-secret").chmod(0o640)
    bad = run(); assert bad.returncode != 0 and "mode 0600" in bad.stdout
    (g / "ctf-gateway-secret").chmod(0o600); assert run().returncode == 0
