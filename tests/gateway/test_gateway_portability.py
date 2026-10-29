"""Portability contract: the gateway uses only portable Docker Compose features and no cloud-provider service.
These are static and syntax checks plus a shell-syntax check under Debian dash and Alpine busybox. They do NOT replace running on
those platforms: only the platform this repository's tests actually ran on (see docs/GATEWAY.md) may be called runtime-tested."""
import re, subprocess
from pathlib import Path
import pytest
from gwhelpers import ROOT, needs_docker

FILES = ["docker-compose.gateway.yml", "gateway/templates/gateway.conf.template", "gateway/attack-enabled.conf", "gateway/attack-disabled.conf", "gateway/identity-headers.conf", "gateway/ctf-enabled.conf", "gateway/ctf-disabled.conf", "docker-compose.gateway-ctf.yml",
         "scripts/gateway.sh", "scripts/gateway-ready.sh", "src/agentsec/gateway_config.py"]
PROVIDER = re.compile(r"amazonaws|\baws\b|\bec2\b|\bssm\b|\bsts\b|azure|windows\.net|googleapis|\bgcp\b|gcloud|metadata\.google|169\.254\.169\.254|instance-id|cloud-init", re.I)
NONPORTABLE = re.compile(r"network_mode:\s*host|privileged:\s*true|docker\.sock|host\.docker\.internal|cap_add|pid:\s*host|userns_mode|runtime:\s*nvidia|extra_hosts", re.I)


@pytest.mark.parametrize("rel", FILES)
def test_no_provider_specific_service_or_non_portable_container_feature(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert not PROVIDER.search(text), PROVIDER.search(text).group(0)
    assert not NONPORTABLE.search(text), NONPORTABLE.search(text).group(0)


def test_images_are_public_multi_platform_and_pinned():
    text = (ROOT / "docker-compose.gateway.yml").read_text(encoding="utf-8")
    assert re.findall(r"image:\s*(\S+)", text) == ["nginx:1.27-alpine"]            # official multi-arch image (amd64 and arm64), version pinned


def test_scripts_use_posix_sh():
    for rel in ("scripts/gateway.sh", "scripts/gateway-ready.sh"):
        first = (ROOT / rel).read_text(encoding="utf-8").splitlines()[0]
        assert first == "#!/bin/sh", rel
        assert "[[" not in (ROOT / rel).read_text(encoding="utf-8")


@needs_docker
@pytest.mark.parametrize("image", ["debian:bookworm-slim", "python:3.12-alpine"])    # Debian dash and Alpine busybox ash
def test_shell_syntax_under_linux_shells(image):
    have = subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
    if not have:
        pytest.skip(f"{image} not present locally (not pulled by this test)")
    for script in ("gateway.sh", "gateway-ready.sh"):
        p = subprocess.run(["docker", "run", "--rm", "-v", f"{ROOT}/scripts:/s:ro", image, "sh", "-n", f"/s/{script}"], capture_output=True, text=True)
        assert p.returncode == 0, (image, script, p.stderr)
