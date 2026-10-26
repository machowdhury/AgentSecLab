"""Static checks of the compose files (no containers are started): the gateway is strictly opt-in and removes host ports."""
import json, os, subprocess
import pytest
from gwhelpers import ROOT, needs_docker

pytestmark = needs_docker
BASE = ["docker", "compose", "-f", "docker-compose.yml"]
OVL = BASE + ["-f", "docker-compose.gateway.yml"]


def cfg(cmd, env=None, profiles=("local",)):
    args = cmd + [x for p in profiles for x in ("--profile", p)] + ["config", "--format", "json"]
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, env={**os.environ, **(env or {})})
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)["services"]


def pubs(svc):
    return sorted((f"{x.get('host_ip', '')}:{x['published']}->{x['target']}") for x in (svc.get("ports") or []))


def test_gateway_is_absent_from_the_base_compose_and_from_the_overlay_without_its_profile():
    base = cfg(BASE)
    assert "gateway" not in base
    assert "gateway" not in cfg(OVL)                          # overlay file alone does not start anything new
    assert set(cfg(OVL, profiles=("local", "gateway"))) == set(base) | {"gateway"}


def test_base_compose_is_untouched_by_the_gateway_work():
    if subprocess.run(["git", "rev-parse", "--verify", "-q", "origin/main"], cwd=ROOT, capture_output=True).returncode != 0:
        pytest.skip("origin/main not available")
    out = subprocess.run(["git", "diff", "--stat", "origin/main", "--", "docker-compose.yml", "docker-compose.local.yml"], cwd=ROOT, capture_output=True, text=True).stdout
    assert out.strip() == ""


def test_with_the_gateway_only_it_publishes_the_learner_facing_port():
    base, gw = cfg(BASE), cfg(OVL, profiles=("local", "gateway"))
    assert pubs(gw["attack_service"]) == [] and pubs(gw["acmebank"]) == []
    assert pubs(base["attack_service"]) != [] and pubs(base["acmebank"]) != []     # the overlay is what removes them
    assert pubs(gw["gateway"]) == ["127.0.0.1:443->8443"]
    for name in set(base) - {"attack_service", "acmebank"}:
        assert pubs(gw[name]) == pubs(base[name]), name           # splunk, collector, ollama keep their base bindings (loopback)


def test_https_port_and_bind_address_are_configurable():
    gw = cfg(OVL, env={"AGENTSEC_HTTPS_PORT": "8443", "AGENTSEC_GATEWAY_BIND": "10.1.2.3"}, profiles=("gateway",))
    assert pubs(gw["gateway"]) == ["10.1.2.3:8443->8443"]


def test_gateway_container_mounts_are_read_only_and_not_the_docker_socket():
    vols = cfg(OVL, profiles=("gateway",))["gateway"]["volumes"]
    assert all(v.get("read_only") for v in vols) and not any("docker.sock" in v["source"] for v in vols)
    assert {v["target"] for v in vols} >= {"/certs/server.pem", "/certs/server.key", "/etc/nginx/htpasswd"}


def test_no_service_other_than_the_gateway_gains_privileges_or_networks():
    base, gw = cfg(BASE), cfg(OVL, profiles=("local", "gateway"))
    for name in base:
        assert gw[name].get("networks") == base[name].get("networks") and gw[name].get("privileged") == base[name].get("privileged"), name
    assert list(gw["gateway"]["networks"]) == ["agentsec_mesh"]
