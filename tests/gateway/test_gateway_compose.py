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


def published(services):
    return [(name, x.get("host_ip", ""), int(x["published"]), x["target"]) for name, svc in services.items() for x in (svc.get("ports") or [])]


@pytest.mark.parametrize("port", ["443", "8000"])
def test_exactly_one_externally_reachable_port_in_the_fully_rendered_compose(port):
    """Fully rendered config (base + overlay, every profile), gateway bound to all interfaces as on a server, legacy remote bind also set."""
    env = {"AGENTSEC_PUBLIC_PORT": port, "AGENTSEC_GATEWAY_BIND": "0.0.0.0", "AGENTSEC_BIND_ADDRESS": "0.0.0.0"}
    gw = cfg(OVL, env=env, profiles=("local", "gateway"))
    pubs_ = published(gw)
    external = [p for p in pubs_ if p[1] not in ("127.0.0.1", "::1")]
    assert external == [("gateway", "0.0.0.0", int(port), 8443)], external
    internal_only = {name for name in gw if name not in {"gateway"}}
    assert {p[0] for p in pubs_} - {"gateway"} <= {"splunk", "otel_collector"}            # nothing else publishes anything
    for name, host_ip, _, _ in pubs_:
        if name != "gateway": assert host_ip == "127.0.0.1", (name, host_ip)           # Splunk, HEC, OTel: host loopback only
    assert len({p[2] for p in pubs_}) == len(pubs_), "two services publish the same host port"
    splunk_web = [p for p in pubs_ if p[0] == "splunk" and p[3] == 8000]
    assert splunk_web == [("splunk", "127.0.0.1", 18000, 8000)]                            # Splunk Web never on the public port, even for 8000
    assert not [p for p in pubs_ if p[0] in ("attack_service", "acmebank", "ollama")]


def test_without_the_overlay_splunk_web_would_collide_with_public_port_8000():
    base = published(cfg(BASE))
    assert ("splunk", "127.0.0.1", 8000, 8000) in base       # why the overlay must move it


def test_public_port_takes_precedence_over_the_older_alias():
    gw = cfg(OVL, env={"AGENTSEC_PUBLIC_PORT": "8000", "AGENTSEC_HTTPS_PORT": "9999"}, profiles=("gateway",))
    assert pubs(gw["gateway"]) == ["127.0.0.1:8000->8443"]


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


@pytest.mark.parametrize("env,port", [({}, "443"), ({"AGENTSEC_PUBLIC_PORT": "8000"}, "8000"), ({"AGENTSEC_HTTPS_PORT": "18543"}, "18543")])
def test_the_gateway_is_told_its_public_port_with_the_same_precedence_as_the_published_port(env, port):
    """The Host the backends receive carries this port (their same-origin check compares it with the browser's Origin), so it must agree with the mapping."""
    gw = cfg(OVL, env=env, profiles=("gateway",))["gateway"]
    assert gw["environment"]["AGENTSEC_PUBLIC_PORT"] == port
    assert [p for p in gw["ports"] if p["target"] == 8443][0]["published"] == port


def test_the_gateway_builds_host_from_configuration_not_from_the_client():
    t = (ROOT / "gateway/templates/gateway.conf.template").read_text()
    assert "proxy_set_header Host $host$authority_port;" in t and "proxy_set_header Host $host;" not in t
    assert 'map "${AGENTSEC_PUBLIC_PORT}" $authority_port' in t and "return 421" in t
    assert "X-Forwarded-Host" not in t and "$http_x_forwarded" not in t       # no client forwarding header is ever consulted


def test_only_the_attack_service_is_told_it_is_behind_the_gateway():
    base, gw = cfg(BASE), cfg(OVL, profiles=("local", "gateway"))
    assert "AGENTSEC_GATEWAY_MODE" not in (base["attack_service"].get("environment") or {})
    assert gw["attack_service"]["environment"]["AGENTSEC_GATEWAY_MODE"] == "1"
    assert all("AGENTSEC_GATEWAY_MODE" not in (gw[n].get("environment") or {}) for n in gw if n not in ("attack_service",))
