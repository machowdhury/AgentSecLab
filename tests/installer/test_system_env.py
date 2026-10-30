"""SystemEnv (the real, read-only inspector) tested without touching this machine's Docker or any lab port: subprocess is replaced by canned output, the port and Ollama
checks talk to throw-away local servers on random ports."""
import http.server, json, os, socket, subprocess, threading
import pytest
from agentsec.installer import preflight as pf


class Canned:
    def __init__(self, table): self.table, self.calls = table, []
    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        key = " ".join(cmd[:3]) if cmd[:2] == ["docker", "compose"] else " ".join(cmd[:2])
        for k, (rc, out) in self.table.items():
            if " ".join(cmd).startswith(k):
                return subprocess.CompletedProcess(cmd, rc, out, "")
        return subprocess.CompletedProcess(cmd, 1, "", "unknown")


@pytest.fixture()
def sysenv(monkeypatch):
    def make(table):
        c = Canned(table); monkeypatch.setattr(subprocess, "run", c); return pf.SystemEnv(), c
    return make


def test_docker_info_containers_volumes_and_compose_are_parsed_and_only_read(sysenv):
    e, c = sysenv({"docker info": (0, json.dumps({"MemTotal": 12 * 2**30, "NCPU": 8, "DockerRootDir": "/var/lib/docker", "ServerVersion": "29.7.2"})),
                   "docker ps": (0, "agentsec_splunk\tagentseclab\tsplunk/splunk:10.2\t127.0.0.1:8000->8000/tcp, 0.0.0.0:8088->8088/tcp, [::]:8088->8088/tcp\nweb\t\tnginx\t\nbadline\n"),
                   "docker volume ls": (0, "agentseclab_splunk_var\nother\n"), "docker compose version": (0, "2.40.3\n")})
    assert e.docker_info() == {"mem_bytes": 12 * 2**30, "ncpu": 8, "root_dir": "/var/lib/docker", "server_version": "29.7.2"}
    assert e.containers() == [{"name": "agentsec_splunk", "project": "agentseclab", "image": "splunk/splunk:10.2", "ports": [8000, 8088]}, {"name": "web", "project": "", "image": "nginx", "ports": []}]
    assert e.volumes() == ["agentseclab_splunk_var", "other"] and e.compose_version() == "2.40.3"
    verbs = {tuple(x[:3]) for x in c.calls}
    assert all(x[0] == "docker" and not ({"rm", "stop", "kill", "down", "pull", "run", "exec", "prune", "create", "start", "restart", "up"} & set(x)) for x in c.calls), verbs


def test_every_failure_mode_is_none_not_an_exception(sysenv):
    e, _ = sysenv({})
    assert e.docker_info() is None and e.compose_version() is None and e.containers() == [] and e.volumes() == []
    e2, _ = sysenv({"docker info": (0, "not json")})
    assert e2.docker_info() is None


def test_missing_docker_binary_is_handled(monkeypatch):
    def boom(*a, **k): raise FileNotFoundError("docker")
    monkeypatch.setattr(subprocess, "run", boom)
    e = pf.SystemEnv()
    assert e.docker_info() is None and e.compose_version() is None and e.compose_supports_override_tags() is False


def test_override_tag_probe_uses_a_temporary_file_and_config_only(sysenv):
    e, c = sysenv({"docker compose": (0, "services: {}")})
    assert e.compose_supports_override_tags() is True
    cmd = c.calls[-1]
    assert cmd[:2] == ["docker", "compose"] and cmd[-1] == "config" and all(x not in cmd for x in ("up", "pull", "run"))
    e2, _ = sysenv({"docker compose": (1, "")})
    assert e2.compose_supports_override_tags() is False


def test_port_listener_distinguishes_a_busy_from_a_free_local_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
    port = s.getsockname()[1]
    e = pf.SystemEnv()
    assert e.port_listener("127.0.0.1", port) and e.port_listener("0.0.0.0", port)
    s.close()
    assert e.port_listener("127.0.0.1", port) is None


def test_disk_path_and_platform_probes(tmp_path):
    e = pf.SystemEnv()
    assert e.free_bytes(str(tmp_path)) > 0 and e.free_bytes("/nonexistent/x") is None
    f = tmp_path / "t"; f.write_text("x"); f.chmod(0o640)
    assert e.path_info(str(f)) == {"exists": True, "mode": 0o640, "size": 1, "is_file": True} and e.path_info(str(tmp_path / "none")) is None and e.path_info(str(tmp_path))["is_file"] is False
    system, machine = e.platform_info()
    assert system and machine


def test_ollama_version_and_tags_over_http_with_bad_servers():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = {"/api/version": {"version": "0.40.12"}, "/api/tags": {"models": [{"name": "m:1"}]}}.get(self.path)
            data = json.dumps(body).encode() if body else b"nope"
            self.send_response(200 if body else 404); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self, *a): pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        e = pf.SystemEnv()
        assert e.ollama_version(base) == "0.40.12" and e.ollama_tags(base) == {"models": [{"name": "m:1"}]}
        assert e.ollama_version("http://127.0.0.1:9") is None and e.ollama_tags("http://127.0.0.1:9") is None
    finally:
        srv.shutdown()


def test_the_system_env_never_disables_certificate_verification():
    import inspect
    src = inspect.getsource(pf)
    assert "CERT_NONE" not in src and "verify=False" not in src and "_create_unverified_context" not in src and "check_hostname = False" not in src
