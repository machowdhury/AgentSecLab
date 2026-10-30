"""Fakes for the installer tests: Docker, the network, the registry and the machine are all pretend. FakeEnv can only READ; it records every call so a test can prove
the installer asked questions and changed nothing."""
from __future__ import annotations

GIB = 2**30
READ_ONLY_CALLS = {"platform", "docker_info", "compose_version", "override_tags", "free_bytes", "port", "containers", "volumes", "ollama_version", "ollama_tags", "path", "environ"}


class FakeEnv:
    def __init__(self, *, os_name="Linux", machine="x86_64", docker=True, mem_gib=16, ncpu=8, compose="2.40.3", override_tags=True, free_gb=500, containers=None,
                 volumes=None, listeners=None, ollama=None, paths=None, avx=True, tags=None, environ=None):
        self.os_name, self.machine, self.docker, self.mem_gib, self.ncpu = os_name, machine, docker, mem_gib, ncpu
        self.compose, self.override_tags, self.free_gb = compose, override_tags, free_gb
        self._containers, self._volumes, self.listeners = containers or [], volumes or [], listeners or {}
        self.ollama = ollama if ollama is not None else {}      # url -> version string
        self.paths, self.avx, self.tags, self._environ = paths or {}, avx, tags, environ or {}
        self.calls: list[tuple] = []

    def platform_info(self):
        self.calls.append(("platform",)); return self.os_name, self.machine

    def docker_info(self):
        self.calls.append(("docker_info",))
        return {"mem_bytes": int(self.mem_gib * GIB), "ncpu": self.ncpu, "root_dir": "/var/lib/docker", "server_version": "29.7.2"} if self.docker else None

    def compose_version(self):
        self.calls.append(("compose_version",)); return self.compose if self.docker else None

    def compose_supports_override_tags(self):
        self.calls.append(("override_tags",)); return self.override_tags

    def free_bytes(self, path):
        self.calls.append(("free_bytes", path)); return int(self.free_gb * 1e9) if self.free_gb is not None else None

    def port_listener(self, host, port):
        self.calls.append(("port", host, port)); return self.listeners.get(port)

    def containers(self):
        self.calls.append(("containers",)); return list(self._containers)

    def environ(self):
        self.calls.append(("environ",)); return dict(self._environ)

    def volumes(self):
        self.calls.append(("volumes",)); return list(self._volumes)

    def ollama_version(self, url):
        self.calls.append(("ollama_version", url)); return self.ollama.get(url)

    def ollama_tags(self, url):
        self.calls.append(("ollama_tags", url)); return self.tags

    def path_info(self, path):
        self.calls.append(("path", path)); return self.paths.get(path)

    def has_avx(self):
        return self.avx


class FakeRunner:
    def __init__(self, fail_on: int | None = None, outputs: dict | None = None):
        self.commands, self.envs, self.fail_on, self.outputs = [], [], fail_on, outputs or {}      # outputs: a word in argv (for example "ps") -> the text returned

    def run(self, argv, cwd, env=None):
        self.commands.append(list(argv)); self.envs.append(dict(env or {}))
        if self.fail_on is not None and len(self.commands) == self.fail_on:
            return 1, "boom"
        return 0, self.outputs.get(self.match(argv), "")

    def match(self, argv):
        for key in self.outputs:
            if key in argv:
                return key
        return None

    def stream(self, argv, cwd, env=None):
        self.commands.append(list(argv)); self.envs.append(dict(env or {}))
        return 0


LEGACY_LAB = dict(
    containers=[{"name": f"agentsec_{n}", "project": "agentseclab", "image": "x", "ports": ports} for n, ports in
                (("splunk", [8000, 8088]), ("ollama", []), ("acmebank", [5000]), ("attack_service", [5001]), ("otel_collector", [4317, 4318]))],
    volumes=[f"agentseclab_{v}" for v in ("splunk_etc", "splunk_var", "ollama_models", "shared_telemetry", "splunk_app_agentsec")],
    listeners={8000: "docker", 5000: "docker", 5001: "docker", 8088: "docker", 4317: "docker", 4318: "docker"})
