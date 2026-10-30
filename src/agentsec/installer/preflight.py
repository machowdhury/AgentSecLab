"""Read-only preflight. Every check goes through an `Env` object: the real `SystemEnv` runs read-only commands (docker info, docker compose version, docker ps/volume ls,
socket connects, disk usage, one GET to Ollama's /api/version), tests use a fake. Nothing here writes, pulls, starts, stops or deletes anything.

Hardware numbers are advisory: no minimum has ever been benchmarked. The only measured figure is that a bundled Splunk 10.2 used about 6.9 GiB resident under
emulation on the development machine; the installer prints that as information and warns near it, it does not pretend it is a tested minimum.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import urllib.request
from typing import Protocol

from agentsec.installer.config import Finding, InstallConfig, Locks, resolve_models, rest_enabled, splunk_image

SPLUNK_MEASURED_GIB = 6.9
SPLUNK_ADVISORY_DOCKER_GIB = 8.0      # advisory round number above the measured figure, NOT a benchmarked minimum
DISK_MARGIN_GB = 2.0
LEGACY_PREFIX = "agentsec_"


class Env(Protocol):
    def platform_info(self) -> tuple[str, str]: ...                   # (os, machine)
    def docker_info(self) -> dict | None: ...                          # {"mem_bytes", "ncpu", "root_dir", "server_version"} or None when unavailable
    def compose_version(self) -> str | None: ...
    def compose_supports_override_tags(self) -> bool: ...              # `docker compose config` on a probe file with !reset / !override
    def free_bytes(self, path: str) -> int | None: ...
    def port_listener(self, host: str, port: int) -> str | None: ...   # a description of what accepts connections there, or None when free
    def containers(self) -> list[dict]: ...                            # [{"name", "project", "image", "ports": [host ports]}], all states
    def environ(self) -> dict: ...                                     # the process environment (names that Compose or the lab read)
    def volumes(self) -> list[str]: ...
    def ollama_version(self, url: str) -> str | None: ...
    def ollama_tags(self, url: str) -> dict | None: ...                # parsed /api/tags payload, read-only
    def path_info(self, path: str) -> dict | None: ...                 # {"exists", "mode", "size", "is_file"} or None when absent
    def has_avx(self) -> bool | None: ...


def published_ports(docker_ps_ports: str) -> list[int]:
    """Host ports from `docker ps` text such as '127.0.0.1:443->8443/tcp, 127.0.0.1:4317-4318->4317-4318/tcp'. A published RANGE counts port by port."""
    out: set[int] = set()
    for lo, hi in re.findall(r":(\d+)(?:-(\d+))?->", docker_ps_ports):
        out.update(range(int(lo), min(int(hi or lo), int(lo) + 64) + 1))      # the cap keeps a malformed range from growing without bound
    return sorted(out)


class SystemEnv:
    """Read-only inspection of the real machine."""
    def _run(self, *cmd: str, timeout: int = 20) -> str | None:
        try:
            p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        return p.stdout if p.returncode == 0 else None

    def platform_info(self):
        return platform.system(), platform.machine()

    def docker_info(self):
        out = self._run("docker", "info", "--format", "{{json .}}")
        if not out:
            return None
        try:
            d = json.loads(out)
            return {"mem_bytes": int(d.get("MemTotal") or 0), "ncpu": int(d.get("NCPU") or 0), "root_dir": d.get("DockerRootDir") or "", "server_version": d.get("ServerVersion") or ""}
        except (ValueError, TypeError):
            return None

    def compose_version(self):
        out = self._run("docker", "compose", "version", "--short")
        return out.strip() if out else None

    def compose_supports_override_tags(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a.yml"), os.path.join(d, "b.yml")
            open(a, "w").write("services:\n  x:\n    image: busybox\n    ports: ['127.0.0.1:1:1']\n")
            open(b, "w").write("services:\n  x:\n    ports: !override ['127.0.0.1:2:1']\n")
            return self._run("docker", "compose", "-f", a, "-f", b, "config") is not None

    def free_bytes(self, path):
        try:
            return shutil.disk_usage(path).free
        except OSError:
            return None

    def port_listener(self, host, port):
        try:
            with socket.create_connection(("127.0.0.1" if host in ("0.0.0.0", "", "::") else host, port), timeout=0.5):
                return "a process is accepting connections"
        except OSError:
            return None

    def containers(self):
        out = self._run("docker", "ps", "-a", "--format", "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Image}}\t{{.Ports}}")
        rows = []
        for line in (out or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                ports = published_ports(parts[3] if len(parts) > 3 else "")
                rows.append({"name": parts[0], "project": parts[1], "image": parts[2], "ports": ports})
        return rows

    def environ(self):
        return dict(os.environ)

    def volumes(self):
        out = self._run("docker", "volume", "ls", "--format", "{{.Name}}")
        return (out or "").split()

    def ollama_version(self, url):
        try:
            with urllib.request.urlopen(url.rstrip("/") + "/api/version", timeout=3) as r:      # certificate verification is the urllib default and is never disabled
                return json.loads(r.read(4096)).get("version")
        except (OSError, ValueError, AttributeError):
            return None

    def ollama_tags(self, url):
        try:
            with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=3) as r:
                return json.loads(r.read(2_000_000))
        except (OSError, ValueError):
            return None

    def path_info(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return {"exists": True, "mode": st.st_mode & 0o777, "size": st.st_size, "is_file": os.path.isfile(path)}

    def has_avx(self):
        try:
            return "avx" in open("/proc/cpuinfo").read().split("flags", 1)[1].split("\n", 1)[0]
        except (OSError, IndexError):
            return None


def _ver(v: object) -> tuple | None:
    """(major, minor, patch, build, release_flag) or None when it is not a version. A pre-release (0.35.0-rc1) sorts BEFORE its release; missing parts are zero."""
    m = re.fullmatch(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(-[0-9A-Za-z.+-]+)?", v.strip()) if isinstance(v, str) else None
    if not m:
        return None
    return (*(int(x or 0) for x in m.groups()[:4]), 0 if m.group(5) else 1)


def preflight(cfg: InstallConfig, locks: Locks, env: Env, *, install_dir: str, legacy_prefix_hint: str | None = None) -> tuple[list[Finding], dict]:
    """(findings, facts). Facts carry what was detected (existing lab, project prefix of existing volumes) so the planner never has to ask the machine again."""
    f: list[Finding] = []
    ok = lambda c, m: f.append(Finding("OK", c, m))
    info = lambda c, m: f.append(Finding("INFO", c, m))
    warn = lambda c, m: f.append(Finding("WARN", c, m))
    err = lambda c, m: f.append(Finding("ERROR", c, m))
    facts: dict = {}

    os_name, arch = env.platform_info()
    facts["platform"] = f"{os_name}/{arch}"
    if os_name == "Windows":
        err("WINDOWS_NATIVE_UNSUPPORTED", "run the installer inside WSL2 (Windows is experimental and only supported through a WSL2 shell, not PowerShell)")
    elif os_name not in ("Darwin", "Linux"):
        err("PLATFORM_UNSUPPORTED", f"{os_name} is not a supported platform (macOS and Linux; Windows only through WSL2, experimental)")
    else:
        info("PLATFORM", f"{os_name} {arch}" + (" (Apple Silicon: the Splunk image is amd64 and runs under emulation)" if (os_name, arch) == ("Darwin", "arm64") else ""))

    di = env.docker_info()
    if di is None:
        err("DOCKER_UNAVAILABLE", "Docker is not installed or its daemon is not running. Install Docker (Desktop on macOS/Windows, Engine on Linux) and start it.")
        facts["docker"] = None
    else:
        ok("DOCKER", f"Docker {di.get('server_version') or '?'} with {di['ncpu']} CPUs and {di['mem_bytes'] / 2**30:.1f} GiB visible to containers")
        facts["docker"] = di
        cv = env.compose_version()
        if not cv:
            err("COMPOSE_UNAVAILABLE", "Docker Compose v2 is not available (`docker compose version` failed)")
        else:
            ok("COMPOSE", f"Docker Compose {cv}")
            if not env.compose_supports_override_tags():
                err("COMPOSE_TOO_OLD", "this Docker Compose does not support the `!reset` / `!override` merge tags the HTTPS gateway and the generated override need; upgrade Docker Compose")

    # memory, advisory only
    if di and cfg.splunk.mode == "bundled":
        gib = di["mem_bytes"] / 2**30
        if gib < SPLUNK_ADVISORY_DOCKER_GIB:
            warn("DOCKER_MEMORY_LOW", f"Docker has {gib:.1f} GiB; a bundled Splunk 10.2 used about {SPLUNK_MEASURED_GIB} GiB resident on the development machine (emulated; NOT a benchmarked minimum). "
                                      "Raise Docker's memory, use an external Splunk, or choose splunk.mode 'none' (replay only).")
        else:
            info("DOCKER_MEMORY", f"Docker has {gib:.1f} GiB (a bundled Splunk used about {SPLUNK_MEASURED_GIB} GiB resident in the one measurement we have)")
        if cfg.ollama.mode == "bundled" and (os_name, arch) == ("Darwin", "arm64"):
            warn("OLLAMA_BUNDLED_MEMORY", "the bundled Ollama container shares that memory with Splunk and cannot use the Apple GPU; on macOS prefer ollama.mode 'host' (native Ollama)")

    # disk (advisory sum from the locks; measured on the filesystems that matter)
    models, _ = resolve_models(cfg, locks)
    need_gb = 0.0
    if cfg.splunk.mode == "bundled":
        _, entry, _ = splunk_image(cfg, locks)
        need_gb += float(entry.get("approx_gb") or locks.images["splunk"]["versions"][locks.images["splunk"]["default"]]["approx_gb"])
    if cfg.ollama.mode == "bundled":
        need_gb += float(locks.images["ollama"]["versions"][locks.images["ollama"]["default"]]["approx_gb"])
    if cfg.ollama.mode != "remote":
        need_gb += sum(float((locks.models["models"].get(n) or {}).get("approx_gb") or 0) for n in set(models.values()))
    need_gb += locks.images["others"]["otel_collector"]["approx_gb"] + 2 * locks.images["others"]["app_images"]["approx_gb_each"] + locks.images["others"]["nginx"]["approx_gb"] + DISK_MARGIN_GB
    for label, path in (("install directory", install_dir), ("Docker storage", (di or {}).get("root_dir") or "")):
        if not path:
            continue
        if label == "Docker storage" and not env.path_info(path):
            warn("DOCKER_DISK_NOT_MEASURED", "Docker's storage is not visible from this machine's filesystem (Docker Desktop keeps it inside its VM): check the free space in Docker Desktop's resources")
            continue
        free = env.free_bytes(path)
        if free is None:
            warn("DISK_NOT_MEASURED", f"free disk for the {label} could not be measured; do not read this as a pass")
        elif free / 1e9 < need_gb:
            err("DISK_LOW", f"{label}: {free / 1e9:.1f} GB free, about {need_gb:.1f} GB needed (image and model sizes from the locks plus {DISK_MARGIN_GB:.0f} GB margin)")
        else:
            ok("DISK", f"{label}: {free / 1e9:.1f} GB free; about {need_gb:.1f} GB needed")
    facts["disk_need_gb"] = round(need_gb, 1)

    # existing lab detection: never touched, only reported
    cons = env.containers()
    legacy = [c["name"] for c in cons if c["name"].startswith(LEGACY_PREFIX)]
    mine = [c["name"] for c in cons if c["project"] == cfg.project]
    vols = env.volumes()
    lab_vol = lambda pre: f"{pre}_splunk_var" in vols and (f"{pre}_splunk_etc" in vols or f"{pre}_ollama_models" in vols)     # a lab, not any volume that ends the same way
    prefixes = sorted({v[: -len("_splunk_var")] for v in vols if v.endswith("_splunk_var") and lab_vol(v[: -len("_splunk_var")])} | ({legacy_prefix_hint} if legacy_prefix_hint else set()))
    mine_ports = {p for c in cons if c["project"] == cfg.project for p in c.get("ports", [])}
    legacy_ports = {p for c in cons if c["name"].startswith(LEGACY_PREFIX) for p in c.get("ports", [])}
    facts.update(legacy_containers=legacy, project_containers=mine, volume_prefixes=prefixes)
    # `up` under project-scoped names recreates containers that exist under the old names in the SAME project (their data volumes are kept, the containers are not)
    same_project_legacy = [c["name"] for c in cons if c["name"].startswith(LEGACY_PREFIX) and c["project"] == cfg.project]
    if same_project_legacy and cfg.naming == "project":
        (warn if cfg.ack_recreate_existing else err)("WOULD_RECREATE_EXISTING_LAB", f"project {cfg.project!r} already runs containers under the old names ({', '.join(same_project_legacy[:3])}): `up` would recreate every one under new names. "
            "Data volumes are kept, but the containers are replaced and configuration rollback cannot bring the old names back. Use naming 'legacy' to adopt them unchanged, a different project name, or set ack_recreate_existing.")
    # a Splunk image change over existing data
    if cfg.splunk.mode == "bundled":
        has_data = any(f"{cfg.project}_{v}" in vols for v in ("splunk_var", "splunk_etc")) or (cfg.naming == "legacy" and bool(prefixes))
        ver = cfg.splunk.version or locks.images["splunk"]["default"]
        entry = locks.images["splunk"]["versions"].get(ver, {})
        if has_data and entry.get("fresh_install_only"):
            err("SPLUNK_UPGRADE_BLOCKED", f"Splunk {ver} migrates its KV store irreversibly on first start (no supported rollback): it is for fresh installs only. Use a new project name (new empty volumes), or restore a backup copy there; existing Splunk data is never upgraded in place by this installer.")
        elif has_data and ver != locks.images["splunk"]["default"] and not cfg.ack_splunk_upgrade:
            err("SPLUNK_UPGRADE_NEEDS_ACK", f"existing Splunk data volumes would start on Splunk {ver} instead of {locks.images['splunk']['default']}: a newer Splunk may migrate the data and cannot always be rolled back. Back the volumes up first, then set ack_splunk_upgrade.")
    # variables in the caller's shell silently beat .env
    shell = env.environ()
    for var in ("COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES", "AGENTSEC_BIND_ADDRESS", "AGENTSEC_GATEWAY_BIND", "AGENTSEC_PUBLIC_PORT", "SPLUNK_IMAGE"):
        if shell.get(var):
            (err if var in ("AGENTSEC_BIND_ADDRESS", "AGENTSEC_GATEWAY_BIND") and cfg.deployment == "localhost" and shell[var] not in ("127.0.0.1", "::1", "localhost") else warn)(
                "SHELL_ENV_OVERRIDES_CONFIG", f"{var} is set in this shell and overrides the generated .env for docker compose; unset it (lab-up.sh --remote sets AGENTSEC_BIND_ADDRESS the same way)")
    if legacy and cfg.naming == "project":
        warn("EXISTING_LAB_LEGACY_NAMES", f"an existing AgentSec lab is present ({', '.join(legacy[:3])}{'...' if len(legacy) > 3 else ''}). It will not be stopped, renamed or recreated. "
                                          "Its host ports will conflict with a new install unless you change ports.* or stop it yourself; to run this lab on top of its data choose naming 'legacy'.")
    if cfg.naming == "legacy":
        if not legacy and not prefixes:
            err("LEGACY_NOTHING_TO_ADOPT", "naming 'legacy' adopts an existing lab, but no agentsec_* containers or lab volumes were found")
        elif prefixes and cfg.project not in prefixes:
            err("LEGACY_PROJECT_MISMATCH", f"existing lab data lives under project {prefixes[0]!r}; set project to that name so its volumes are reused. A different name would start with EMPTY volumes (the old ones are never deleted).")
        else:
            ok("LEGACY_ADOPT", "the existing lab's volumes and names will be reused unchanged")
    elif prefixes and cfg.project not in prefixes:
        warn("VOLUMES_NOT_ADOPTED", f"lab data volumes exist for project {prefixes[0]!r}; project {cfg.project!r} starts with empty volumes. Nothing is deleted, and naming 'legacy' with that project reuses the data.")
    if mine:
        info("PROJECT_EXISTS", f"project {cfg.project!r} already has containers ({len(mine)}); an install updates configuration only and never removes data volumes")

    # ports (everything that will be published on the host)
    wanted = {}
    if cfg.gateway.enabled:
        wanted["gateway"] = (cfg.gateway.bind, cfg.gateway.port)
    else:
        wanted.update(acmebank=("127.0.0.1", cfg.ports.acmebank), attack=("127.0.0.1", cfg.ports.attack), splunk_web=("127.0.0.1", cfg.ports.splunk_web))
    if cfg.splunk.mode == "bundled":
        wanted.update(hec=("127.0.0.1", cfg.ports.hec))
    wanted.update(otel_grpc=("127.0.0.1", cfg.ports.otel_grpc), otel_http=("127.0.0.1", cfg.ports.otel_http))
    for name, (host, port) in wanted.items():
        who = env.port_listener(host, port)
        owned = port in (mine_ports if cfg.naming == "project" else legacy_ports)      # published by THIS install's containers (or the adopted lab's), not merely "some project container exists"
        if who and not owned:
            err("PORT_IN_USE", f"{name}: port {port} on {host} is already in use ({who}); free it or change the port")
        elif who:
            info("PORT_IN_USE_BY_PROJECT", f"{name}: port {port} is in use, and the install's own containers exist (assumed to be them)")
        else:
            ok("PORT_FREE", f"{name}: port {port} is free")

    # ollama
    min_v = locks.images["ollama"]["minimum_server_version"]
    url = {"bundled": "", "host": "http://127.0.0.1:11434"}.get(cfg.ollama.mode, "")      # a remote URL is refused by validate and is never contacted
    if url:
        v = env.ollama_version(url)
        if v is None:
            warn("OLLAMA_UNREACHABLE", f"Ollama did not answer at {url if cfg.ollama.mode == 'remote' else 'this machine (127.0.0.1:11434)'}; start it before the first live run")
        elif _ver(v) is None:
            warn("OLLAMA_VERSION_UNREADABLE", f"Ollama reported a version this installer cannot read ({str(v)[:40]!r}); the minimum is {min_v}")
        elif _ver(v) < _ver(min_v):
            err("OLLAMA_TOO_OLD", f"Ollama {v} is older than the minimum {min_v} (known security fixes); upgrade it")
        else:
            ok("OLLAMA_VERSION", f"Ollama {v}")
    # external splunk files
    if rest_enabled(cfg.splunk):
        for label, path, code in (("CA bundle", cfg.splunk.ca_file, "SPLUNK_CA_MISSING"), ("search token file", cfg.splunk.token_file, "SPLUNK_TOKEN_MISSING")):
            if not path:
                if label == "search token file":
                    err(code, f"splunk.{'token_file'} is required")
                continue
            pi = env.path_info(path)
            if not pi or not pi["is_file"]:
                err(code, f"the {label} {path!r} does not exist or is not a file")
            elif label == "search token file" and pi["mode"] & 0o077:
                warn("SPLUNK_TOKEN_PERMISSIONS", f"the token file is readable by other users (mode {pi['mode']:03o}); use 0600")
    if cfg.splunk.mode == "bundled" and cfg.splunk.version in ("10.6",) and env.has_avx() is False:
        err("SPLUNK_NEEDS_AVX", "Splunk 10.6's KV store needs a CPU with AVX, SSE4.2 and AES-NI; this CPU does not report AVX")
    return f, facts
