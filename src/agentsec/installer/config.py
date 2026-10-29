"""Installer configuration: the data model, strict loading, and validation. No I/O except reading the two lock files; nothing here touches Docker or the network.

Deployment modes (owner decision, 2026-10-28): `localhost` (default, loopback only) and `organization` (behind the organization's own authentication,
rate-limiting and network-access gateway). Direct public exposure is unsupported, so a non-loopback bind is refused unless the organization mode is chosen AND
the external access controls are explicitly acknowledged. The lab's own login has no throttling (M-2, unresolved); the acknowledgement says so.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit
from dataclasses import MISSING, dataclass, field, fields, asdict
from pathlib import Path

from agentsec import model_names
from agentsec.gateway_config import HOST_RE, INTERNAL_PORTS

ROOT = Path(__file__).resolve().parents[3]
PROJECT_RE = re.compile(r"[a-z][a-z0-9_-]{1,30}")                      # always used with fullmatch: `$` would accept a trailing newline
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
# A value written to .env or the Compose override: no control characters, no whitespace, no quotes, no `$` (Compose interpolates it), no `#`.
ENV_SAFE = re.compile(r"[A-Za-z0-9._:/@%+,=~\[\]-]*")
NO_CONTROL = re.compile(r"[^\x00-\x1f\x7f]*")
ACK_PHRASE = "I ACKNOWLEDGE"
DEPLOYMENTS = ("localhost", "organization")
NAMINGS = ("project", "legacy")
OLLAMA_MODES = ("bundled", "host", "remote")
SPLUNK_MODES = ("bundled", "external_enterprise", "cloud", "none")
ACK_TEXT = ("Organization-managed mode: the lab's own login (HTTP Basic) has NO failed-login throttling and is not SSO. It is only safe behind your organization's own "
            "authentication, rate-limiting and network-access gateway. Direct exposure to the public internet or an untrusted network is unsupported.")


class ConfigError(ValueError):
    """The configuration file or flags are malformed (unknown key, wrong type). Messages never contain secret values."""


@dataclass
class Finding:
    level: str      # ERROR | WARN | INFO | OK
    code: str
    message: str

    def line(self) -> str:
        return f"{self.level:<5} {self.code}: {self.message}"


@dataclass
class Ports:
    splunk_web: int = 8000
    hec: int = 8088
    otel_grpc: int = 4317
    otel_http: int = 4318
    acmebank: int = 5000
    attack: int = 5001


@dataclass
class GatewayCfg:
    enabled: bool = True
    host: str = "localhost"
    port: int = 443
    bind: str = "127.0.0.1"
    ctf: bool = False        # opt-in: publish the Advanced CTF through the gateway (needs the gateway; the Attack Service then runs as the installing user)


@dataclass
class OllamaCfg:
    mode: str = "bundled"          # bundled container | host (native Ollama on this machine) | remote
    url: str = ""                  # required for remote; https only. Host mode defaults to host.docker.internal
    ca_file: str = ""


@dataclass
class SplunkCfg:
    mode: str = "bundled"
    version: str = ""              # key in images.lock splunk.versions; empty = the lock default
    rest_url: str = ""
    ca_file: str = ""
    token_file: str = ""
    index: str = "agentsec_telemetry"


def rest_enabled(s: "SplunkCfg") -> bool:
    """The Attack Service verifies evidence over Splunk REST: always for an external Splunk, and for the bundled one only when a REST URL and token file are both given."""
    return s.mode in ("external_enterprise", "cloud") or (s.mode == "bundled" and bool(s.rest_url and s.token_file))


def _splunk_rest_findings(s: "SplunkCfg") -> list:
    from agentsec import splunk_client
    f: list = []
    env = {"AGENTSEC_SPLUNK_MODE": s.mode.upper(), "AGENTSEC_SPLUNK_REST_URL": s.rest_url, "AGENTSEC_SPLUNK_CA_BUNDLE_FILE": s.ca_file,
           "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": s.token_file, "AGENTSEC_SPLUNK_INDEX": s.index}
    for x in splunk_client.validate_config(env):                 # one source of truth for the strict-TLS client's rules (files are checked by preflight, not here)
        if x.code in ("TOKEN_FILE_MISSING", "CA_BUNDLE_MISSING", "TOKEN_FILE_EMPTY", "CA_BUNDLE_INVALID", "TOKEN_FILE_TOO_LARGE", "TOKEN_FILE_PERMISSIONS"):
            continue
        f.append(Finding(x.level, "SPLUNK_" + x.code, x.message))
    for field_name, value in (("rest_url", s.rest_url), ("ca_file", s.ca_file), ("token_file", s.token_file), ("index", s.index)):
        if value and not ENV_SAFE.fullmatch(value):
            f.append(Finding("ERROR", "SPLUNK_VALUE_UNSAFE", f"splunk.{field_name} contains a character that is not allowed (a space, quote, $ or #)"))
    if s.ca_file and not s.ca_file.startswith("/"):
        f.append(Finding("ERROR", "SPLUNK_CA_NOT_ABSOLUTE", "splunk.ca_file must be an absolute path"))
    for field_name, value in (("ca_file", s.ca_file), ("token_file", s.token_file)):
        if value and (value == "/" or ".." in value.split("/")):            # it becomes a bind-mount source: a directory or a dot-dot path is never the file meant
            f.append(Finding("ERROR", "SPLUNK_PATH_UNSAFE", f"splunk.{field_name} must name a file, with no '..' segment"))
    if not s.token_file.startswith("/"):
        f.append(Finding("ERROR", "SPLUNK_TOKEN_FILE_NOT_ABSOLUTE", "splunk.token_file must be an absolute path to a one-line token file (the token itself is never put in the configuration)"))
    return f


@dataclass
class InstallConfig:
    project: str = "agentsec"
    naming: str = "project"        # project: containers are named <project>-<service>; legacy: adopt an existing lab's fixed agentsec_* names
    deployment: str = "localhost"
    ack_external_controls: bool = False
    gateway: GatewayCfg = field(default_factory=GatewayCfg)
    ollama: OllamaCfg = field(default_factory=OllamaCfg)
    splunk: SplunkCfg = field(default_factory=SplunkCfg)
    models: dict = field(default_factory=lambda: {"pipeline": "", "loan_desk": ""})   # empty = the role default from models.lock
    allow_unpinned_model: bool = False
    allow_candidate_images: bool = False
    ack_splunk_upgrade: bool = False   # acknowledge changing the Splunk image over existing data volumes (10.6 is never allowed over existing data)
    ack_recreate_existing: bool = False  # acknowledge that `up` will recreate an existing lab's containers under new names (data volumes are kept)
    require_digests: bool = False  # release mode: every image must carry a digest
    ports: Ports = field(default_factory=Ports)

    @classmethod
    def from_dict(cls, data: dict) -> "InstallConfig":
        if not isinstance(data, dict):
            raise ConfigError("the configuration must be a JSON object")
        return _build(cls, data, "")

    def to_dict(self) -> dict:
        return asdict(self)


def _build(klass, data: dict, path: str):
    known = {f.name: f for f in fields(klass)}
    unknown = sorted(set(data) - set(known))
    if unknown:
        raise ConfigError(f"unknown setting(s) {', '.join(path + k for k in unknown)}")
    kwargs = {}
    for name, value in data.items():
        f = known[name]
        default = f.default_factory() if f.default_factory is not MISSING else f.default
        if hasattr(default, "__dataclass_fields__"):
            if not isinstance(value, dict):
                raise ConfigError(f"{path}{name} must be an object")
            kwargs[name] = _build(type(default), value, f"{path}{name}.")
        elif isinstance(default, dict):
            if not isinstance(value, dict) or set(value) - set(default) or not all(isinstance(v, str) and NO_CONTROL.fullmatch(v) for v in value.values()):
                raise ConfigError(f"{path}{name} must be an object with the keys {sorted(default)} and plain text values")
            kwargs[name] = {**default, **value}
        else:
            if isinstance(value, str) and not NO_CONTROL.fullmatch(value):
                raise ConfigError(f"{path}{name} contains a control character (a newline, for example)")
            if isinstance(default, bool) != isinstance(value, bool) or (isinstance(default, int) and not isinstance(default, bool) and (isinstance(value, bool) or not isinstance(value, int))) \
                    or (isinstance(default, str) and not isinstance(value, str)):
                raise ConfigError(f"{path}{name} has the wrong type")
            kwargs[name] = value
    return klass(**kwargs)


@dataclass
class Locks:
    images: dict
    models: dict

    @classmethod
    def load(cls, root: Path | None = None) -> "Locks":
        r = root or ROOT
        return cls(json.loads((r / "deploy/images.lock.json").read_text()), json.loads((r / "deploy/models.lock.json").read_text()))


def splunk_image(cfg: InstallConfig, locks: Locks) -> tuple[str, dict, list[Finding]]:
    """(image reference, lock entry, findings). The reference is `repo@sha256:digest` when pinned, else the tag (a floating pin, flagged)."""
    out: list[Finding] = []
    sp = locks.images["splunk"]
    key = cfg.splunk.version or sp["default"]
    if key in sp.get("not_released", []):
        out.append(Finding("ERROR", "SPLUNK_VERSION_NOT_RELEASED", f"Splunk Enterprise {key} has not been released on-premises; there is no image to run."))
        return "", {}, out
    entry = sp["versions"].get(key)
    if entry is None:
        out.append(Finding("ERROR", "SPLUNK_VERSION_UNKNOWN", f"Splunk version {key!r} is not in the image lock (known: {', '.join(sorted(sp['versions']))})."))
        return "", {}, out
    if entry["status"] != "tested":
        if not cfg.allow_candidate_images:
            out.append(Finding("ERROR", "SPLUNK_VERSION_NOT_QUALIFIED", f"Splunk {key} is a candidate that has not passed the compatibility tests; set allow_candidate_images to use it anyway."))
        else:
            out.append(Finding("WARN", "SPLUNK_CANDIDATE_IMAGE", f"Splunk {key} is an unqualified candidate ({entry.get('evidence', '')})."))
    return _ref(sp["repository"], entry, cfg, "SPLUNK", out), entry, out


def _ref(repo: str, entry: dict, cfg: InstallConfig, what: str, out: list[Finding]) -> str:
    digest = entry.get("digest")
    if digest:
        if not DIGEST_RE.match(digest):
            out.append(Finding("ERROR", f"{what}_DIGEST_INVALID", f"the pinned digest for {repo} is malformed"))
        return f"{repo}@{digest}"
    out.append(Finding("ERROR" if cfg.require_digests else "WARN", f"{what}_FLOATING_TAG", f"{repo}:{entry['tag']} is a floating tag with no pinned digest; a re-pushed tag would change it silently."))
    return f"{repo}:{entry['tag']}"


def ollama_image(cfg: InstallConfig, locks: Locks) -> tuple[str, list[Finding]]:
    out: list[Finding] = []
    o = locks.images["ollama"]
    return _ref(o["repository"], o["versions"][o["default"]], cfg, "OLLAMA", out), out


def resolve_models(cfg: InstallConfig, locks: Locks) -> tuple[dict, list[Finding]]:
    """{role: name}. Empty means the role default from models.lock. A name must be valid; a name not in the lock needs allow_unpinned_model; a null digest is a warning."""
    out: list[Finding] = []
    resolved = {}
    for role, default in locks.models["roles"].items():
        name = (cfg.models.get(role) or default).strip()
        try:
            model_names.normalize(name)
        except model_names.ModelConfigError as exc:
            out.append(Finding("ERROR", "MODEL_NAME_INVALID", f"{role}: {exc}"))
            continue
        resolved[role] = name
        entry = locks.models["models"].get(name) or locks.models["models"].get(model_names.normalize(name))
        if entry is None:
            out.append(Finding("WARN" if cfg.allow_unpinned_model else "ERROR", "MODEL_NOT_IN_LOCK",
                               f"{role}: {name} is not in models.lock (UNPINNED); set allow_unpinned_model to use it, and every result is then labelled unpinned."))
        elif not entry.get("digest"):
            out.append(Finding("WARN", "MODEL_DIGEST_NOT_PINNED", f"{role}: {name} has no qualified digest in models.lock yet; the runtime still records the digest Ollama reports."))
    return resolved, out


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _url_problem(url: str) -> str | None:
    """None when `url` is a plain https URL with a host, no credentials, no query or fragment, and only characters that are safe in .env."""
    if not ENV_SAFE.fullmatch(url):
        return "contains a character that is not allowed (a space, quote, $ or #)"
    try:
        u = urlsplit(url)
        u.port
    except ValueError:
        return "is not a valid URL (check the host and port)"
    if u.scheme != "https" or not u.hostname:
        return "must be an https:// URL with a host name"
    if u.username or u.password or "@" in u.netloc:
        return "must not contain credentials (they would be stored in the plan and the state file)"
    if u.query or u.fragment or u.path not in ("", "/"):
        return "must not contain a path, query or fragment"
    return None


def validate(cfg: InstallConfig, locks: Locks) -> list[Finding]:
    """Everything that can be decided from the configuration and the two lock files alone (no machine inspection, no network)."""
    f: list[Finding] = []
    err = lambda c, m: f.append(Finding("ERROR", c, m))
    warn = lambda c, m: f.append(Finding("WARN", c, m))
    if cfg.deployment not in DEPLOYMENTS:
        err("DEPLOYMENT_INVALID", f"deployment must be one of {list(DEPLOYMENTS)}")
    if cfg.naming not in NAMINGS:
        err("NAMING_INVALID", f"naming must be one of {list(NAMINGS)}")
    if not PROJECT_RE.fullmatch(cfg.project or ""):
        err("PROJECT_INVALID", "project must be 2-31 characters: a lowercase letter, then lowercase letters, digits, - or _")
    # access control: loopback unless the organization mode is chosen and acknowledged
    bind = cfg.gateway.bind
    if bind not in LOOPBACK and not _is_ip(bind):
        err("BIND_INVALID", "gateway.bind must be an IP address (or localhost): the address Docker publishes the port on")
        bind = "127.0.0.1"     # judged below as loopback so only this error is reported
    if cfg.deployment == "localhost":
        if bind not in LOOPBACK:
            err("BIND_NOT_LOOPBACK", f"localhost mode binds only to loopback; {bind!r} would expose the lab. Choose deployment 'organization' behind your own gateway, or use 127.0.0.1.")
        if cfg.ack_external_controls:
            warn("ACK_NOT_NEEDED", "ack_external_controls is only used in organization mode")
    elif cfg.deployment == "organization":
        if not cfg.ack_external_controls:
            err("ORG_ACK_REQUIRED", "organization mode needs the explicit acknowledgement that access control, rate limiting and network access are enforced by YOUR gateway: " + ACK_TEXT)
        if bind in LOOPBACK:
            warn("ORG_BIND_LOOPBACK", "organization mode is bound to loopback: your gateway must run on this machine; set gateway.bind (for example 0.0.0.0) to publish to it")
        elif bind in ("0.0.0.0", "::"):
            warn("ORG_BIND_ALL_INTERFACES", "the gateway will listen on every interface: restrict it with the host firewall to your gateway's address")
    # gateway
    g = cfg.gateway
    if g.enabled:
        if not HOST_RE.fullmatch(g.host or "") or (g.host or "").startswith("*"):
            err("GATEWAY_HOST_INVALID", "gateway.host must be a DNS name (no scheme, port, wildcard or spaces)")
        if not 1 <= g.port <= 65535:
            err("GATEWAY_PORT_INVALID", "gateway.port must be 1 to 65535: 443 (default) or 8000 are the supported values")
        elif g.port in INTERNAL_PORTS or g.port in {**vars(cfg.ports), "splunk_web": 18000 if cfg.ports.splunk_web == 8000 else cfg.ports.splunk_web}.values():   # the gateway moves Splunk Web off 8000
            err("GATEWAY_PORT_RESERVED", f"port {g.port} belongs to an internal service and cannot be the public port")
        elif g.port not in (443, 8000):
            warn("GATEWAY_PORT_NONSTANDARD", f"supported public ports are 443 and 8000; {g.port} is for development only")
    if g.ctf and not g.enabled:
        err("CTF_NEEDS_GATEWAY", "gateway.ctf publishes the CTF through the HTTPS gateway; enable gateway.enabled or turn gateway.ctf off")
    if not g.enabled and cfg.deployment == "organization":
        warn("ORG_WITHOUT_GATEWAY", "organization mode without the lab gateway publishes the lab's plain-HTTP ports: only acceptable behind your own TLS-terminating gateway")
    for name, port in vars(cfg.ports).items():
        if not 1 <= port <= 65535:
            err("PORT_INVALID", f"ports.{name} must be 1 to 65535")
    if len(set(vars(cfg.ports).values())) != len(vars(cfg.ports)):
        err("PORTS_COLLIDE", "two internal services are configured on the same host port")
    # ollama
    o = cfg.ollama
    if o.mode not in OLLAMA_MODES:
        err("OLLAMA_MODE_INVALID", f"ollama.mode must be one of {list(OLLAMA_MODES)}")
    elif o.mode == "remote":
        problem = _url_problem(o.url) if o.url else "is required"
        if problem:
            err("OLLAMA_REMOTE_NOT_HTTPS", f"ollama.url {problem}. A remote Ollama must be an https:// URL (Ollama has no TLS or authentication of its own: front it with your authenticating TLS proxy)")
        # Fail closed: Ollama has no authentication or TLS of its own and the lab's model client cannot yet send credentials or trust a private CA (RC2 phase 6),
        # so no remote configuration can be made safe today. Refusing is better than a lab that silently talks to an unauthenticated endpoint.
        err("OLLAMA_REMOTE_UNSUPPORTED", "remote Ollama is not supported in this release: the lab's model client cannot authenticate to the endpoint or use a custom CA (RC2 phase 6). Use ollama.mode 'bundled' or 'host'")
        if o.ca_file and (not o.ca_file.startswith("/") or not ENV_SAFE.fullmatch(o.ca_file)):
            err("OLLAMA_CA_NOT_ABSOLUTE", "ollama.ca_file must be an absolute path without spaces, quotes or $")
    elif o.url:
        warn("OLLAMA_URL_IGNORED", "ollama.url is only used for the remote mode")
    # splunk
    s = cfg.splunk
    if s.mode not in SPLUNK_MODES:
        err("SPLUNK_MODE_INVALID", f"splunk.mode must be one of {list(SPLUNK_MODES)}")
    elif s.mode in ("external_enterprise", "cloud"):
        f.extend(_splunk_rest_findings(s))
    elif s.mode == "bundled":
        img, _, fs = splunk_image(cfg, locks)
        f += fs
        if rest_enabled(s):
            f.extend(_splunk_rest_findings(s))
        elif s.rest_url or s.token_file:
            f.append(Finding("WARN", "SPLUNK_REST_INCOMPLETE", "splunk.rest_url and splunk.token_file must both be set for REST verification with the bundled Splunk; neither is used until they are"))
    else:
        pass
    _, mfs = resolve_models(cfg, locks)
    f += mfs
    _, ofs = ollama_image(cfg, locks)
    f += ofs if o.mode == "bundled" else []
    return f
