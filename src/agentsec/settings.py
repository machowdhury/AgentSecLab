"""Lab configuration. Profile and secrets come from the environment, not attacker JSON."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from agentsec import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    version: str
    lab_id: str
    service_name: str
    security_profile: str
    ollama_base_url: str
    ollama_model: str
    otel_collector_http: str
    otel_enabled: bool
    artifacts_dir: Path
    schema_path: Path
    bind_host: str
    acmebank_port: int
    attack_port: int
    acmebank_url: str
    flask_secret_key: str
    baseline_enabled: bool
    baseline_interval_min_sec: int
    baseline_interval_max_sec: int
    baseline_startup_delay_sec: int
    deployment_environment: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    profile = _env("AGENTSEC_SECURITY_PROFILE", "defended").lower()
    if profile not in ("defended", "vulnerable"):
        profile = "defended"

    artifacts = Path(_env("AGENTSEC_ARTIFACTS_DIR", str(REPO_ROOT / "artifacts")))
    schema = Path(_env("AGENTSEC_SCHEMA_PATH", str(REPO_ROOT / "schemas" / "security_event.schema.json")))

    secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if not secret:
        secret = secrets.token_hex(32)

    return Settings(
        version=_env("AGENTSEC_VERSION", __version__),
        lab_id=_env("AGENTSEC_LAB_ID", "agentsec-local"),
        service_name=_env("OTEL_SERVICE_NAME", "acmebank"),
        security_profile=profile,
        ollama_base_url=_env("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=_env("OLLAMA_MODEL", "llama3.2:1b"),
        otel_collector_http=_env("OTEL_COLLECTOR_HTTP", "http://127.0.0.1:4318").rstrip("/"),
        otel_enabled=_env_bool("AGENTSEC_OTEL_ENABLED", True),
        artifacts_dir=artifacts,
        schema_path=schema,
        bind_host=_env("AGENTSEC_BIND_HOST", "127.0.0.1"),
        acmebank_port=_env_int("ACMEBANK_PORT", 5000),
        attack_port=_env_int("ATTACK_SERVICE_PORT", 5001),
        acmebank_url=_env("ACMEBANK_URL", "http://127.0.0.1:5000").rstrip("/"),
        flask_secret_key=secret,
        baseline_enabled=_env_bool("BASELINE_TRAFFIC_ENABLED", True),
        baseline_interval_min_sec=_env_int("BASELINE_INTERVAL_MIN_SEC", 90, 5),
        baseline_interval_max_sec=_env_int("BASELINE_INTERVAL_MAX_SEC", 240, 5),
        baseline_startup_delay_sec=_env_int("BASELINE_STARTUP_DELAY_SEC", 15, 0),
        deployment_environment=_env("DEPLOYMENT_ENVIRONMENT", "lab"),
    )


def reset_settings_cache() -> None:
    get_settings.cache_clear()
