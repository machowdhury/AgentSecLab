"""The install workflow: validate, preflight, plan, (dry-run | write), (apply), rollback. All machine effects go through the injected Env and Runner."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Protocol

from agentsec.installer import preflight as pf
from agentsec.installer import render
from agentsec.installer.config import Finding, InstallConfig, Locks, validate

EXIT_OK, EXIT_USAGE, EXIT_CHECKS, EXIT_REFUSED, EXIT_APPLY = 0, 2, 3, 4, 6
GENERATED = [".env", f"{render.STATE_DIR}/compose.override.yml", f"{render.STATE_DIR}/install.json"]


class Runner(Protocol):
    def run(self, argv: list[str], cwd: str, env: dict | None = None) -> tuple[int, str]: ...
    def stream(self, argv: list[str], cwd: str, env: dict | None = None) -> int: ...      # output goes straight to the terminal (logs --follow)


class SubprocessRunner:
    """Executes plan commands for `--apply`. Not used by any test and not run by the installer-core work; it is the only place that starts anything."""
    def run(self, argv, cwd, env=None):
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, env={**os.environ, **(env or {})})
        return p.returncode, (p.stdout + p.stderr)[-200000:]

    def stream(self, argv, cwd, env=None):
        try:
            return subprocess.run(argv, cwd=cwd, env={**os.environ, **(env or {})}).returncode
        except KeyboardInterrupt:
            return 130


def read_env(root: Path) -> tuple[dict, bool]:
    """(values, generated_by_installer) of an existing .env, or ({}, False)."""
    p = root / ".env"
    if not p.is_file():
        return {}, False
    text = p.read_text(encoding="utf-8", errors="replace")
    return render.parse_env(text), text.startswith(render.MARKER)


def collect(cfg: InstallConfig, locks: Locks, env: pf.Env, root: Path) -> tuple[list[Finding], dict]:
    findings = validate(cfg, locks)
    pre, facts = pf.preflight(cfg, locks, env, install_dir=str(root))
    return findings + pre, facts


def gate(findings: list[Finding], accept: set[str]) -> tuple[list[Finding], list[Finding]]:
    """(errors, unaccepted warnings). `accept` is a set of WARN codes, or {"all"}."""
    errors = [f for f in findings if f.level == "ERROR"]
    warns = [f for f in findings if f.level == "WARN" and "all" not in accept and f.code not in accept]
    return errors, warns


def _write_private(dest: Path, data: str | bytes) -> None:
    """Create a new owner-only file next to `dest` (O_EXCL, never following a symlink) and move it into place atomically."""
    import tempfile
    if dest.is_symlink():
        raise OSError(f"{dest.name} is a symbolic link; refusing to write through it")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=dest.name + ".", suffix=".tmp")      # mode 0600, O_EXCL
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(dest, 0o600)


def unchanged(root: Path, plan: render.Plan) -> bool:
    return all((root / rel).is_file() and (root / rel).read_text(encoding="utf-8", errors="replace") == text for rel, text in plan.files.items())


def write_files(root: Path, plan: render.Plan) -> list[str]:
    """Writes the generated files atomically and owner-only. The previous generated configuration is kept ONE level deep in .agentsec/previous, but only when this write
    actually changes something (a no-op re-run or a retry after a failed apply must not destroy the real previous configuration). Returns the paths written."""
    state = root / render.STATE_DIR
    if state.is_symlink():
        raise OSError(f"{render.STATE_DIR} is a symbolic link; refusing to write through it")
    state.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    if unchanged(root, plan):
        return []
    prev = state / "previous"
    env_file = root / ".env"
    ours = env_file.is_file() and env_file.read_text(errors="replace").startswith(render.MARKER)
    if ours:
        stage = state / "previous.new"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(mode=0o700)
        for g in GENERATED:
            if (root / g).is_file():
                _write_private(stage / g.replace("/", "__"), (root / g).read_bytes())
        shutil.rmtree(prev, ignore_errors=True)
        os.replace(stage, prev)
    else:
        shutil.rmtree(prev, ignore_errors=True)         # a foreign .env is being replaced: an older `previous` would restore an unrelated configuration
    written = []
    for rel, text in plan.files.items():
        _write_private(root / rel, text)
        written.append(rel)
    return written


def backup_foreign_env(root: Path) -> str:
    """Keep a foreign .env before it is replaced: owner-only from the first byte, never overwriting an earlier backup. Returns the backup's name."""
    n, src = 0, root / ".env"
    while True:
        dest = root / (".env.pre-agentsec" + (f".{n}" if n else ""))
        if not dest.exists():
            _write_private(dest, src.read_bytes())
            return dest.name
        n += 1


def rollback(root: Path) -> list[str]:
    """Restore the previous generated configuration. Touches only the three generated files; never containers, images or volumes. Refuses anything that is not
    an installer-generated configuration."""
    prev = root / render.STATE_DIR / "previous"
    prev_env = prev / ".env"
    if not prev.is_dir() or not prev_env.is_file() or not prev_env.read_text(errors="replace").startswith(render.MARKER):
        return []
    restored = []
    for g in GENERATED:
        src = prev / g.replace("/", "__")
        if src.is_file() and not src.is_symlink():
            _write_private(root / g, src.read_bytes())
            restored.append(g)
    return restored


def apply(plan: render.Plan, runner: Runner, root: Path, say: Callable[[str], None]) -> int:
    for c in plan.commands:
        argv, extra = c["argv"], c.get("env") or {}
        say("  $ " + " ".join(f"{k}={v}" for k, v in extra.items()) + (" " if extra else "") + " ".join(argv))
        rc, out = runner.run(argv, str(root), extra)
        if rc != 0:
            say(f"FAIL  command exited {rc}: {out.strip()[-400:]}")
            return EXIT_APPLY
    return EXIT_OK
