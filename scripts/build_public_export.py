#!/usr/bin/env python3
"""Build the public export of the repository from the tracked files of HEAD, without touching history.

Everything tracked is exported except: documents under `docs/` that no public document links to, the directories in `excluded_dirs`, and the
listed tests/files. Links in exported Markdown to anything excluded are turned into plain text. Writes MANIFEST.txt (what was left out and why).
Usage: build_public_export.py OUT_DIR   (OUT_DIR must not exist)
"""
from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]+)(\s+\"[^\"]*\")?\)")
HTML_SRC = re.compile(r"""(?:src|href)=["']([^"']+)["']""")


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def resolve(src: str, target: str) -> str | None:
    """Repo-relative path a relative Markdown link points at, or None for URLs, anchors and mail links."""
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("/"):
        return None
    parts: list[str] = []
    for seg in PurePosixPath(src).parent.joinpath(target).parts:
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        elif seg != ".":
            parts.append(seg)
    return "/".join(parts)


def under(path: str, dirs: list[str]) -> bool:
    return any(path == d or path.startswith(d + "/") for d in dirs)


DOC_REF = re.compile(r"docs/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+")
PRODUCT_DIRS = ("src/", "learning/", "academy-ui/src/", "splunk_app/", "gateway/", "deploy/", "config/", "agentsec")


def product_refs(files: set[str], read) -> set[str]:
    """docs/ paths the product itself names (code, learning content, UI, app, config): they must ship with it."""
    refs: set[str] = set()
    for f in files:
        if f.startswith(PRODUCT_DIRS) and f.endswith((".py", ".json", ".ts", ".tsx", ".md", ".xml", ".conf", ".yaml", ".yml", ".sh", ".template", "")):
            try:
                refs.update(m.rstrip(".") for m in DOC_REF.findall(read(f)))
            except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
                pass
    return refs & files


def closure(files: set[str], cfg: dict, read) -> set[str]:
    """Documents under docs/ (and what they link to) reachable from the public roots and the product's own references; excluded dirs are never entered."""
    seen: set[str] = set()
    todo = [r for r in cfg["roots"] if r in files] + [r for r in product_refs(files, read) if not under(r, cfg["excluded_dirs"])]
    while todo:
        cur = todo.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if not cur.endswith(".md"):
            continue
        text = read(cur)
        targets = [m.group(3) for m in LINK.finditer(text)] + HTML_SRC.findall(text)
        for t in targets:
            p = resolve(cur, t)
            if p and p in files and not under(p, cfg["excluded_dirs"]):
                todo.append(p)
    return seen


def select(files: list[str], cfg: dict, read) -> tuple[list[str], list[tuple[str, str]]]:
    fs = set(files)
    reach = closure(fs, cfg, read)
    keep, drop = [], []
    allowed = set(cfg.get("allowed_top_level", []))
    for f in files:
        if allowed and f.split("/", 1)[0] not in allowed:
            drop.append((f, "not on the export allowlist"))
        elif f in cfg.get("included_files", []):
            keep.append(f)
        elif under(f, cfg["excluded_dirs"]) and not under(f, cfg.get("included_dirs", [])):
            drop.append((f, "internal record (excluded directory)"))
        elif f in cfg["excluded_files"] or any(fnmatch.fnmatch(f, g) for g in cfg["excluded_tests"]):
            drop.append((f, "excluded by name"))
        elif f.startswith("docs/") and f not in reach and not under(f, cfg.get("included_dirs", [])):
            drop.append((f, "not linked from any public document"))
        else:
            keep.append(f)
    return keep, drop


def drop_test_functions(text: str, names: list[str]) -> str:
    """Remove top-level test functions (with decorators) that assert on documents which are not exported."""
    import ast
    lines = text.splitlines(keepends=True)
    spans = []
    for n in ast.parse(text).body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names:
            start = min([n.lineno] + [d.lineno for d in n.decorator_list])
            spans.append((start - 1, n.end_lineno))
    for a, b in sorted(spans, reverse=True):
        del lines[a:b]
    return "".join(lines)


UNPUBLISHED = re.compile(r"`?(?:docs/(?:reviews|design|screenshots|security|ops)/[A-Za-z0-9_./*-]*|\.cursor/[A-Za-z0-9_./*-]*)`?")


def mention(m: re.Match, kept: set[str]) -> str:
    return m.group(0) if m.group(0).strip("`") in kept else "an unpublished internal record"


def rewrite(src: str, text: str, kept: set[str], note: str) -> str:
    """Links to files that are not exported become plain text (images become their alt text); so do bare path mentions of unpublished records."""
    def sub(m: re.Match) -> str:
        bang, label, target = m.group(1), m.group(2), m.group(3)
        p = resolve(src, target)
        if p is None or p in kept or p.rstrip("/") in kept or any(k.startswith(p.rstrip("/") + "/") for k in kept):
            return m.group(0)
        return label if bang else f"{label} {note}" if note else label
    return UNPUBLISHED.sub(lambda m: mention(m, kept), LINK.sub(sub, text))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = Path(argv[1])
    if out.exists():
        print(f"{out} exists; refusing to overwrite")
        return 2
    cfg = json.loads((ROOT / "scripts/public_export.json").read_text())
    files = tracked(ROOT)
    keep, drop = select(files, cfg, lambda p: (ROOT / p).read_text(encoding="utf-8"))
    kept = set(keep)
    for f in keep:
        dst = out / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / f).read_bytes()
        if f in cfg.get("excluded_test_functions", {}):
            data = drop_test_functions(data.decode("utf-8"), cfg["excluded_test_functions"][f]).encode("utf-8")
        if f.endswith(".md"):
            data = rewrite(f, data.decode("utf-8"), kept, cfg.get("private_note", "")).encode("utf-8")
        dst.write_bytes(data)
        dst.chmod((ROOT / f).stat().st_mode & 0o777)
    lines = [f"exported {len(keep)} of {len(files)} tracked files", ""] + [f"{why}\t{f}" for f, why in drop]
    (out.parent / (out.name + ".MANIFEST.txt")).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(lines[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
