"""Prepared, NOT executed by the installer core: provenance checks for pinned images and models.

`image_pin_plan` turns images.lock into the exact read-only registry queries (`docker buildx imagetools inspect`), and `compare_image_digest` judges a query's output
against the pin. `verify_models` judges an Ollama /api/tags payload against models.lock. Both take their input as data, so tests use fakes and the live
verification is a later, explicit step on a disposable host (it needs registry access)."""
from __future__ import annotations

import json
import re
from typing import Callable

from agentsec.installer.config import DIGEST_RE, Finding, Locks
from agentsec import model_names

SHA = re.compile(r"sha256:[0-9a-f]{64}")


def image_pin_plan(locks: Locks) -> list[dict]:
    """[{name, ref, expected, argv}] for every Splunk version in the lock (and the other pinned images). Nothing is run."""
    out = []
    sp = locks.images["splunk"]
    for key, e in sorted(sp["versions"].items()):
        ref = f"{sp['repository']}:{e['tag']}"
        out.append({"name": f"splunk {key}", "ref": ref, "expected": e.get("digest"), "status": e["status"], "argv": ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .}}", ref]})
    for key, e in locks.images["others"].items():
        if isinstance(e, dict) and e.get("ref"):
            out.append({"name": key, "ref": e["ref"], "expected": e.get("digest"), "status": "pinned" if e.get("digest") else "unpinned",
                        "argv": ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .}}", e["ref"]]})
    return out


def _digests(output: str) -> set[str]:
    try:
        doc = json.loads(output)
    except ValueError:
        return set(SHA.findall(output or ""))
    found: set[str] = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "digest" and isinstance(v, str) and SHA.fullmatch(v):
                    found.add(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(doc)
    return found


def compare_image_digest(item: dict, output: str | None) -> Finding:
    """MATCH: the pin appears among the registry's digests for that tag (manifest list or a platform image). DIFFERS: the tag now points elsewhere (re-pushed)."""
    name, exp = item["name"], item.get("expected")
    if output is None:
        return Finding("WARN", "IMAGE_PIN_UNREADABLE", f"{name}: the registry did not answer; the pin was not checked")
    seen = _digests(output)
    if not exp:
        return Finding("WARN", "IMAGE_UNPINNED", f"{name}: no digest is pinned; the registry reports {sorted(seen)[:2]}")
    if not DIGEST_RE.match(exp):
        return Finding("ERROR", "IMAGE_PIN_MALFORMED", f"{name}: the pinned digest is not sha256:<64 hex>")
    if exp in seen:
        return Finding("OK", "IMAGE_PIN_MATCH", f"{name}: the registry still serves the pinned digest for {item['ref']}")
    return Finding("ERROR", "IMAGE_PIN_DIFFERS", f"{name}: {item['ref']} no longer points at the pinned digest (re-pushed tag); the pin is kept, qualify the new digest before changing it")


def verify_image_pins(locks: Locks, runner: Callable[[list[str]], tuple[int, str]]) -> list[Finding]:
    """Executes the read-only queries through `runner` (real runner = a later step on a host with registry access)."""
    out = []
    for item in image_pin_plan(locks):
        rc, text = runner(item["argv"])
        out.append(compare_image_digest(item, text if rc == 0 else None))
    return out


def _hex(d: str | None) -> str | None:
    return d.split(":", 1)[-1].lower() if d else None


def verify_models(locks: Locks, resolved: dict, tags_payload: object, *, allow_missing: bool = False) -> list[Finding]:
    """Judge what Ollama reports (/api/tags payload) against the requested models and models.lock. Exact names only."""
    out: list[Finding] = []
    if not (isinstance(tags_payload, dict) and isinstance(tags_payload.get("models"), list)):
        return [Finding("WARN", "OLLAMA_MODEL_LIST_UNREADABLE", "Ollama's model list could not be read; no model was verified")]
    models = [m for m in tags_payload["models"] if isinstance(m, dict)]
    for role, name in sorted(resolved.items()):
        want = model_names.normalize(name)
        hits = [m for m in models if str(m.get("name") or m.get("model") or "") == want]
        if len({_hex(m.get("digest")) for m in hits}) > 1:
            out.append(Finding("ERROR", "MODEL_AMBIGUOUS", f"{role}: Ollama lists {want} more than once with different digests"))
            continue
        if not hits:
            out.append(Finding("WARN" if allow_missing else "ERROR", "MODEL_ABSENT", f"{role}: Ollama has no model named exactly {want}; nothing else will be used in its place (`ollama pull {want}`)"))
            continue
        observed = _hex(hits[0].get("digest"))
        pinned = _hex((locks.models["models"].get(name) or locks.models["models"].get(want) or {}).get("digest"))
        if pinned and observed and pinned != observed:
            out.append(Finding("ERROR", "MODEL_DIGEST_MISMATCH", f"{role}: {want} is installed but its digest ({observed[:12]}) is not the pinned one ({pinned[:12]}): the tag was re-pushed or a different model was imported"))
        elif pinned and observed:
            out.append(Finding("OK", "MODEL_PINNED_MATCH", f"{role}: {want} matches the pinned digest {observed[:12]}"))
        else:
            out.append(Finding("WARN", "MODEL_UNPINNED", f"{role}: {want} is installed with digest {(observed or 'not reported')[:12]}; models.lock has no pinned digest for it"))
    return out
