"""Prepared, not executed: pin provenance checks, model verification and the Splunk compatibility matrix are tested with data, never a registry or an Ollama."""
import json
from pathlib import Path
import pytest
from agentsec.installer import provenance as P
from agentsec.installer.config import Locks

LOCKS = Locks.load()
ROOT = Path(__file__).resolve().parents[2]
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def test_the_pin_plan_lists_one_read_only_query_per_pinned_image_and_runs_nothing():
    plan = P.image_pin_plan(LOCKS)
    names = {i["name"] for i in plan}
    assert {"splunk 10.2", "splunk 10.4", "splunk 10.6", "nginx", "otel_collector"} <= names
    for i in plan:
        assert i["argv"][:4] == ["docker", "buildx", "imagetools", "inspect"] and "pull" not in i["argv"] and "run" not in i["argv"]
    assert next(i for i in plan if i["name"] == "splunk 10.4")["ref"] == "splunk/splunk:10.4.4"


@pytest.mark.parametrize("output,expected,level,code", [
    (json.dumps({"manifest": {"digest": D2}, "image": {"linux/amd64": {"digest": D1}}}), D1, "OK", "IMAGE_PIN_MATCH"),       # a per-platform digest counts
    (json.dumps({"manifest": {"digest": D1}}), D1, "OK", "IMAGE_PIN_MATCH"),                                               # so does the list digest
    (json.dumps({"manifest": {"digest": D2}}), D1, "ERROR", "IMAGE_PIN_DIFFERS"),                                           # the tag was re-pushed
    (f"Digest: {D1}\n", D1, "OK", "IMAGE_PIN_MATCH"),                                                                       # plain text output
    (json.dumps({"manifest": {"digest": D2}}), None, "WARN", "IMAGE_UNPINNED"),
    (None, D1, "WARN", "IMAGE_PIN_UNREADABLE"),
    (json.dumps({"manifest": {"digest": D1}}), "sha256:short", "ERROR", "IMAGE_PIN_MALFORMED"),
])
def test_digest_comparison(output, expected, level, code):
    f = P.compare_image_digest({"name": "x", "ref": "r:1", "expected": expected}, output)
    assert (f.level, f.code) == (level, code)


def test_verify_image_pins_uses_the_runner_for_every_query_and_maps_failures():
    seen = []
    def runner(argv):
        seen.append(argv)
        return (1, "") if argv[-1].endswith("10.6.1") else (0, json.dumps({"digest": "sha256:" + "9" * 64}))
    res = P.verify_image_pins(LOCKS, runner)
    assert len(seen) == len(P.image_pin_plan(LOCKS)) == len(res)
    by = {f.message.split(":")[0]: f.code for f in res}
    assert by["splunk 10.6"] == "IMAGE_PIN_UNREADABLE" and by["splunk 10.2"] == "IMAGE_PIN_DIFFERS"


# ---- Ollama model verification ------------------------------------------------------------------------------------------------------------------
RES = {"pipeline": "llama3.2:1b", "loan_desk": "llama3.2:latest"}
PIN = LOCKS.models["models"]["llama3.2:latest"]["digest"].split(":", 1)[1]


def tags(*pairs):
    return {"models": [{"name": n, "digest": d} for n, d in pairs]}


def codes(payload, **kw):
    return {(f.level, f.code) for f in P.verify_models(LOCKS, RES, payload, **kw)}


def test_pinned_match_unpinned_mismatch_absent():
    got = codes(tags(("llama3.2:1b", "abc"), ("llama3.2:latest", PIN)))
    assert ("OK", "MODEL_PINNED_MATCH") in got and ("WARN", "MODEL_UNPINNED") in got
    assert ("ERROR", "MODEL_DIGEST_MISMATCH") in codes(tags(("llama3.2:1b", "abc"), ("llama3.2:latest", "f" * 64)))
    assert ("ERROR", "MODEL_ABSENT") in codes(tags(("llama3.2:1b", "abc")))
    assert ("WARN", "MODEL_ABSENT") in codes(tags(("llama3.2:1b", "abc")), allow_missing=True)


@pytest.mark.parametrize("installed", ["llama3.2:1b-instruct-q8_0", "LLAMA3.2:LATEST", "xllama3.2:latest", "llama3.2"])
def test_only_the_exact_name_counts(installed):
    got = codes(tags((installed, PIN)))
    assert ("ERROR", "MODEL_ABSENT") in got and ("OK", "MODEL_PINNED_MATCH") not in got


def test_the_digest_prefix_form_does_not_matter_but_ambiguity_does():
    assert ("OK", "MODEL_PINNED_MATCH") in codes(tags(("llama3.2:latest", "sha256:" + PIN), ("llama3.2:1b", "x")))
    assert ("ERROR", "MODEL_AMBIGUOUS") in codes(tags(("llama3.2:latest", PIN), ("llama3.2:latest", "e" * 64), ("llama3.2:1b", "x")))


@pytest.mark.parametrize("payload", [None, {}, {"models": "x"}, [], "text", 7])
def test_an_unreadable_model_list_verifies_nothing_and_does_not_crash(payload):
    assert codes(payload) == {("WARN", "OLLAMA_MODEL_LIST_UNREADABLE")}


# ---- the Splunk compatibility matrix ------------------------------------------------------------------------------------------------------------
def test_the_compatibility_matrix_covers_every_version_and_claims_nothing_has_run():
    m = json.loads((ROOT / "deploy/splunk_compat_matrix.json").read_text())
    assert set(m["versions"]) == set(LOCKS.images["splunk"]["versions"])
    ids = [r["id"] for r in m["rows"]]
    assert len(ids) == len(set(ids)) >= 10 and {"boot", "rest", "spl", "hec", "app", "volumes", "upgrade_copy", "security"} <= set(ids)
    for r in m["rows"]:
        assert r["status"] == "NOT_RUN" and set(r["versions"]) <= set(m["versions"]) and r["test"] and r["pass"]
    for v in m["versions"]:
        assert any(v in r["versions"] for r in m["rows"])                          # every version has tests to pass
    # a version may only be `tested` in the lock when no applicable row is NOT_RUN: today only the RC1-verified default is tested, by RC1 evidence rather than this matrix
    tested = [k for k, e in LOCKS.images["splunk"]["versions"].items() if e["status"] == "tested"]
    assert tested == ["10.2"]
