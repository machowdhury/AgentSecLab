"""Constrained read-only SPL policy (RC1 M-4): accepted dialect, adversarial rejections, audit lines, and every backend that sends SPL.
The policy is an allowlist for the application's fixed dialect; these tests do not claim arbitrary SPL can be made safe."""
import logging, random, uuid
import pytest
from agentsec import spl_policy as sp
from agentsec import splunk_client as sc
from agentsec.loan_desk import search as srch, reconcile
from agentsec.search_handoff import completeness_spl, starter_spl

RUN = str(uuid.uuid4())

ACCEPTED = [
    f'index=agentsec_telemetry sourcetype="otel:agentic:json" earliest=-24h "agentsec.run.id"="{RUN}" | stats count',
    f'search index=agentsec_telemetry "agentsec.run.id"="{RUN}" | stats count',
    "| makeresults count=1 | eval ok=1",
    "index=a x=1 | eval y=mvindex(mvdedup('f'),0) | fillnull value=\"(none)\" y | stats count AS n by y | rename y AS \"z\" | sort 0 - n | head 5 | table z n | where n>1",
    "index=a \n | stats\tcount",                                # whitespace is normalised
]


@pytest.mark.parametrize("spl", ACCEPTED)
def test_the_applications_dialect_is_accepted(spl):
    assert sp.check(spl) == " ".join(spl.split())


def test_every_query_the_application_builds_passes():
    other = str(uuid.uuid4())
    for t in srch.TEMPLATES.values():
        spl, _ = t.build(RUN, {}, other if t.runs == 2 else None)
        sp.check(spl)
    sp.check(starter_spl(RUN)); sp.check(completeness_spl(RUN))


REFUSED = {
    # subsearch closer glued to the command (the RC1 bypass: the old check saw the token 'delete]')
    "subsearch delete": ("search x [ search y | delete]", "subsearch_or_macro"),
    "subsearch outputlookup": ("search x [| makeresults | outputlookup f.csv]", "subsearch_or_macro"),
    "subsearch bare": ("index=a [search index=b | head 1]", "subsearch_or_macro"),
    # comments and macros
    "comment before command": ("index=a | ```c``` delete", "subsearch_or_macro"),
    "macro as command": ("index=a | `anything`", "subsearch_or_macro"),
    "macro in base search": ("`macro` index=a", "subsearch_or_macro"),
    # commands that are mutating, external, or simply not in the application's dialect
    "delete": ("index=a | delete", "command_not_allowed"), "no space": ("index=a |delete", "command_not_allowed"), "upper": ("index=a | DELETE", "command_not_allowed"),
    "mixed": ("index=a | DeLeTe", "command_not_allowed"), "outputlookup": ("| outputlookup t.csv", "command_not_allowed"),
    "outputtelemetry": ("index=a | outputtelemetry", "command_not_allowed"), "webhook": ("index=a | webhook url=http://x", "command_not_allowed"),
    "runshellscript": ("index=a | runshellscript x", "command_not_allowed"), "collect": ("index=a | collect index=b", "command_not_allowed"),
    "sendemail": ("index=a | eval x=1 | sendemail to=a@b.c", "command_not_allowed"), "map": ("index=a | map search=\"x\"", "command_not_allowed"),
    "rest": ("| rest /services/authentication/users", "command_not_allowed"), "inputlookup": ("| inputlookup x", "command_not_allowed"),
    "tstats": ("| tstats count where index=*", "command_not_allowed"), "from savedsearch": ("| from savedsearch:x", "command_not_allowed"),
    "loadjob": ("| loadjob 1234", "command_not_allowed"), "script": ("index=a | script python", "command_not_allowed"),
    "later search stage": ("index=a | search index=_internal", "command_not_allowed"),
    "makeresults not first": ("index=a | makeresults", "command_not_allowed"), "double makeresults": ("| makeresults | makeresults", "command_not_allowed"),
    "ldapsearch": ("index=a | ldapsearch domain=x", "command_not_allowed"), "app command": ("index=a | curl uri=http://x", "command_not_allowed"),
    "index in later stage": ("index=a | where index=b", "index_outside_base_search"),
    # quoting tricks: every pipe is a stage boundary, quoted or not
    "pipe in double quotes": ('index=a "x | delete "', "command_not_allowed"), "pipe in single quotes": ("index=a 'x | delete '", "command_not_allowed"),
    "escaped quote": ('index=a "x\\" | delete "', "command_not_allowed"), "pipe in eval string": ('index=a | eval s="a|b"', "command_not_allowed"),
    # line breaks, control and non-ASCII characters
    "newline pipe": ("index=a | head 1\n| delete", "command_not_allowed"), "NUL": ("index=a\x00 | delete", "disallowed_character"),
    "unicode lookalike": ("index=a | ｄelete", "disallowed_character"), "zero width": ("index=a | de​lete", "disallowed_character"),
    "empty": ("", "empty"), "blank": ("   ", "empty"), "search only": ("search", "empty"), "oversized": ("x" * 9000, "oversized"),
    "too many stages": ("index=a" + " | head 1" * 17, "too_many_stages"),
}


@pytest.mark.parametrize("label", sorted(REFUSED))
def test_adversarial_searches_are_refused_with_a_fixed_code(label):
    spl, code = REFUSED[label]
    with pytest.raises(sp.SplPolicyViolation) as e:
        sp.check(spl)
    assert e.value.code == code, (label, e.value.code)
    assert len(spl.strip()) < 12 or spl.strip()[:40] not in str(e.value)      # the message never echoes the search text


def test_non_string_input_is_refused():
    for bad in (None, 5, b"index=a", ["index=a"]):
        with pytest.raises(sp.SplPolicyViolation):
            sp.check(bad)


def test_randomised_mutations_never_slip_through():
    """Oracle: split on EVERY pipe; if any later stage begins with a mutating command (after any amount of obfuscation we generate) it must be refused."""
    rng = random.Random(1307)
    frags = ["index=a", "x=1", "| head 3", "| stats count", "| eval a=1", "|", " ", "\t", '"', "'", "[", "]", "`", "```c```", "(", ")", "\\", "-", "="]
    cmds = sorted(sp.KNOWN_MUTATING)
    for _ in range(3000):
        parts = [rng.choice(frags) for _ in range(rng.randint(1, 8))]
        spl = " ".join(parts)
        if rng.random() < 0.7:
            c = rng.choice(cmds); c = "".join(ch.upper() if rng.random() < .4 else ch for ch in c)
            glue = rng.choice([" | ", "|", " |\n", "\t|\t"]); spl += glue + c + rng.choice(["", " x=1", " index=b"])
        try:
            out = sp.check(spl)
        except sp.SplPolicyViolation:
            continue
        stages = [s.strip().lower() for s in out.split("|")][1:]
        assert not [s for s in stages if s.split(None, 1)[:1] and s.split(None, 1)[0].rstrip("=") in sp.KNOWN_MUTATING], spl
        assert "[" not in out and "`" not in out


def test_the_audit_line_has_a_hash_and_counts_but_never_the_search_text_or_a_secret(caplog):
    secret = "tok-9f8e7d6c5b4a"
    spl = f'index=a "agentsec.run.id"="{RUN}" | stats count'
    with caplog.at_level(logging.INFO, logger="agentsec.splunk.audit"):
        sp.checked(spl, backend="rest")
        with pytest.raises(sp.SplPolicyViolation):
            sp.checked(f"index=a {secret} | delete", backend="rest")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "ACCEPTED backend=rest" in text and "REFUSED backend=rest code=command_not_allowed" in text and sp.fingerprint(" ".join(spl.split())) in text
    assert RUN not in text and secret not in text and "delete" not in text and "stats" not in text


# ---- every path that sends SPL applies the same policy ----
def test_the_rest_client_refuses_before_any_request():
    sent = []
    cfg = sc.SplunkConfig("EXTERNAL_ENTERPRISE", "https://splunk.example:8089", "", "t", "agentsec_telemetry", 5)
    client = sc.SplunkRestClient(cfg, opener=lambda *a, **k: sent.append(a))
    for spl in ("search x [ search y | delete]", "index=a | webhook url=x", "index=a | ```c``` delete"):
        with pytest.raises(sc.SplunkError) as e:
            client.export_csv(spl)
        assert (e.value.stage, e.value.code) == ("search", "forbidden_spl")
    assert sent == []


def test_the_docker_paths_refuse_before_running_anything():
    calls = []
    runner = lambda argv, **kw: calls.append(argv)
    assert srch.DockerExecBackend("c", runner).run("index=a | outputlookup x", timeout_s=5, max_rows=5).error == "search_failed"
    with pytest.raises(RuntimeError, match="read-only policy"):
        reconcile.run_spl("index=a | delete", runner=runner)
    assert calls == []


def test_a_malformed_rest_port_is_a_configuration_error_not_a_crash():
    for url in ("https://splunk.example:abc", "https://splunk.example:99999", "https://[::1"):
        f = sc.validate_config({"AGENTSEC_SPLUNK_MODE": "EXTERNAL_ENTERPRISE", "AGENTSEC_SPLUNK_REST_URL": url, "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": "/nonexistent"})
        assert ("ERROR", "REST_URL_INVALID") in [(x.level, x.code) for x in f], url
