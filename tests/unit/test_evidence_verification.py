"""Attack Service evidence verification without Docker: REST where configured (also in BUNDLED mode), and three honest states."""
from pathlib import Path

from agentsec import evidence_readiness as er
from agentsec import splunk_client as sc


def _env(tmp_path, **extra):
    tok = tmp_path / "tok"; tok.write_text("t" * 20); tok.chmod(0o600)
    return {"AGENTSEC_SPLUNK_REST_URL": "https://splunk.example.org:8089", "AGENTSEC_SPLUNK_SEARCH_TOKEN_FILE": str(tok), **extra}


def test_bundled_mode_with_rest_settings_uses_the_strict_client_not_docker(tmp_path):
    env = _env(tmp_path)
    assert sc.rest_configured(env) and not [f for f in sc.validate_config(env) if f.level == "ERROR"]
    assert isinstance(sc.client_for_mode(env), sc.SplunkRestClient)
    assert er.select_probe(env) is not er.probe_splunk_count        # a lambda over the client; the docker probe is not chosen


def test_bundled_without_a_token_file_keeps_the_docker_probe_and_warns(tmp_path):
    env = {"AGENTSEC_SPLUNK_REST_URL": "https://splunk.example.org:8089"}
    assert not sc.rest_configured(env) and sc.client_for_mode(env) is None
    assert er.select_probe(env) is er.probe_splunk_count
    assert ("WARN", "EXTERNAL_SETTINGS_IGNORED") in [(f.level, f.code) for f in sc.validate_config(env)]


def test_invalid_rest_settings_never_fall_back_to_docker(tmp_path):
    env = _env(tmp_path, AGENTSEC_SPLUNK_REST_URL="http://splunk.example.org:8089")      # not https
    got = er.select_probe(env)("run-1")
    assert got["error"] == "probe_misconfigured" and got["splunk_ok"] is False and got["splunk_count"] is None


class _Client:
    def __init__(self, text): self.text = text
    def export_csv(self, spl): return self.text


def test_the_three_states(tmp_path, monkeypatch):
    art = tmp_path / "a"; (art / "r1").mkdir(parents=True); (art / "r1" / "events.jsonl").write_text('{"a":1}\n')
    ok = er.wait_for_searchable_evidence("r1", artifacts_dir=art, timeout_seconds=0, probe_fn=lambda r: er.probe_splunk_count_client(r, client=_Client("n\n1\n")))
    assert (ok["verification"], ok["splunk_verified"]) == ("VERIFIED", True)
    none = er.wait_for_searchable_evidence("r1", artifacts_dir=art, timeout_seconds=0, probe_fn=lambda r: er.probe_splunk_count_client(r, client=_Client("n\n0\n")))
    assert (none["verification"], none["splunk_verified"]) == ("NOT VERIFIED", False)
    gone = er.wait_for_searchable_evidence("r1", artifacts_dir=art, timeout_seconds=0, probe_fn=lambda r: {"splunk_attempted": False, "splunk_ok": False, "splunk_count": None, "error": "docker_not_available"})
    assert (gone["verification"], gone["splunk_verified"], gone["evidence_state"]) == ("VERIFICATION UNAVAILABLE", False, "EVIDENCE_CHECK_UNAVAILABLE")
    assert er.rollup_evidence([gone, ok])["verification"] == "VERIFICATION UNAVAILABLE" and er.rollup_evidence([ok])["verification"] == "VERIFIED"
