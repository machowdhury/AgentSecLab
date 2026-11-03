"""The attack tier refuses with structured JSON, never an HTML page: the Academy and scripts must be able to tell a role refusal (403) or a quota (429)
from a broken service. Static check of the shipped config; the live behaviour is in test_gateway_runtime.py / test_gateway_browser.py (opt-in)."""
from pathlib import Path

CONF = (Path(__file__).resolve().parents[2] / "gateway/attack-enabled.conf").read_text()


def test_denials_are_json_and_say_nothing_ran():
    block = CONF[CONF.index("location @attack_denied"):]
    block = block[:block.index("\n}\n")]
    assert "default_type application/json;" in block
    assert "return 429 '{\"error\":\"rate_limited\"" in block and "Retry-After" in block
    assert "return 403 '{\"error\":\"forbidden\"" in block and "Nothing ran." in block
