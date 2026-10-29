"""Always-on (no browser) contract for the redesigned AcmeBank template: ids, aria, landmarks and read-only markers."""
from __future__ import annotations

import re

from agentsec.attack_app import AcmeBankClient, create_app as create_attack_app


def _bank(settings):
    from agentsec.bank_app import build_runtime, create_app
    return create_app(build_runtime(settings, otel_enabled=False)).test_client().get("/").get_data(as_text=True)


def test_bank_page_contract(settings):
    html = _bank(settings)
    for needle in ('id="loan-form"', 'id="input"', 'name="input"', 'id="submit-loan"', 'id="ui-status"', 'id="run-id"', 'id="copy-run-id"',
                   'id="result-json"', 'id="behind-the-ai"', 'id="session-history"', 'role="status"', 'id="ab-steps"', 'for="input"',
                   'aria-describedby="input-hint"', 'Simulated bank', 'acmebank.css', '<main id="main"', 'class="skip-link"'):
        assert needle in html, needle
    assert len(re.findall(r"<h1[ >]", html)) == 1


def test_read_only_page_contract():
    app = create_attack_app(AcmeBankClient("http://acmebank.example:5000"))
    html = app.test_client().get("/acmebank").get_data(as_text=True)
    for needle in ('id="readonly-notice"', "DOCUMENTED", 'id="behind-the-ai"', 'id="go-workbench"', "Simulated bank", 'class="ab-hero"'):
        assert needle in html, needle
    assert "<script" not in html and 'id="loan-form"' not in html
    assert len(re.findall(r"<h1[ >]", html)) == 1
