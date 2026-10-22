"""Links for the shared surface bar (templates/_shell_bar.html).

Pages never contain a host name. Same-origin links are relative. The AcmeBank app (port 5000) and
Splunk Web (port 8000) are other origins: their links carry data-shell-port and static/shell.js
completes them from the hostname the browser is already using. No link carries a token,
credential or run state.
"""

from __future__ import annotations

import os

ATTACK_PORT = os.getenv("ATTACK_SERVICE_PORT", "5001")
SPLUNK_WEB_PORT = "8000"


def shell_links(path: str, *, surface: str) -> dict:
    if surface == "acmebank_app":
        active, port = "acmebank", ATTACK_PORT  # this app is not the Attack Service: hop across origins
        acme = "/"
    else:
        active = "academy" if path.startswith("/academy") else ("acmebank" if path.startswith("/acmebank") else "attack")
        port, acme = "", "/acmebank"
    return {"active": active, "service_port": port, "acmebank": acme, "splunk_port": SPLUNK_WEB_PORT,
            "splunk_path": "/en-US/app/agentsec/learner_path"}
