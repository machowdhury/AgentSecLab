#!/usr/bin/env python3
"""Serve one source tree (AcmeBank + Attack Service, stub LLM, no OTLP, temp artifacts) for the preservation browser walk.
Usage: PYTHONPATH=<tree>/src python preservation_servers.py <tree> <attack_port> <bank_port>   (run with cwd=<tree>)
The LLM is the repository's own labelled StubLLM, so both trees behave deterministically."""
import os, sys, tempfile, threading, time
tree, ap, bp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.chdir(tree); sys.path.insert(0, tree + "/src")
os.environ.update(AGENTSEC_OTEL_ENABLED="false", AGENTSEC_SECURITY_PROFILE="defended", AGENTSEC_ARTIFACTS_DIR=tempfile.mkdtemp(prefix="pres-srv-"),
                  AGENTSEC_LAB_ID="agentsec-local", AGENTSEC_SPLUNK_WEB_URL="http://127.0.0.1:8000", AGENTSEC_BIND_HOST="127.0.0.1")
from werkzeug.serving import make_server
from agentsec.attack_app import AcmeBankClient, create_app as attack_app
from agentsec.bank_app import build_runtime, create_app as bank_app
from agentsec.llm import StubLLM
from agentsec.settings import get_settings
rt = build_runtime(get_settings(), llm=StubLLM(), otel_enabled=False)
bank = make_server("127.0.0.1", bp, bank_app(rt), threaded=True)
atk = make_server("127.0.0.1", ap, attack_app(AcmeBankClient(f"http://127.0.0.1:{bp}"),
                  launch_kwargs={"probe_fn": lambda rid: {"splunk_attempted": False, "splunk_ok": False, "splunk_count": 0, "error": "stubbed"}}), threaded=True)
for s in (bank, atk):
    threading.Thread(target=s.serve_forever, daemon=True).start()
print("ready", flush=True)
while True:
    time.sleep(3600)
