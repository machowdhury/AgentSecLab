"""Poisoned Catalog (Advanced).

Engine: the EXISTING LAB-MCP-CATALOG path of agentsec.mcp.pipeline.run_mcp_invoke (attack id MCP-CATALOG-001): an in-process tools/list-shaped
snapshot whose lookup_policy description carries a hidden follow-on instruction, CTRL-MCP-METADATA-001 (OBSERVE only, never DENY), and the
vulnerable-profile metadata overlay. SIMULATED in-process catalog: there is no MCP transport and no external MCP server. No rug-pull.
Success is read from the run's recorded control decisions and handler events (agentsec.timeline), never from text.
"""

from __future__ import annotations

import dataclasses

from agentsec.ctf.registry import Challenge, register
from agentsec.ctf.scenario import ParamError, Verdict, posture, strict_params
from agentsec.mcp.catalog import FIXTURE_MALICIOUS, build_catalog_snapshot
from agentsec.mcp.fixtures import MCP_CUSTOMER_SCOPE, MCP_LOOKUP_POLICY_ARGS, MCP_LOOKUP_TIER_ARGS, MCP_POLICY_SCOPE
from agentsec.mcp.metadata_trust import METADATA_CONTROL_ID, METADATA_IS_DATA_REASON, MCP_CATALOG_FAIL_OPEN_REASON
from agentsec.mcp.pipeline import run_mcp_invoke
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings
from agentsec.telemetry import MemorySink
from agentsec.timeline import build_timeline

CHALLENGE = register(Challenge(
    id="poisoned-catalog", title="Poisoned Catalog", difficulty="Advanced", points=300,
    technique="Tool-description (catalog metadata) poisoning: a hidden follow-on instruction inside data an agent reads",
    control_boundary=("CTRL-MCP-METADATA-001 classifies catalog metadata as untrusted data but only OBSERVES it; the allowlist control "
                      "CTRL-MCP-001 is what holds in the hardened posture"),
    objective=("Read the simulated tool catalog, find the tool whose description carries a hidden instruction, and call that tool in the "
               "baseline posture so the hidden follow-on tool runs. (You may also run the hardened posture to compare; that run is not scored.)"),
    learning_outcome=("Metadata is data and cannot grant authority. An OBSERVE-only control records the poisoned entry but does not stop it; "
                      "the server-owned allowlist is what denies the follow-on call. Detection is not prevention."),
    simulation="SIMULATED",
    simulation_note=("SIMULATED in-process catalog (a tools/list-shaped snapshot built in this process). It is NOT an external MCP server and "
                     "there is no MCP transport. No rug-pull is modelled. Nothing is sent to Splunk by this challenge."),
    engine="mcp_catalog", hint=("Descriptions are written by whoever publishes the tool. Compare each description with what the tool's name "
                                "promises, and note which entry asks the agent to do something else first."), max_steps=1))

TOOLS = {"lookup_policy": (MCP_POLICY_SCOPE, MCP_LOOKUP_POLICY_ARGS), "lookup_customer_tier": (MCP_CUSTOMER_SCOPE, MCP_LOOKUP_TIER_ARGS)}
FOLLOW_ON = "lookup_customer_tier"


def _tool(value: object) -> str:
    if not isinstance(value, str) or value not in TOOLS:
        raise ParamError("bad_tool")
    return value


class PoisonedCatalog:
    challenge = CHALLENGE

    def validate(self, params: object, prior_steps: list[str]) -> dict:
        return strict_params(params, {"posture": posture, "tool": _tool})

    def execute(self, params: dict, step_index: int) -> tuple[str, dict]:
        baseline = params["posture"] == "baseline"
        sink = MemorySink()
        scope, args = TOOLS[params["tool"]]
        settings = dataclasses.replace(get_settings(), security_profile="vulnerable" if baseline else "defended")
        result = run_mcp_invoke(tool=params["tool"], arguments=dict(args), requested_scope=scope, sink=sink, memory=sink, settings=settings,
                                testbed_mode="ATTACK" if baseline else "RETEST", attack_id="MCP-CATALOG-001", registry=default_registry(),
                                write_evidence=False)
        return str(result.run_id), {"events": list(sink.events)}

    def verify(self, bundles: list[dict]) -> Verdict:
        b = bundles[0]
        events, run_id = b["events"], b["run_id"]
        calls = build_timeline(events, run_id=run_id, source="LIVE")["tool_calls"]
        started = [e for e in events if e.get("event.name") == "agentsec.run.started"]
        observed = [c for c in calls if c["control_id"] == METADATA_CONTROL_ID and c["decision"] == "OBSERVE" and c["reason"] == METADATA_IS_DATA_REASON]
        follow = [c for c in calls if c["control_id"] == "CTRL-MCP-001" and c["tool"] == FOLLOW_ON and c["decision"] == "ALLOW"
                  and c["reason"] == MCP_CATALOG_FAIL_OPEN_REASON and c["executed"]]
        checks = (
            ("the run is a baseline catalog run (vulnerable profile, MCP-CATALOG-001)", bool(started) and all(
                e.get("agentsec.security.profile") == "vulnerable" and e.get("agentsec.attack.id") == "MCP-CATALOG-001" for e in started)),
            ("CTRL-MCP-METADATA-001 observed the poisoned catalog entry and did not block it", bool(observed)),
            ("the tool you called was ALLOWED and its handler executed", any(c["control_id"] == "CTRL-MCP-001" and c["decision"] == "ALLOW" and c["executed"]
                                                                              and c["tool"] == "lookup_policy" for c in calls)),
            ("the hidden follow-on tool was ALLOWED on metadata-derived authority and its handler executed", bool(follow)),
        )
        ok = all(p for _, p in checks)
        return Verdict(ok, "The hidden follow-on instruction in catalog metadata ran." if ok else
                       "Objective not met: the metadata-derived follow-on call did not execute in a baseline run.", checks)

    def materials(self) -> dict:
        snap = build_catalog_snapshot(fixture=FIXTURE_MALICIOUS)
        return {"kind": "catalog", "simulated_catalog": [{"name": t["name"], "description": t["description"]} for t in snap.tools],
                "tools": sorted(TOOLS), "postures": ["baseline", "hardened"], "transport": "none (in-process snapshot, NOT an MCP server)"}


SCENARIO = PoisonedCatalog()
