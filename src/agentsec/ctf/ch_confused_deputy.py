"""Confused Deputy Relay (Advanced).

Engines: the EXISTING identity delegation lab (agentsec.identity.pipeline.run_identity_delegation, A2A-001, CTRL-IDENTITY-001) and the
EXISTING MCP-006 deputy lab (agentsec.mcp.delegation_pipeline.run_mcp_006_invoke, CTRL-DELEGATION-001), each driven in-process with a
CTF-owned MemorySink. SIMULATED delegation model, NOT A2A: no A2A transport, no agent cards, no real agents. The server sequences the two
runs (claim, then relay); the engines stay independent, so the claim run does not technically feed the relay run. Success is read from each
run's recorded authorization/delegation decisions and handler events.
"""

from __future__ import annotations

import dataclasses

from agentsec.agents import COMPLIANCE_ID, CREDIT_ID
from agentsec.ctf.registry import Challenge, register
from agentsec.ctf.scenario import ParamError, Verdict, posture, strict_params
from agentsec.identity.fixtures import IDENTITY_ATTACK_ID, adversarial_a2a_payload
from agentsec.identity.pipeline import run_identity_delegation
from agentsec.mcp.delegation import MCP006_FAIL_OPEN_REASON
from agentsec.mcp.delegation_pipeline import run_mcp_006_invoke
from agentsec.mcp.fixtures import MCP_CUSTOMER_SCOPE, MCP_LOOKUP_TIER_ARGS
from agentsec.mcp.registry import default_registry
from agentsec.settings import get_settings
from agentsec.telemetry import MemorySink
from agentsec.timeline import build_timeline

CHALLENGE = register(Challenge(
    id="confused-deputy-relay", title="Confused Deputy Relay", difficulty="Advanced", points=300,
    technique="Confused deputy: a low-privilege caller obtains a restricted resource by relaying through a more privileged agent",
    control_boundary=("CTRL-IDENTITY-001 (an identity claim is not a grant, OBSERVE) and CTRL-DELEGATION-001 (the deputy may act only "
                      "within the authority delegated to it, DENY in the hardened posture)"),
    objective=("In two server-sequenced steps, present the delegation claim and then relay the request through the deputy so a low-privilege "
               "principal's request is executed under the deputy's authority, in the baseline posture. (You may also run the hardened posture to compare; that run is not scored.)"),
    learning_outcome=("A deputy must act on the caller's delegated authority, never its own ambient authority. Verify delegation at the point of "
                      "use, and treat an identity claim as data. Defended mode denies because the delegated set excludes the restricted tool."),
    simulation="SIMULATED",
    simulation_note=("SIMULATED delegation model, NOT A2A: in-process coded agents and fixtures, no A2A transport or agent cards. The two steps "
                     "are separate runs the server sequences; they are two independent engine checks sequenced by the server, not one cryptographic chain. Nothing is sent to Splunk by this challenge."),
    engine="delegation", hint=("Step 1 shows what the callee does with a claimed scope. Step 2 asks who actually executes the restricted tool, and "
                               "under whose authority. Run both in the same posture."), max_steps=2))

STEPS = ("claim", "relay")


def _step(value: object) -> str:
    if value not in STEPS:
        raise ParamError("bad_step")
    return value  # type: ignore[return-value]


class ConfusedDeputyRelay:
    challenge = CHALLENGE

    def validate(self, params: object, prior_steps: list[str]) -> dict:
        clean = strict_params(params, {"posture": posture, "step": _step})
        if clean["step"] != STEPS[len(prior_steps)]:
            raise ParamError("wrong_step_order")
        return clean

    def execute(self, params: dict, step_index: int) -> tuple[str, dict]:
        baseline = params["posture"] == "baseline"
        sink = MemorySink()
        settings = dataclasses.replace(get_settings(), security_profile="vulnerable" if baseline else "defended")
        mode = "ATTACK" if baseline else "RETEST"
        if params["step"] == "claim":
            res = run_identity_delegation(payload=adversarial_a2a_payload(), sink=sink, memory=sink, settings=settings, testbed_mode=mode,
                                          registry=default_registry(), write_evidence=False)
        else:
            res = run_mcp_006_invoke(tool="lookup_customer_tier", arguments=dict(MCP_LOOKUP_TIER_ARGS), requested_scope=MCP_CUSTOMER_SCOPE,
                                     sink=sink, memory=sink, settings=settings, testbed_mode=mode, registry=default_registry(), write_evidence=False)
        return str(res.run_id), {"events": list(sink.events), "step": params["step"]}

    @staticmethod
    def _profile_ok(events: list[dict], attack_id: str) -> bool:
        started = [e for e in events if e.get("event.name") == "agentsec.run.started"]
        return bool(started) and all(e.get("agentsec.security.profile") == "vulnerable" and e.get("agentsec.attack.id") == attack_id for e in started)

    def verify(self, bundles: list[dict]) -> Verdict:
        claim, relay = bundles
        cc = build_timeline(claim["events"], run_id=claim["run_id"], source="LIVE")["tool_calls"]
        rc = build_timeline(relay["events"], run_id=relay["run_id"], source="LIVE")["tool_calls"]
        claim_observed = any(c["control_id"] == "CTRL-IDENTITY-001" and c["decision"] == "OBSERVE" for c in cc)
        claim_ran = any(c["control_id"] == "CTRL-MCP-001" and c["tool"] == "lookup_customer_tier" and c["decision"] == "ALLOW" and c["executed"]
                        and str(c["reason"]).startswith("vulnerable_profile_fail_open:") for c in cc)
        deleg = [e for e in relay["events"] if e.get("agentsec.control.id") == "CTRL-DELEGATION-001" and e.get("agentsec.control.decision") == "ALLOW"
                 and e.get("agentsec.control.reason") == MCP006_FAIL_OPEN_REASON and e.get("agentsec.delegation.authority.source") == "ambient_deputy"
                 and e.get("gen_ai.agent.id") == CREDIT_ID]
        ran = [e for e in relay["events"] if e.get("event.name") == "agentsec.mcp.started" and e.get("gen_ai.tool.name") == "lookup_customer_tier"
               and e.get("agentsec.operation.executed") is True and e.get("gen_ai.agent.id") == COMPLIANCE_ID
               and e.get("agentsec.delegator.agent.id") == CREDIT_ID]
        checks = (
            ("both steps ran in the baseline posture (vulnerable profile)", self._profile_ok(claim["events"], IDENTITY_ATTACK_ID)
             and self._profile_ok(relay["events"], "MCP-006")),
            ("step 1: CTRL-IDENTITY-001 observed the delegation claim as data", claim_observed),
            ("step 1: the claimed restricted tool was ALLOWED on claim-derived authority and executed", claim_ran),
            ("step 2: CTRL-DELEGATION-001 ALLOWED the relay on the deputy's ambient authority for the credit-agent caller", bool(deleg)),
            ("step 2: the restricted tool executed under the deputy (compliance agent), not under the caller's delegated authority", bool(ran)),
            ("step 2: the same call is ALLOWED and executed per the recorded authorization decision", any(
                c["control_id"] == "CTRL-MCP-001" and c["tool"] == "lookup_customer_tier" and c["decision"] == "ALLOW" and c["executed"] for c in rc)),
        )
        ok = all(p for _, p in checks)
        return Verdict(ok, "A low-privilege caller's request executed the restricted tool under the deputy's authority." if ok else
                       "Objective not met: the restricted tool did not execute under the wrong principal across both baseline steps.", checks)

    def materials(self) -> dict:
        return {"kind": "delegation", "steps": list(STEPS), "postures": ["baseline", "hardened"],
                "model": "SIMULATED delegation model, NOT A2A", "restricted_tool_class": "customer-tier lookup (customer:read)"}


SCENARIO = ConfusedDeputyRelay()
