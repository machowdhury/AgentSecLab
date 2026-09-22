# Agent identity / delegation LIVE learning loop

**Lab:** LAB-AGENT-DELEGATION-001 / A2A-001  
**Schema:** 1.9.0  
**Studio:** `ws_lab_agent_delegation` (REPLAY syllabus). LIVE investigation is Splunk Search.

## WHAT IS IT?

A learner-operated LIVE purple-team loop for the existing identity/delegation lab. The browser launches a closed experiment. AcmeBank enforces. Splunk copies telemetry.

## WHY DOES IT EXIST?

So a learner can prove that a caller/delegation **claim** is not a **grant**, and that an identity **string** is not **authentication**.

## HOW DOES IT WORK?

1. Predict.
2. Launch LIVE ATTACK (vulnerable overlay).
3. Copy run.id. Hunt in Splunk Search.
4. Defend: claims are data; coded policy is authority; CTRL-MCP-001 is the tool PDP.
5. Launch LIVE RETEST with the same frozen request (defended).
6. Compare. Prove. Classify evidence.

## WHERE DOES IT SIT IN AGENTSEC?

After PI, MCP, RAG, Memory, and Goal Integrity LIVE labs. Same ExperimentContext / Attack Service architecture. Identity control stays OBSERVE. MCP stays the tool PDP.

## WHAT IS THE TRUST BOUNDARY?

Between an identity/delegation claim and coded grants. Between OBSERVE and tool authorization.

## WHAT COULD AN ATTACKER CONTROL?

The closed adversarial fixture (claimed customer:read / lookup_customer_tier / cust-001). Not profile, grants, identity_verified, or authenticated.

## WHAT CAN GO WRONG?

Treating caller_agent_id as authentication. Treating IDENTITY OBSERVE as ALLOW. Treating A+B as a union of imagined permissions. Treating Splunk as the PDP.

## WHAT TELEMETRY SHOULD EXIST?

principal, caller, callee, claimed scope, CTRL-IDENTITY-001, requested tool/scope/resource, CTRL-MCP-001, mcp.* / handler counts, request fingerprint.

## HOW WILL SPLUNK SHOW IT?

Q-AGENT-DELEGATION-AUTHORITY plus Q-MCP-AUTHZ / TOOL / EXECUTED. Path A then Path B. Bound tables are 12C REPLAY.

## WHAT CONTROL COULD CHANGE THE RESULT?

Server-owned ExperimentContext profile feeding CTRL-MCP-001. IDENTITY still only OBSERVEs.

## WHAT TEST PROVES THE LOGIC?

Offline pytest in `tests/unit/test_phase15e_identity_learning_loop.py` (suite **848 passed, 2 deselected**). LIVE ATTACK `110dd7a6-58b5-472a-ae80-aec76e11bf4e` 10=10 / RETEST `7e4f74a8-84bf-4d18-abe1-0dcc7f0ab58a` 9=9 in `PHASE15E_SPLUNK_LIVE_VALIDATION.md`.

## What I should now be able to explain

1. Why IDENTITY CLAIM != AUTHENTICATION.
2. Why DELEGATION CLAIM != AUTHORIZATION.
3. Why CALLER ID != GRANT.
4. Why OBSERVE != ALLOW.
5. Why CTRL-IDENTITY-001 is not a tool PDP.
6. Why neither agent possesses customer:read, so A+B cannot mint it.
7. What ATTACK overlay does and why it is labeled vulnerable.
8. What RETEST must keep the same and what must change.
9. What Splunk can prove and what it cannot prove.
10. Why DET-MCP-001 silence is not SAFE, and why DET-A2A was not created.
