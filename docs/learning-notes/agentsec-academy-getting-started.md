# Getting started with the AgentSec Academy

AgentSec is a hands-on range for **agentic security**: how an LLM-backed agent requests tools, how retrieved or stored text can influence those requests, and how a coded control actually grants or denies them.

You do not need this repository’s source tree to learn. You need Home, Attack Service, and Splunk Search.

Splunk is the notebook. Splunk does **not** grant or deny authority. AcmeBank (the runtime) is the enforcement point. Attack Service is a closed launcher. You never choose grants, tools, or profiles in the browser.

---

## Where to start

1. Open **Home** (default view in the AgentSec app).
2. Read **START**, then **ORIENT** if the words agent / MCP / RAG / PDP are new.
3. Skim **PATH** so you know Foundations → Context Security → Agent Intent → Capstone.
4. Use **SPLUNK** for the short Search bootcamp, then the CHECK claims (not scored).
5. Primary action: **Direct Prompt Injection**. If you already know agents, tools, and RAG, skip ORIENT and go to that lab, then Attack Service. You still need run.id → Search.
6. After the labs, **Mastery Check** is optional self-assessment. It is not a certificate.

Then keep this loop: predict → launch → copy `run.id` → investigate in Search (Path A) → optional Path B → defend → retest → compare → prove.

---

## Words that matter

**LIVE** — you mint a fresh `run.id` from Attack Service.  
**REPLAY** — canonical specimens already in the index; no launcher.  
**BASELINE** — a normal run. Not SAFE.  
**ATTACK** — labeled vulnerable experiment. Success is not universal vulnerability.  
**RETEST** — same adversarial bytes, defended configuration. One RETEST is not universal security.  
**OBSERVE** — classification. Not ALLOW.  
**PDP** — the control that authorizes or denies the dangerous operation. Some controls only OBSERVE.  
**Path A** — you type SPL. **Path B** — optional answer key, not policy.

---

## What I should now be able to explain

1. Why Splunk is evidence and not a policy decision point.
2. Why a tool request is not a grant.
3. Why retrieved or stored text is data, not authority.
4. Why an identity or delegation *claim* is not authentication.
5. Why an authorized tool is not an authorized goal.
6. Why missing Splunk events are not prevention.
7. Why Path B is optional and does not replace Search.
8. Why the capstone is last, after Goal and Identity.
9. What LIVE vs REPLAY means for a `run.id` you did not launch.
10. What you still cannot conclude from one successful RETEST.
