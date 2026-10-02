# Guided learning experience

## What is it?

AgentSec's Academy is a path through the existing L0–L10 workshops. Each workshop opens with where you are, the lesson, the next action, an inline Splunk search, and what that search does not prove.

## Why does it exist?

A learner was getting lost in a large menu and was sent to Splunk Search for the normal investigation. The workshops and the evidence rules stay. The navigation and the first investigation step change.

## How does it work?

`learning/academy/curriculum.json` is the order. `scripts/apply_guided_learning.py` writes the grouped navigation and a guide band on the first tab of each workshop. A LIVE workshop adds an empty **LIVE run.id** text token. The table searches `agentsec_telemetry` only when that token is non-empty. A REPLAY workshop that already has an Investigate specimen reuses that token. A workshop with no run token gets the orientation band only.

Your path is a classic Splunk view, `learner_path`, with app JavaScript. It stores NOT STARTED, IN PROGRESS, and INVESTIGATED in `localStorage`. Reset removes that key. It does not delete an index.

Arena is a separate view after Mastery. It links to the same LIVE launchers.

## Where does it sit in AgentSec?

It sits in the Academy, in front of the existing tabs. Attack Service still launches. AcmeBank still decides. Splunk still stores and searches. Splunk does not ALLOW or DENY.

## What is the trust boundary?

The pasted run.id is an investigation handle. Retrieved rows are a Splunk copy. Browser progress and Attack Service session history are last known client state. They are not indexed evidence.

## What could an attacker control?

A learner can paste any string into the run.id box. The search is constrained to `agentsec_telemetry` and that token. The box does not grant a tool. Arena does not add a grant.

## What can go wrong?

An empty table can be misread as DENY. A decision row can be misread as execution. A progress mark can be misread as mastery. Studio cannot pull a fresh run.id from Attack Service, so a learner can investigate the wrong id if they paste the wrong value.

## What telemetry should exist?

The same schema 1.9.0 events as before. The guide table reads `event.name`, `agentsec.control.decision`, `agentsec.operation.executed`, and related fields. It does not create a new event.

## How will Splunk show it?

The workshop table and the summary table are Dashboard Studio searches. Search remains available for a learner who wants to edit the SPL.

## What control could change the result?

The runtime controls, including CTRL-MCP-001 for tool authorization. Changing the dashboard does not change those decisions. DET-MCP-001 stays disabled.

## What test proves the logic?

`tests/splunk/test_guided_learning.py` checks navigation, guide metadata, the empty LIVE token, and the security contracts. `tests/unit/test_learner_progress.py` executes the browser progress and session helpers. A rendered Splunk page is a separate measurement and is not claimed by those tests.

## What I should now be able to explain

1. Why is Arena not the landing page?
2. Why does a LIVE workshop ask you to paste a run.id?
3. Why is an empty table not DENY?
4. Which event is a control decision, and which event is execution?
5. What does Your path persist, and what does Reset leave untouched?
6. Why is REPLAY not a weaker conclusion than LIVE?
7. Why does browser session history say LAST KNOWN CLIENT STATE?
8. What would be wrong with treating `executed=true` as a downstream resource change?
