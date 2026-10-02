# Attack Service learning console

The Attack Service is still a closed educational launcher. The browser can record a prediction and a short list of run ids for this tab. That list is not telemetry, not an account, and not a verdict.

A prediction is ALLOW, DENY, ERROR, or UNKNOWN for the control, and YES, NO, or UNKNOWN for execution. It stays in `sessionStorage`. The launch request body is still `lab_id`, `specimen_id`, `mode`, and `execution`.

`run.id` is the handle you copy into Splunk Search. REQUEST ACCEPTED means the launcher accepted the specimen. It is not authorization. RUN DENIED is a control outcome. BACKEND UNAVAILABLE is infrastructure. RUN TIMED OUT is not a DENY. RUN COMPLETED is not proof the attack succeeded.

The page asks for the prediction. It does not print the control decision or the execution result before the launch.

After a reload, the history line keeps the last painted client state and labels it that way. A launcher terminal is shown only when this tab stored it or the launcher record is still available. That line is not a Splunk verdict. The ATTACK versus RETEST panel is rebuilt only for the newest ATTACK and RETEST that share the same lab id.

Search links keep using the host already in the address bar.

## What I should now be able to explain

1. Why is a prediction not a Splunk event?
2. Why is REQUEST ACCEPTED not authorization?
3. Why is RUN DENIED different from BACKEND UNAVAILABLE?
4. Why is run.id not a verdict?
5. Why does session history not create an identity?
6. Why must Search links follow the browser host on a remote deployment?
7. Why is ALLOW still separate from llm_call_count?
