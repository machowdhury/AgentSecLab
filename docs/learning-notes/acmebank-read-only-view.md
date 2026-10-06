# Serving WORLD 1 without exposing the vulnerable target

## What is it?

`GET /acmebank` on the Attack Service (port 5001) renders the AcmeBank customer
page read-only: the same template, with the loan form, the `/process` call and
every line of client script removed.

## Why does it exist?

The MCP golden path starts with the business story — an ordinary customer
applying for a home loan — because the security lesson only lands if you first
understand what normal looks like. But AcmeBank binds to `127.0.0.1:5000` on the
lab host and is not reachable from a browser, so a remote learner could never
read step one.

The obvious fix is the wrong one. AcmeBank is a deliberately vulnerable LLM
target; publishing it would hand anyone who finds the port a prompt-injection
playground with a real model behind it. `tests/security/test_remote_listener_bindings.py`
pins the loopback binding on purpose. So the requirement is to show the page
without exposing the service.

## How does it work?

The Attack Service already listens on 5001 and both apps already share
`TEMPLATE_DIR`. So the route renders `acmebank.html` directly with
`read_only=True`. Nothing is forwarded.

Only two values come from the target: the security profile and the model name,
over the fixed `/health` probe the Attack Service already makes for
`/api/target-health`. When AcmeBank is unreachable they render `NOT MEASURED`,
because a page that cannot see the profile must not assert one.

## Where does it sit in AgentSec?

Between the learner's browser and the lab host, on the service whose entire job
is to be the untrusted HTTP client. It is the first screen of the LAB-MCP-001
journey, linked from the workbench's WORLD 1 panel.

## What is the trust boundary?

```
browser  ->  Attack Service (5001, exposed)  ->  AcmeBank (5000, loopback only)
```

The Attack Service sits on the boundary. Anything it forwards on a caller's
behalf crosses from the public internet into the lab host's network.

## What could an attacker control?

Only the HTTP request to 5001: method, path, query string, headers, body. The
route consumes none of them. There is no `?target=`, no path pass-through, no
body forwarding.

## What can go wrong?

This is the failure mode worth remembering: **a convenience view quietly becoming
a proxy.** Two small changes would each be a real vulnerability.

- Accept a caller-supplied upstream, and you have server-side request forgery —
  an attacker reaches `169.254.169.254` or anything else on the host's network,
  from inside it.
- Forward POST, and the browser can reach `/process`, which is exactly what the
  loopback binding exists to prevent.

Neither looks like a security change in review. Both look like "make the page a
bit more useful." That is why they are tested rather than merely intended.

## What telemetry should exist?

None specific to this route, and that is deliberate. It renders documentation;
it mints no `run.id`, invokes no tool, and reaches no control. Emitting
telemetry here would put non-events into the index a learner then has to
explain away. The page is labelled DOCUMENTED for the same reason.

## How will Splunk show it?

It will not, and should not. If you see a `run.id` while reading this page,
something is wrong.

## What control could change the result?

The listener binding in `docker-compose.yml`. Setting `AGENTSEC_BIND_ADDRESS`
on the AcmeBank mapping would make this route unnecessary and the lab unsafe.
That is the trade the route exists to avoid.

## What test proves the logic?

`tests/security/test_acmebank_read_only_view.py` (17 tests): GET-only, upstream
parameters ignored, no form, no `/process`, no script, the teaching content
preserved, and AcmeBank's own page unchanged. The guards were mutation-tested —
turning the route into a POST-accepting proxy and shipping the form both make
them fail.

## What I should now be able to explain

1. Why exposing AcmeBank on a public port would be a security regression rather
   than a usability improvement.
2. The difference between rendering a template and proxying a request, and why
   only one of them creates a server-side request forgery surface.
3. What an attacker gains from a caller-supplied upstream on a service that sits
   inside the lab host's network.
4. Why forwarding POST specifically would defeat the loopback binding.
5. Why the profile and model read `NOT MEASURED` instead of falling back to the
   Attack Service's own settings.
6. Why this route deliberately emits no telemetry, and what would be wrong with
   the evidence if it did.
7. Why removing the form is the control, and a disabled submit button would not
   be.
8. How a mutation test shows a guard is load-bearing rather than decorative.
