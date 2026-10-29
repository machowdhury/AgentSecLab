/* CTF challenge page. Talks only to same-origin /api/ctf. Renders with textContent (never innerHTML). Holds no answer and decides nothing:
   the server verifies, signs and scores. */
(function () {
  "use strict";
  var root = document.querySelector("[data-ctf-challenge]");
  if (!root) return;
  var cid = root.getAttribute("data-ctf-challenge");
  var total = parseInt(root.getAttribute("data-max-steps"), 10) || 1;
  var att = null;
  var ERR = {
    rate_limited: "Too many requests. Wait and try again.", attempt_not_active: "This attempt is not active. Start a new attempt.",
    all_steps_done: "All steps are already done. Ask the server to verify.", steps_incomplete: "Finish every step before verifying.",
    wrong_step_order: "Run the steps in order, once each.", bad_note: "That note was refused (empty, too long, or it looks like real personal data).",
    bad_parameters: "The request was not accepted.", invalid_receipt: "Receipt rejected: it is malformed or its signature does not verify.",
    already_redeemed: "Receipt rejected: it was already redeemed. A receipt scores once.", receipt_mismatch: "Receipt rejected: it does not belong to this attempt.",
    attempt_not_redeemable: "Receipt rejected: this attempt is not in a redeemable state (reset, failed or superseded).", receipt_expired: "Receipt rejected: it has expired.",
    run_not_owned: "Verification refused: a run is not owned by this attempt.", evidence_unavailable: "The server no longer holds this attempt's events. Reset and retry.",
    local_only: "The CTF answers local clients only.", scenario_failed: "The scenario could not run. Try again.", network: "Could not reach the server."
  };

  function q(sel) { return root.querySelector(sel); }
  function api(method, path, body) {
    var opt = { method: method, credentials: "same-origin", headers: { "Content-Type": "application/json" } };
    if (body !== undefined) opt.body = JSON.stringify(body);
    return fetch(path, opt).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, body: j }; }, function () { return { status: r.status, body: { error: "bad_response" } }; });
    }, function () { return { status: 0, body: { error: "network" } }; });
  }
  function say(text, kind) { var s = q("#ctf-status"); s.textContent = text; s.setAttribute("data-kind", kind || ""); }
  function fail(res) { say(ERR[res.body && res.body.error] || "The request was refused.", "error"); }
  function btn(act, step) { return root.querySelectorAll('[data-act="' + act + '"]' + (step ? '[data-step="' + step + '"]' : "")); }
  function enable(list, on) { Array.prototype.forEach.call(list, function (b) { b.disabled = !on; }); }
  function line(tag, text, cls) { var e = document.createElement(tag); e.textContent = text; if (cls) e.className = cls; return e; }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function render(a) {
    att = a;
    q("#attempt-id").textContent = a.attempt_id;
    q("#attempt-state").textContent = a.state + (a.expired ? " (expired)" : "");
    q("#attempt-steps").textContent = a.steps_done.length + " of " + a.steps_total;
    var active = (a.state === "NEW" || a.state === "RUNNING") && !a.expired;
    var more = active && a.steps_done.length < a.steps_total;
    var form = q("#run-form");
    Array.prototype.forEach.call(form.querySelectorAll('[data-act="run"]'), function (b) {
      var step = b.getAttribute("data-step");
      b.disabled = !more || (step && a.steps_done.indexOf(step) !== -1);
    });
    enable(btn("verify"), active && a.steps_done.length === a.steps_total);
    enable(btn("reset"), a.state !== "RESET");
    enable(btn("redeem"), !!a.redeemable);
    var runs = q("#run-list"); clear(runs);
    a.runs.forEach(function (r) { var li = document.createElement("li"); li.appendChild(line("span", r.step + ": run.id ")); li.appendChild(line("code", r.run_id)); runs.appendChild(li); });
    var vc = q("#verdict-card");
    if (a.verdict) {
      vc.hidden = false; q("#verdict-summary").textContent = (a.state === "VERIFIED" ? "VERIFIED. " : "NOT ACHIEVED. ") + a.verdict.summary;
      var ul = q("#verdict-checks"); clear(ul);
      a.verdict.checks.forEach(function (c) { ul.appendChild(line("li", (c.passed ? "✓ PASSED: " : "✗ NOT MET: ") + c.check)); });
    } else { vc.hidden = true; }
    var rc = q("#receipt-card");
    if (a.receipt && a.state === "VERIFIED") { rc.hidden = false; var ta = q("#receipt-json"); if (!ta.dataset.attempt || ta.dataset.attempt !== a.attempt_id) { ta.value = JSON.stringify(a.receipt, null, 1); ta.dataset.attempt = a.attempt_id; } }
    else { rc.hidden = true; }
    var sc = q("#splunk-card");
    if (a.runs.length) {
      sc.hidden = false; q("#splunk-detail").textContent = a.splunk.detail + (a.splunk.link_note ? " " + a.splunk.link_note : "");
      var ul2 = q("#splunk-runs"); clear(ul2);
      a.splunk.runs.forEach(function (r) {
        var li = document.createElement("li"); li.appendChild(line("span", "run.id ")); li.appendChild(line("code", r.run_id));
        li.appendChild(line("br", "")); li.appendChild(line("span", "Search: ")); li.appendChild(line("code", r.search));
        if (r.link) { var link = document.createElement("a"); link.href = r.link; link.textContent = " Open in Splunk Search"; li.appendChild(link); }
        ul2.appendChild(li);
      });
    } else { sc.hidden = true; }
  }

  function runBody(button) {
    var form = q("#run-form"), kind = form.getAttribute("data-kind");
    var body = { posture: form.querySelector('input[name="posture"]:checked').value };
    if (kind === "loan_desk") body.note = form.querySelector("#note").value;
    if (kind === "catalog") body.tool = form.querySelector("#tool").value;
    if (kind === "delegation") body.step = button.getAttribute("data-step");
    return body;
  }

  q("#run-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (!att) return;
    var button = ev.submitter || q('[data-act="run"]');
    say("Running the scenario...", "");
    api("POST", "/api/ctf/attempts/" + att.attempt_id + "/run", runBody(button)).then(function (r) {
      if (r.status === 200) { render(r.body); say("Recorded. " + (r.body.steps_done.length < r.body.steps_total ? "Run the next step." : "Now ask the server to verify."), "ok"); } else fail(r);
    });
  });
  root.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-act]");
    if (!b || b.type === "submit") return;
    var act = b.getAttribute("data-act");
    if (act === "start") {
      api("POST", "/api/ctf/challenges/" + cid + "/attempts", {}).then(function (r) { if (r.status === 201) { render(r.body); say("New attempt started with a new id.", "ok"); } else fail(r); });
    } else if (act === "verify" && att) {
      api("POST", "/api/ctf/attempts/" + att.attempt_id + "/verify", {}).then(function (r) { if (r.status === 200) { render(r.body); say(r.body.state === "VERIFIED" ? "Verified by the server. Redeem the receipt to score." : "Not achieved. Reset to try again.", r.body.state === "VERIFIED" ? "ok" : "error"); } else fail(r); });
    } else if (act === "reset" && att) {
      api("POST", "/api/ctf/attempts/" + att.attempt_id + "/reset", {}).then(function (r) { if (r.status === 200) { render(r.body); say("Attempt reset. Start a new attempt to retry.", "ok"); } else fail(r); });
    } else if (act === "redeem" && att) {
      var parsed;
      try { parsed = JSON.parse(q("#receipt-json").value); } catch (_e) { say(ERR.invalid_receipt, "error"); return; }
      api("POST", "/api/ctf/attempts/" + att.attempt_id + "/redeem", { receipt: parsed }).then(function (r) {
        if (r.status === 200) { say("Redeemed: " + r.body.awarded + " points awarded. Total " + r.body.scoreboard.total + ".", "ok"); api("GET", "/api/ctf/attempts/" + att.attempt_id).then(function (g) { if (g.status === 200) render(g.body); }); }
        else fail(r);
      });
    } else if (act === "hint") {
      api("GET", "/api/ctf/challenges/" + cid + "/hint").then(function (r) { var h = q("#hint-text"); h.hidden = false; h.textContent = r.status === 200 ? "Hint: " + r.body.hint : "No hint for this challenge."; });
    }
  });

  api("GET", "/api/ctf/challenges/" + cid).then(function (r) {
    if (r.status === 200 && r.body.current_attempt) api("GET", "/api/ctf/attempts/" + r.body.current_attempt).then(function (g) { if (g.status === 200) render(g.body); });
  });
})();
