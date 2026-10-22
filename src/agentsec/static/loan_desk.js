/* Loan Desk page. All dynamic text goes through textContent: names, notes and tool results are untrusted. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var FIELDS = ["full_name", "annual_income", "credit_score", "loan_amount", "term_years", "province", "employment", "notes"];
  var RULES = {
    annual_income: [10000, 2000000, false, "Annual income"], credit_score: [300, 900, true, "Credit score"],
    loan_amount: [10000, 5000000, false, "Loan amount"], term_years: [5, 35, true, "Term (years)"]
  };
  var EXAMPLE = {
    full_name: "Priya Chen", annual_income: "118000", credit_score: "740", loan_amount: "420000", term_years: "25",
    province: "ON", employment: "full_time", notes: "First-time buyer, relocating for work."
  };
  var PHASES = ["submitted", "reasoning", "policy", "tool", "done"];
  var poll = null;

  if (window.AgentSecUI && window.AgentSecUI.rewriteLearnerLinks) { window.AgentSecUI.rewriteLearnerLinks(document); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined) { n.textContent = text; }
    return n;
  }
  function tag(text, kind) { return el("span", "ld-tag" + (kind ? " ld-tag--" + kind : ""), text); }

  /* ---------- model status ---------- */
  fetch("/api/v1/loan-desk/status").then(function (r) { return r.json(); }).then(function (s) {
    var chip = $("model-chip"), banner = $("model-banner");
    if (s.available) {
      chip.dataset.state = "READY";
      chip.textContent = "Model ready · " + s.model + " via Ollama";
    } else {
      chip.dataset.state = "UNAVAILABLE";
      chip.textContent = "Model unavailable · " + s.model;
      banner.hidden = false;
      banner.textContent = (s.reason || "The model is not available.") + " You can still submit; the run will fail visibly and no tool will run.";
    }
  }).catch(function () {
    $("model-chip").dataset.state = "UNAVAILABLE";
    $("model-chip").textContent = "Model status unknown";
  });

  /* ---------- form ---------- */
  function clearErrors() {
    FIELDS.forEach(function (f) {
      $("err-" + f).textContent = "";
      $(f).removeAttribute("aria-invalid");
      var desc = ["err-" + f]; if ($("hint-" + f)) { desc.unshift("hint-" + f); }
      $(f).setAttribute("aria-describedby", desc.join(" "));
    });
    var box = $("form-errors"); box.hidden = true; box.textContent = "";
  }
  function showErrors(errors) {
    var names = [];
    Object.keys(errors).forEach(function (k) {
      if (FIELDS.indexOf(k) >= 0) {
        $("err-" + k).textContent = errors[k];
        $(k).setAttribute("aria-invalid", "true");
        names.push(k);
      } else {
        var box = $("form-errors"); box.hidden = false; box.textContent = errors[k];
      }
    });
    if (names.length) {
      var box2 = $("form-errors"); box2.hidden = false;
      box2.textContent = "Please fix " + names.length + " field" + (names.length > 1 ? "s" : "") + " below.";
      box2.focus();
      $(names[0]).focus();
    }
  }
  function clientErrors(v) {
    var e = {};
    if (!/^[A-Za-z][A-Za-z .'-]{1,59}$/.test(v.full_name.trim())) { e.full_name = "Enter a name using letters only (2-60 characters)."; }
    Object.keys(RULES).forEach(function (k) {
      var r = RULES[k], raw = v[k].trim();
      if (raw === "") { e[k] = r[3] + " is required."; return; }
      var n = Number(raw);
      if (!isFinite(n) || (r[2] && Math.floor(n) !== n)) { e[k] = r[3] + (r[2] ? " must be a whole number." : " must be a number."); return; }
      if (n < r[0] || n > r[1]) { e[k] = r[3] + " must be between " + r[0].toLocaleString("en-US") + " and " + r[1].toLocaleString("en-US") + "."; }
    });
    if (!v.province) { e.province = "Choose a province."; }
    if (!v.employment) { e.employment = "Choose an employment status."; }
    return e;
  }
  function values() { var v = {}; FIELDS.forEach(function (f) { v[f] = $(f).value; }); return v; }

  $("example").addEventListener("click", function () {
    FIELDS.forEach(function (f) { $(f).value = EXAMPLE[f]; });
    clearErrors();
  });

  /* ---------- progress and rendering ---------- */
  function setPhase(active, failed) {
    var items = $("phases").children;
    for (var i = 0; i < items.length; i += 1) {
      items[i].dataset.s = i < active ? "done" : i === active ? (failed ? "failed" : "active") : "";
    }
  }
  function phaseFor(view) {
    var ev = (view.timeline && view.timeline.events) || [], last = ev.length ? ev[ev.length - 1] : null;
    if (view.status === "COMPLETED") { return [5, false]; }
    if (view.status === "INCOMPLETE") { return [4, true]; }
    if (view.status === "FAILED") { return [1, true]; }
    if (!last) { return [1, false]; }
    switch (last.event) {
      case "agentsec.agent.action.proposed": return [2, false];
      case "agentsec.control.decision": return [last.decision === "ALLOW" ? 3 : 1, false];
      case "agentsec.mcp.started": return [3, false];
      default: return [1, false];
    }
  }
  function liveText(view) {
    if (view.status === "COMPLETED") { return "Review finished: the model produced a recommendation after " + view.timeline.tool_calls.length + " proposed action(s)."; }
    if (view.status === "FAILED") {
      return view.stop_reason === "model_unavailable"
        ? "The model could not be reached. No action was proposed, no policy decision was made and no tool ran. Detail: " + (view.error || "unknown")
        : "The review failed (" + view.stop_reason + "). " + (view.error || "");
    }
    if (view.status === "INCOMPLETE") { return "The agent hit its step budget before finishing. No recommendation was produced."; }
    var ev = view.timeline.events, n = ev.length;
    return n ? "Working… " + n + " event(s) recorded." : "Starting…";
  }
  function describe(args) {
    var parts = Object.keys(args || {}).map(function (k) { return k + "=" + JSON.stringify(args[k]); });
    return parts.join(", ");
  }
  function renderTimeline(view) {
    var ol = $("timeline"); ol.textContent = "";
    var calls = {}; (view.timeline.tool_calls || []).forEach(function (c) { calls[c.step] = c; });
    view.steps.forEach(function (s) {
      var li = el("li", "ld-tl");
      if (s.kind === "tool") {
        var c = calls[s.step] || {}, d = s.decision, p = s.proposal;
        li.dataset.d = d.decision;
        li.appendChild(el("p", "ld-tl__title", "Step " + s.step + " · " + p.tool));
        var tags = el("div", "ld-tags");
        tags.appendChild(tag("PROPOSED by " + (p.source === "model" ? "model" : "SCRIPTED TEST DOUBLE (not model-driven)"), "src"));
        tags.appendChild(tag(d.decision === "ALLOW" ? "POLICY: ALLOW" : "POLICY: DENY", d.decision === "ALLOW" ? "yes" : "no"));
        var ran = c.executed === true;
        tags.appendChild(tag(ran ? "HANDLER BEGAN" : "HANDLER DID NOT RUN", ran ? "yes" : "no"));
        li.appendChild(tags);
        li.appendChild(el("p", "", "Arguments: " + describe(p.arguments) + (p.coerced && p.coerced.length ? "  (numeric text converted for: " + p.coerced.join(", ") + ")" : "")));
        li.appendChild(el("p", "", "Policy " + d.control_id + ": " + d.reason + " · scope " + d.scope + (d.resource ? " · resource " + d.resource : "")));
        if (s.error) { li.appendChild(el("p", "", "Handler error: " + s.error)); }
        else if (s.result_preview) { li.appendChild(el("p", "", "Result returned to the model as untrusted data: " + s.result_preview)); }
        else if (d.decision === "DENY") { li.appendChild(el("p", "", "No result: the handler never began, so nothing was read or changed.")); }
      } else if (s.kind === "final") {
        li.dataset.d = "final";
        li.appendChild(el("p", "ld-tl__title", "Step " + s.step + " · final answer from the model"));
        li.appendChild(el("p", "", "The model stopped proposing actions and wrote its recommendation."));
      } else {
        li.dataset.d = "invalid";
        li.appendChild(el("p", "ld-tl__title", "Step " + s.step + " · unusable model reply"));
        li.appendChild(el("p", "", "Reason: " + s.reason + ". Nothing was proposed, so policy had nothing to decide."));
      }
      ol.appendChild(li);
    });
    $("timeline-card").hidden = view.steps.length === 0;
  }
  function renderEvidence(view) {
    var ev = view.evidence;
    $("evidence-card").hidden = false;
    $("ev-run").textContent = ev.run_id;
    $("ev-count").textContent = ev.event_count + " emitted by AcmeBank (LOCAL evidence, " + ev.schema + ")";
    var sp = ev.splunk || {}, node = $("ev-indexed"), msg = {
      NOT_VERIFIED: "NOT VERIFIED. " + (sp.detail || "Only local evidence exists.") + " Run the search below in Splunk, or press Verify with Splunk.",
      PENDING: "VERIFYING… the host verifier is running fixed, read-only Splunk searches for this run.",
      VERIFIER_OFFLINE: "NOT VERIFIED. The host verifier is not running, so nothing can confirm indexing.",
      TIMED_OUT: "NOT VERIFIED. The host verifier did not answer in time. Try again.",
      VERIFICATION_FAILED: "NOT VERIFIED. The host check could not complete: " + (sp.detail || "unknown"),
      INVALID_RECORD: "NOT VERIFIED. A reconciliation record failed authentication and was ignored.",
      SPLUNK_VERIFIED: "SPLUNK-VERIFIED by the host verifier at " + sp.checked_at + ": " + sp.indexed_events + " indexed of " + sp.local_events + " local events.",
      SPLUNK_MISMATCH: "SPLUNK MISMATCH. Indexed " + sp.indexed_events + " of " + sp.local_events + " local events: " + (sp.problems || []).join(", "),
      STALE: "STALE. The last host check no longer matches this run's event count."
    };
    node.textContent = msg[ev.indexed_status] || msg.NOT_VERIFIED;
    node.dataset.state = ev.indexed_status;
    $("ev-model").textContent = view.model.name + " via " + view.model.provider + " · proposals from: " + view.model.proposal_source;
    $("ev-spl").value = ev.splunk_search;
    $("ev-download").setAttribute("href", "/api/v1/loan-desk/runs/" + encodeURIComponent(ev.run_id) + "/events.ndjson");
  }
  var RECO = { PROCEED_TO_UNDERWRITER: "Proceed to underwriter", NEEDS_MORE_INFORMATION: "Needs more information", NOT_RECOMMENDED: "Not recommended" };
  var SEC = { BLOCKED: "BLOCKED", NOTHING_BLOCKED: "Nothing needed blocking" };
  var BIZ = { COMPLETE: "COMPLETE", INCOMPLETE: "INCOMPLETE", FAILED: "FAILED", RUNNING: "RUNNING" };
  function renderOutcome(view) {
    var o = view.outcomes, card = $("outcome-card");
    var done = view.status !== "RUNNING";
    card.hidden = !done;
    if (!done) { return; }
    $("out-security").dataset.v = o.security.outcome; $("out-business").dataset.v = o.business.outcome;
    $("out-security-v").textContent = SEC[o.security.outcome] + (o.security.blocked.length ? " (" + o.security.blocked.length + " action" + (o.security.blocked.length > 1 ? "s" : "") + ")" : "");
    $("out-business-v").textContent = BIZ[o.business.outcome] + (o.business.reason ? " · " + o.business.reason : "");
    var p = o.operations;
    $("out-ops").textContent = "Proposed " + p.proposed + " · authorized " + p.authorized + " · denied " + p.denied + " · executed " + p.executed +
      (p.denied_but_executed ? " · DENIED-BUT-EXECUTED " + p.denied_but_executed + " (a control failure)" : " · no denied action ran");
    var ul = $("out-blocked"); ul.textContent = "";
    o.security.blocked.forEach(function (b) {
      ul.appendChild(el("li", "", "Step " + b.step + " " + b.tool + ": " + b.reason + (b.executed ? " — EXECUTED ANYWAY" : " — handler did not run")));
    });
  }
  function renderFacts(view) {
    var f = view.facts, card = $("facts-card");
    card.hidden = !(f && f.items && f.items.length);
    if (card.hidden) { return; }
    $("facts-basis").textContent = f.basis;
    var dl = $("facts-list"); dl.textContent = "";
    f.items.forEach(function (i) {
      var v = typeof i.value === "number" ? i.value.toLocaleString("en-US", { maximumFractionDigits: 2 }) : i.value;
      dl.appendChild(el("dt", "", i.label));
      dl.appendChild(el("dd", "", v + (i.unit ? " " + i.unit : "") + "  ·  " + i.source));
    });
    var ul = $("screening"); ul.textContent = "";
    f.screening.forEach(function (c) { var li = el("li", "", c.rule + ": " + c.result); li.dataset.r = c.result; ul.appendChild(li); });
    $("screening-v").textContent = "Screening result: " + f.screening_result.replace(/_/g, " ");
  }
  function render(view) {
    var st = $("run-status"); st.dataset.state = view.status; st.textContent = view.status;
    var ph = phaseFor(view); setPhase(ph[0], ph[1]);
    $("live").textContent = liveText(view);
    renderTimeline(view); renderEvidence(view); renderOutcome(view); renderFacts(view);
    var adv = view.advisory;
    if (view.status === "COMPLETED" && adv) {
      $("result-card").hidden = false;
      $("reco").textContent = (RECO[adv.recommendation] || adv.recommendation) + (adv.differs_from_screening ? " (differs from rule-based screening)" : "");
      $("summary").textContent = adv.summary;
      var w = $("claims-warn"), bad = adv.unsupported_figures || [];
      w.hidden = bad.length === 0;
      w.textContent = bad.length ? "Figures in this text that no tool result or computation supports: " + bad.join(", ") + ". Do not rely on them." : "";
    } else { $("result-card").hidden = true; }
  }

  function stopPolling() { if (poll) { clearTimeout(poll); poll = null; } }
  function finish() { $("submit").disabled = false; $("submit").textContent = "Submit application"; $("loan-form").setAttribute("aria-busy", "false"); }
  function watch(runId, started) {
    fetch("/api/v1/loan-desk/runs/" + encodeURIComponent(runId)).then(function (r) { return r.json(); }).then(function (view) {
      render(view);
      if (view.status === "RUNNING" && Date.now() - started < 180000) { poll = setTimeout(function () { watch(runId, started); }, 600); }
      else { finish(); }
    }).catch(function () {
      $("run-status").dataset.state = "FAILED"; $("run-status").textContent = "FAILED";
      $("live").textContent = "Lost contact with AcmeBank while the review was running. The run may still be executing; its run.id is shown above if it was created.";
      finish();
    });
  }

  $("loan-form").addEventListener("submit", function (event) {
    event.preventDefault();
    if ($("submit").disabled) { return; }
    stopPolling(); clearErrors();
    var v = values(), errs = clientErrors(v);
    if (Object.keys(errs).length) { showErrors(errs); return; }
    $("submit").disabled = true; $("submit").textContent = "Submitting…"; $("loan-form").setAttribute("aria-busy", "true");
    ["result-card", "timeline-card", "evidence-card", "outcome-card", "facts-card"].forEach(function (id) { $(id).hidden = true; });
    var st = $("run-status"); st.dataset.state = "RUNNING"; st.textContent = "RUNNING";
    setPhase(0, false); $("live").textContent = "Submitting your application…";
    fetch("/api/v1/loan-desk/applications", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(v) })
      .then(function (r) { return r.json().then(function (b) { return { status: r.status, body: b }; }); })
      .then(function (res) {
        if (res.status === 202) { setPhase(1, false); watch(res.body.run_id, Date.now()); return; }
        st.dataset.state = "IDLE"; st.textContent = "IDLE"; setPhase(-1, false);
        $("live").textContent = "The application was not accepted. Nothing was run.";
        showErrors(res.body.errors || { _form: "The application could not be submitted." });
        finish();
      })
      .catch(function () {
        st.dataset.state = "FAILED"; st.textContent = "FAILED"; setPhase(-1, false);
        $("live").textContent = "Could not reach AcmeBank. Nothing was run.";
        finish();
      });
  });

  function copy(id, labelId) {
    var node = $(id), text = node.value || node.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text); }
    else if (node.select) { node.select(); document.execCommand("copy"); }
    $(labelId).textContent = "Copied";
    setTimeout(function () { $(labelId).textContent = labelId === "copy-run" ? "Copy run.id" : "Copy search"; }, 1500);
  }
  $("refresh-ev").addEventListener("click", function () {
    var id = $("ev-run").textContent, btn = $("refresh-ev");
    if (!id) { return; }
    btn.disabled = true;
    function settle(msg) { $("ev-indexed").textContent = msg; btn.disabled = false; }
    fetch("/api/v1/loan-desk/runs/" + encodeURIComponent(id) + "/verify", { method: "POST" }).then(function (r) {
      if (r.status === 503) { settle("NOT VERIFIED. The verifier is not installed on this lab."); return; }
      if (r.status !== 202 && r.status !== 429) { settle("The verification request was not accepted (HTTP " + r.status + ")."); return; }
      var t0 = Date.now();
      (function tick() {
        fetch("/api/v1/loan-desk/runs/" + encodeURIComponent(id)).then(function (x) { return x.json(); }).then(function (v) {
          render(v);
          if (v.evidence.indexed_status === "PENDING" && Date.now() - t0 < 160000) { setTimeout(tick, 2000); } else { btn.disabled = false; }
        }).catch(function () { settle("Could not reach AcmeBank to read the result."); });
      }());
    }).catch(function () { settle("Could not reach AcmeBank to request verification."); });
  });
  $("copy-run").addEventListener("click", function () { copy("ev-run", "copy-run"); });
  $("copy-spl").addEventListener("click", function () { copy("ev-spl", "copy-spl"); });
}());
