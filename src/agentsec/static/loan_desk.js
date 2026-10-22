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
      NOT_VERIFIED: "NOT VERIFIED. Only local evidence exists. Run the search below in Splunk, or ask the lab host to run: " + ev.host_check,
      SPLUNK_VERIFIED: "SPLUNK-VERIFIED. Host check at " + sp.checked_at + ": " + sp.indexed_events + " indexed of " + sp.local_events + " local events, reconciled.",
      SPLUNK_MISMATCH: "SPLUNK MISMATCH. Indexed " + sp.indexed_events + " of " + sp.local_events + " local events: " + (sp.problems || []).join(", "),
      STALE: "STALE. The last host check no longer matches this run's event count. Re-run the host check."
    };
    node.textContent = msg[ev.indexed_status] || msg.NOT_VERIFIED;
    node.dataset.state = ev.indexed_status;
    $("ev-model").textContent = view.model.name + " via " + view.model.provider + " · proposals from: " + view.model.proposal_source;
    $("ev-spl").value = ev.splunk_search;
    $("ev-download").setAttribute("href", "/api/v1/loan-desk/runs/" + encodeURIComponent(ev.run_id) + "/events.ndjson");
  }
  var RECO = { PROCEED_TO_UNDERWRITER: "Proceed to underwriter", NEEDS_MORE_INFORMATION: "Needs more information", NOT_RECOMMENDED: "Not recommended" };
  function render(view) {
    var st = $("run-status"); st.dataset.state = view.status; st.textContent = view.status;
    var ph = phaseFor(view); setPhase(ph[0], ph[1]);
    $("live").textContent = liveText(view);
    renderTimeline(view); renderEvidence(view);
    if (view.status === "COMPLETED" && view.final) {
      $("result-card").hidden = false;
      $("reco").textContent = RECO[view.final.recommendation] || view.final.recommendation;
      $("summary").textContent = view.final.summary;
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
    $("result-card").hidden = true; $("timeline-card").hidden = true; $("evidence-card").hidden = true;
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
    var id = $("ev-run").textContent;
    if (!id) { return; }
    fetch("/api/v1/loan-desk/runs/" + encodeURIComponent(id)).then(function (r) { return r.json(); }).then(render)
      .catch(function () { $("ev-indexed").textContent = "Could not reach AcmeBank to re-check."; });
  });
  $("copy-run").addEventListener("click", function () { copy("ev-run", "copy-run"); });
  $("copy-spl").addEventListener("click", function () { copy("ev-spl", "copy-spl"); });
}());
