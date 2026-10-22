/* AgentSec Academy client. No inline script; served under a strict CSP.
 * Every value from the server is inserted with textContent. Predictions, answers
 * and progress live in this browser only and are never sent anywhere. */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  var PROGRESS_KEY = "agentsec.academy.progress.v1";
  var WORKSHOP_KEY = "agentsec.academy.mcp.v1";
  var LAB = "LAB-MCP-001";

  /* ---------- small DOM helpers ---------- */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        var value = attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (key === "text") node.textContent = String(value);
        else if (key === "className") node.className = value;
        else node.setAttribute(key, value === true ? "" : String(value));
      });
    }
    (children || []).forEach(function (child) {
      if (child === null || child === undefined) return;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }
  function $(selector, root) { return (root || document).querySelector(selector); }
  function $all(selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); }
  function code(text) { return el("code", {text: text}); }

  /* Narrow screens restyle tables as cards (display:block), which removes their
   * implicit semantics in some browsers; explicit roles keep headers announced. */
  function tableRoles(table) {
    table.setAttribute("role", "table");
    $all("thead, tbody", table).forEach(function (n) { n.setAttribute("role", "rowgroup"); });
    $all("tr", table).forEach(function (n) { n.setAttribute("role", "row"); });
    $all("th", table).forEach(function (n) { n.setAttribute("role", n.getAttribute("scope") === "row" ? "rowheader" : "columnheader"); });
    $all("td", table).forEach(function (n) { n.setAttribute("role", "cell"); });
    return table;
  }
  $all("table.data-table").forEach(tableRoles);

  function readJSON(storage, key) {
    try { return JSON.parse(storage.getItem(key) || "null"); } catch (_e) { return null; }
  }
  function writeJSON(storage, key, value) {
    try { storage.setItem(key, JSON.stringify(value)); } catch (_e) { /* storage unavailable: convenience only */ }
  }

  /* Splunk Web runs on port 8000 of the host the learner used. */
  function splunkHref(path) {
    return window.location.protocol + "//" + window.location.hostname + ":8000" + path;
  }
  $all("a[data-splunk-link]").forEach(function (link) {
    var href = link.getAttribute("href") || "";
    if (href.indexOf("/en-US/") === 0) link.setAttribute("href", splunkHref(href));
  });

  /* ---------- navigation menu (narrow screens) ---------- */
  var toggle = $("[data-menu-toggle]");
  var nav = $("#primary-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
      nav.classList.toggle("is-open", !open);
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && nav.classList.contains("is-open")) {
        nav.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
        toggle.focus();
      }
    });
  }

  /* ---------- browser-local progress ---------- */
  var PROGRESS_LABEL = {in_progress: "In progress", workflow_complete: "Workflow complete"};
  function progress() { return readJSON(window.localStorage, PROGRESS_KEY) || {}; }
  function setProgress(lab, state) {
    var all = progress();
    var current = all[lab] && all[lab].state;
    if (current === "workflow_complete" && state === "in_progress") return;
    all[lab] = {state: state, updated: new Date().toISOString()};
    writeJSON(window.localStorage, PROGRESS_KEY, all);
    paintProgress();
  }
  function paintProgress() {
    var all = progress();
    $all("[data-progress-for]").forEach(function (node) {
      var row = all[node.getAttribute("data-progress-for")];
      node.textContent = row && PROGRESS_LABEL[row.state] ? PROGRESS_LABEL[row.state] : "Not started";
    });
  }
  paintProgress();
  var resetButton = $("[data-reset-progress]");
  if (resetButton) {
    resetButton.addEventListener("click", function () {
      try {
        window.localStorage.removeItem(PROGRESS_KEY);
        window.sessionStorage.removeItem(WORKSHOP_KEY);
      } catch (_e) { /* ignore */ }
      paintProgress();
      $("[data-reset-feedback]").textContent = "Browser progress cleared. No run or evidence was changed.";
    });
  }

  /* ---------- system status ---------- */
  function fetchStatus() {
    return fetch("/api/academy/status", {headers: {"Accept": "application/json"}})
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)); });
  }
  var summary = $("[data-status-summary]");
  if (summary) {
    fetchStatus().then(function (data) {
      summary.replaceChildren.apply(summary, data.checks.map(function (check) {
        return el("li", null, [el("strong", {text: check.name + ": "}), el("span", {className: "badge " + stateClass(check.state), text: check.state})]);
      }));
    }).catch(function () {
      summary.replaceChildren(el("li", {text: "Status check failed. The Academy could not reach its own status endpoint."}));
    });
  }
  function stateClass(state) {
    if (state === "AVAILABLE") return "badge--ok";
    if (state === "NOT CHECKED") return "badge--muted";
    if (state === "DEGRADED") return "badge--warn";
    return "badge--warn";
  }
  var detail = $("[data-status-detail]");
  function paintStatusDetail() {
    detail.replaceChildren(el("p", {text: "Checking…"}));
    fetchStatus().then(function (data) {
      var list = el("ul", {className: "card-grid card-grid--2"});
      data.checks.forEach(function (check) {
        var card = el("li", {className: "card"}, [
          el("h2", {className: "card-title", text: check.name}),
          el("p", null, [el("span", {className: "badge " + stateClass(check.state), text: check.state}), " ", el("span", {className: "evidence-class", text: "Established: " + check.evidence})]),
          el("p", {text: check.detail})
        ]);
        if (check.packs) {
          var table = el("table", {className: "data-table"}, [
            el("caption", {text: "Committed REPLAY packs"}),
            el("thead", null, [el("tr", null, [el("th", {scope: "col", text: "Role"}), el("th", {scope: "col", text: "run.id"}), el("th", {scope: "col", text: "sha256"})])]),
            el("tbody", null, check.packs.map(function (pack) {
              return el("tr", null, [el("th", {scope: "row", text: pack.role}), el("td", {"data-label": "run.id"}, [code(pack.run_id)]), el("td", {"data-label": "sha256"}, [code(pack.present ? pack.sha256 : "NOT PRESENT")])]);
            }))
          ]);
          card.appendChild(el("div", {className: "table-wrap"}, [tableRoles(table)]));
        }
        if (check.href) card.appendChild(el("p", null, [el("a", {href: check.href, text: "Open Splunk Search (advanced)"})]));
        list.appendChild(card);
      });
      detail.replaceChildren(list);
    }).catch(function () {
      detail.replaceChildren(el("p", {text: "Status check failed. Treat every service as UNKNOWN, not available."}));
    });
  }
  if (detail) {
    paintStatusDetail();
    var refresh = $("[data-status-refresh]");
    if (refresh) refresh.addEventListener("click", paintStatusDetail);
  }

  /* ---------- evidence rendering (shared) ---------- */
  function citation(source) {
    if (!source) return "no supporting event";
    return "event " + source.sequence + " · " + source.event_name + " · " + source.timestamp;
  }
  function summarise(event) {
    var name = event["event.name"] || "";
    if (name === "agentsec.control.decision") {
      var reason = String(event["agentsec.control.reason"] || "").split(":")[0];
      return (event["agentsec.control.id"] || "control") + " recorded " + (event["agentsec.control.decision"] || "NOT MEASURED") + " (" + reason + ") for " + (event["gen_ai.tool.name"] || "a tool");
    }
    if (name === "agentsec.mcp.started") return "Tool handler started: " + (event["gen_ai.tool.name"] || "");
    if (name === "agentsec.mcp.completed") return "Tool handler completed: " + (event["agentsec.operation.outcome"] || "outcome not recorded");
    if (name === "agentsec.pipeline.stopped") return "Pipeline stopped before any tool handler";
    if (name === "agentsec.run.started") return "Run started";
    if (name === "agentsec.run.completed") return "Run completed";
    if (name === "agentsec.hop.started") return "Agent hop started";
    if (name === "agentsec.hop.completed") return "Agent hop completed";
    return "Recorded event";
  }
  function provenanceClass(value) {
    if (value === "LIVE") return "badge--live";
    if (value === "REPLAY") return "badge--replay";
    if (value === "SYNTHETIC") return "badge--muted";
    return "badge--unavailable";
  }
  function provenanceBlock(doc) {
    var badge = el("span", {className: "badge " + provenanceClass(doc.provenance), text: doc.provenance});
    var facts = doc.facts;
    var schema = doc.telemetry_schema_recorded || (facts && facts.schema_version_recorded) || "NOT MEASURED";
    var list = el("dl", {className: "facts-grid"}, [
      el("div", null, [el("dt", {text: "run.id"}), el("dd", null, [code(doc.run_id)])]),
      el("div", null, [el("dt", {text: "Source"}), el("dd", null, [code(doc.source)])]),
      el("div", null, [el("dt", {text: "Source sha256"}), el("dd", null, [code(doc.source_sha256)])]),
      el("div", null, [el("dt", {text: "Recorded"}), el("dd", {text: (facts.first_timestamp || "NOT MEASURED") + " to " + (facts.last_timestamp || "NOT MEASURED") + " (UTC)"})]),
      el("div", null, [el("dt", {text: "Recorded mode and profile"}), el("dd", {text: facts.testbed_mode + " · " + facts.security_profile})]),
      el("div", null, [el("dt", {text: "Telemetry schema"}), el("dd", {text: schema + " (runtime expects " + (doc.runtime_schema_expected || "1.9.0") + ")"})]),
      el("div", null, [el("dt", {text: "Events in record"}), el("dd", {text: String(facts.event_count)})])
    ]);
    var block = el("div", {className: "provenance-card"}, [
      el("p", null, [badge, " ", el("span", {text: doc.provenance_text})]),
      list
    ]);
    if (doc.launch_response) {
      block.appendChild(el("p", {className: "form-note", text: "Launch response (independent source): runtime handler count " + doc.launch_response.runtime_handler_count + ". " + doc.launch_response.note}));
    }
    if (doc.external_evidence) {
      block.appendChild(el("p", {className: "form-note", text: "ExternalEvidence " + doc.external_evidence.contract_version + ": " + doc.external_evidence.detail}));
    }
    facts.warnings.forEach(function (warning) { block.appendChild(el("p", {className: "callout callout--warn", text: warning})); });
    return block;
  }
  function splunkBlock(doc) {
    var items = [el("li", null, [el("a", {href: doc.splunk.search_url, text: "Search this run in Splunk"}), " (advanced; opens Splunk Search with the run.id and time range filled in)"])];
    if (doc.splunk.studio_url) items.push(el("li", null, [el("a", {href: doc.splunk.studio_url, text: "Open the Studio workshop for this run"}), " (advanced)"]));
    return el("div", {className: "splunk-links"}, [
      el("h4", {text: "Advanced: verify in Splunk"}),
      el("ul", null, items),
      el("p", {className: "form-note", text: doc.splunk.studio_note}),
      el("details", null, [el("summary", {text: "Show the search (SPL)"}), el("pre", null, [code(doc.splunk.spl)])])
    ]);
  }
  function eventTable(doc) {
    var table = el("table", {className: "data-table event-table", role: "table"}, [
      el("caption", {text: "Events recorded for " + doc.provenance + " run " + doc.run_id + " (" + doc.events.length + " events, in sequence order)"}),
      el("thead", {role: "rowgroup"}, [el("tr", {role: "row"}, ["#", "Time (UTC)", "Event", "What it records", "Fields"].map(function (h) {
        return el("th", {scope: "col", role: "columnheader", text: h});
      }))]),
      el("tbody", {role: "rowgroup"}, doc.events.map(function (event) {
        var seq = String(event["agentsec.sequence"] === undefined ? "" : event["agentsec.sequence"]);
        var fields = el("dl", {className: "field-list"}, Object.keys(event).map(function (key) {
          return el("div", null, [el("dt", {text: key}), el("dd", null, [code(String(event[key]))])]);
        }));
        return el("tr", {role: "row"}, [
          el("td", {role: "cell", "data-label": "#", text: seq}),
          el("td", {role: "cell", "data-label": "Time (UTC)"}, [code(String(event.timestamp || ""))]),
          el("td", {role: "cell", "data-label": "Event"}, [code(String(event["event.name"] || ""))]),
          el("td", {role: "cell", "data-label": "What it records", text: summarise(event)}),
          el("td", {role: "cell", "data-label": "Fields"}, [el("details", null, [el("summary", null, ["Show fields", el("span", {className: "visually-hidden", text: " for event " + seq})]), fields])])
        ]);
      }))
    ]);
    return el("div", {className: "table-wrap"}, [table]);
  }
  function renderEvidence(slot, doc) {
    slot.replaceChildren(provenanceBlock(doc), eventTable(doc), splunkBlock(doc));
  }
  function errorText(data, fallback) {
    return (data && data.detail) ? data.detail + " (" + data.error + ")" : fallback;
  }
  function unavailableBlock(detail) {
    return el("div", {className: "callout callout--warn"}, [
      el("p", null, [el("span", {className: "badge badge--unavailable", text: "UNAVAILABLE"}), " ", el("span", {text: detail})]),
      el("p", {text: "This is missing evidence, not a control decision and not a SYNTHETIC result."})
    ]);
  }
  function fetchEvidence(runId) {
    return fetch("/api/academy/evidence/" + encodeURIComponent(runId), {headers: {"Accept": "application/json"}})
      .then(function (r) {
        return r.json().catch(function () { return {error: "non_json", detail: "The response was not JSON."}; })
          .then(function (data) { return r.ok ? data : Promise.reject(data); });
      });
  }

  /* ---------- workshop ---------- */
  var root = $("[data-workshop]");
  if (!root) return;

  var ORDER = ["start", "baseline", "predict", "attack", "investigate", "defend", "retest", "compare", "explain"];
  var LABELS = {start: "Start", baseline: "Baseline", predict: "Predict", attack: "Attack", investigate: "Investigate", defend: "Defend", retest: "Retest", compare: "Compare", explain: "Explain"};
  var REPLAY = {
    BASELINE: root.getAttribute("data-replay-baseline"),
    ATTACK: root.getAttribute("data-replay-attack"),
    RETEST: root.getAttribute("data-replay-retest")
  };
  var SPECIMEN = {ATTACK: root.getAttribute("data-attack-specimen"), RETEST: root.getAttribute("data-retest-specimen")};

  var state = readJSON(window.sessionStorage, WORKSHOP_KEY) || {};
  state.prediction = state.prediction || {};
  state.runs = state.runs || {};
  state.answers = state.answers || {};
  var docs = {};
  var compareDoc = null;
  var busy = false;
  function save() { writeJSON(window.sessionStorage, WORKSHOP_KEY, state); }

  function hasRun(mode) { return Boolean(state.runs[mode] && state.runs[mode].run_id); }
  function gateReason(step) {
    if (step === "attack" && !state.prediction.locked) return "Lock your prediction on the Predict step first.";
    if ((step === "investigate" || step === "defend" || step === "retest") && !hasRun("ATTACK")) return "Complete the Attack step first.";
    if ((step === "compare" || step === "explain") && !(hasRun("ATTACK") && hasRun("RETEST"))) return "Complete both Attack and Retest first.";
    return "";
  }

  var gateMessage = $("[data-gate-message]");
  var announcer = $("[data-step-announcer]");
  var current = null;

  function paintStepper() {
    $all("[data-step-link]").forEach(function (link) {
      var step = link.getAttribute("data-step-link");
      var marker = $('[data-step-state="' + step + '"]', link);
      var locked = Boolean(gateReason(step));
      if (step === current) {
        link.setAttribute("aria-current", "step");
        marker.textContent = " (current)";
      } else {
        link.removeAttribute("aria-current");
        marker.textContent = locked ? " (locked)" : "";
      }
      if (locked) link.setAttribute("aria-disabled", "true"); else link.removeAttribute("aria-disabled");
    });
  }

  function show(step, options) {
    options = options || {};
    if (ORDER.indexOf(step) === -1) step = "start";
    var reason = gateReason(step);
    if (reason) {
      gateMessage.hidden = false;
      gateMessage.textContent = LABELS[step] + " is locked. " + reason;
      if (!current) {
        step = "start";
      } else {
        try { window.history.replaceState(null, "", "#" + current); } catch (_e) { /* ignore */ }
        return;
      }
    } else {
      gateMessage.hidden = true;
      gateMessage.textContent = "";
    }
    current = step;
    state.step = step;
    save();
    $all("[data-step]").forEach(function (section) { section.hidden = section.getAttribute("data-step") !== step; });
    paintStepper();
    syncControls();
    if (window.location.hash !== "#" + step) {
      try { window.history.replaceState(null, "", "#" + step); } catch (_e) { /* ignore */ }
    }
    if (options.focus !== false) {
      var heading = $("#h-" + step);
      if (heading) {
        heading.focus({preventScroll: true});
        heading.scrollIntoView({block: "start"});
      }
      announcer.textContent = "Step " + (ORDER.indexOf(step) + 1) + " of 9: " + LABELS[step];
    }
    if (step === "compare" || step === "explain") loadCompare();
    if (step === "investigate") loadNotebook();
  }

  $all("[data-step-link]").forEach(function (link) {
    link.addEventListener("click", function (event) {
      event.preventDefault();
      show(link.getAttribute("data-step-link"));
    });
  });
  $all("[data-go]").forEach(function (button) {
    button.addEventListener("click", function () { show(button.getAttribute("data-go")); });
  });
  window.addEventListener("hashchange", function () {
    var step = window.location.hash.slice(1);
    if (ORDER.indexOf(step) !== -1 && step !== current) show(step);
  });

  /* ---- baseline (REPLAY only) ---- */
  var baselineButton = $("[data-load-baseline]");
  var baselineSlot = $('[data-evidence-slot="baseline"]');
  function loadBaseline() {
    baselineSlot.setAttribute("aria-busy", "true");
    baselineSlot.replaceChildren(el("p", {className: "form-note", text: "Loading the recorded baseline…"}));
    fetchEvidence(REPLAY.BASELINE).then(function (doc) {
      renderEvidence(baselineSlot, doc);
      baselineSlot.setAttribute("aria-busy", "false");
      state.baselineLoaded = true;
      save();
    }).catch(function (data) {
      baselineSlot.setAttribute("aria-busy", "false");
      baselineSlot.replaceChildren(unavailableBlock(errorText(data, "The baseline could not be loaded. That is missing evidence, not a result.")));
    });
  }
  baselineButton.addEventListener("click", loadBaseline);

  /* ---- prediction ---- */
  var form = $("[data-prediction-form]");
  var note = $("[data-prediction-note]");
  function picked(name) {
    var input = $('input[name="' + name + '"]:checked', form);
    return input ? input.value : "";
  }
  function paintPrediction() {
    if (state.prediction.control) {
      var c = $('input[name="predict-control"][value="' + state.prediction.control + '"]', form);
      if (c) c.checked = true;
    }
    if (state.prediction.execution) {
      var x = $('input[name="predict-execution"][value="' + state.prediction.execution + '"]', form);
      if (x) x.checked = true;
    }
    $all("input", form).forEach(function (input) { input.disabled = Boolean(state.prediction.locked); });
    if (state.prediction.locked) {
      note.textContent = "Prediction locked: control " + state.prediction.control + ", tool starts " + state.prediction.execution + ". It stays in this browser tab, is never sent, and is not graded.";
      $("[data-lock-prediction]").textContent = "Continue to Attack";
    }
  }
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    if (state.prediction.locked) { show("attack"); return; }
    var control = picked("predict-control");
    var execution = picked("predict-execution");
    if (!control || !execution) {
      note.textContent = "Answer both questions first. Missing: " + [!control ? "the control decision" : "", !execution ? "whether the tool starts" : ""].filter(Boolean).join(" and ") + ".";
      note.setAttribute("tabindex", "-1");
      note.focus();
      return;
    }
    state.prediction = {control: control, execution: execution, locked: true};
    save();
    setProgress(LAB, "in_progress");
    paintPrediction();
    show("attack");
  });

  /* ---- runs: LIVE launch or REPLAY ---- */
  function syncControls() {
    var attackGate = $("[data-attack-gate]");
    var retestGate = $("[data-retest-gate]");
    var locked = Boolean(state.prediction.locked);
    attackGate.textContent = !locked ? "Lock your prediction first to enable these actions."
      : hasRun("ATTACK") ? "An ATTACK run is recorded in this tab. One run per mode prevents duplicate experiments."
      : "Choose one. LIVE sends a real request to the lab runtime; REPLAY opens the recorded run.";
    $all('[data-launch="ATTACK"], [data-use-replay="ATTACK"]').forEach(function (b) { b.disabled = busy || !locked || hasRun("ATTACK"); });

    var attackSource = hasRun("ATTACK") ? state.runs.ATTACK.provenance : null;
    retestGate.textContent = !attackSource ? "Complete the ATTACK step first."
      : hasRun("RETEST") ? "A RETEST run is recorded in this tab."
      : attackSource === "LIVE" ? "Your ATTACK was LIVE, so the RETEST is launched LIVE too."
      : "Your ATTACK was the recording, so the RETEST uses its recorded pair.";
    $('[data-launch="RETEST"]').disabled = busy || attackSource !== "LIVE" || hasRun("RETEST");
    $('[data-use-replay="RETEST"]').disabled = busy || attackSource !== "REPLAY" || hasRun("RETEST");
    var switchBtn = $("[data-switch-replay]");
    if (switchBtn) {
      switchBtn.hidden = !(hasRun("ATTACK") && state.runs.ATTACK.provenance === "LIVE");
    }
    var freshBtn = $("[data-fresh-live]");
    if (freshBtn) freshBtn.hidden = busy || !hasRun("ATTACK");
  }

  function runStatus(mode, text) { $('[data-run-status="' + mode + '"]').textContent = text; }

  function paintRunCard(mode, doc) {
    var card = $('[data-run-card="' + mode + '"]');
    card.hidden = false;
    var copyFeedback = el("span", {className: "form-note", role: "status"});
    var copyButton = el("button", {type: "button", className: "button button--ghost", text: "Copy run.id"});
    copyButton.addEventListener("click", function () {
      var done = function (ok) { copyFeedback.textContent = ok ? " Copied." : " Copy failed; select the run.id above."; };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(doc.run_id).then(function () { done(true); }, function () { done(false); });
      else done(false);
    });
    var decision = doc.facts.decision;
    card.replaceChildren(
      el("h3", {text: mode + " run"}),
      el("p", null, [el("span", {className: "badge " + provenanceClass(doc.provenance), text: doc.provenance}), " run.id ", code(doc.run_id), " ", copyButton, copyFeedback]),
      el("p", {text: doc.facts.event_count + " events recorded. Investigate them to find out what happened."}),
      el("details", null, [
        el("summary", {text: "Show the recorded control decision now (the notebook asks you this)"}),
        el("p", {text: "CTRL-MCP-001 recorded " + decision.value + " (" + doc.facts.reason_code + "), " + citation(decision.source) + ". A decision is not execution."})
      ]),
      splunkBlock(doc)
    );
  }

  function adoptRun(mode, runId, provenance) {
    runStatus(mode, "Loading the evidence for " + mode + " run " + runId + "…");
    return fetchEvidence(runId).then(function (doc) {
      docs[mode] = doc;
      paintRunCard(mode, doc);
      runStatus(mode, mode + " run ready (" + provenance + "). " + doc.facts.event_count + " events recorded.");
      return doc;
    }).catch(function (data) {
      runStatus(mode, "The " + mode + " run " + runId + " is recorded in this tab, but its evidence could not be loaded: " + errorText(data, "unknown error") + ". That is missing evidence, not a result.");
      var card = $('[data-run-card="' + mode + '"]');
      card.hidden = false;
      var retry = el("button", {type: "button", className: "button button--secondary", text: "Try loading the evidence again"});
      retry.addEventListener("click", function () { adoptRun(mode, runId, provenance); });
      card.replaceChildren(unavailableBlock(errorText(data, "unknown error")), el("p", null, ["run.id ", code(runId)]), retry);
      return null;
    });
  }

  function launch(mode) {
    if (busy || hasRun(mode)) return;
    busy = true;
    syncControls();
    runStatus(mode, "Launching LIVE " + mode + ". Launch controls are disabled until it finishes.");
    var controller = typeof AbortController === "function" ? new AbortController() : null;
    var timer = window.setTimeout(function () { if (controller) controller.abort(); }, 45000);
    fetch("/api/launch", {
      method: "POST",
      headers: {"Content-Type": "application/json", "Accept": "application/json"},
      body: JSON.stringify({lab_id: LAB, specimen_id: SPECIMEN[mode], mode: mode, execution: "live"}),
      signal: controller ? controller.signal : undefined
    }).then(function (r) {
      return r.json().catch(function () { return {error_class: "ERROR", detail: "The response was not JSON."}; });
    }).catch(function (err) {
      var timedOut = err && (err.name === "AbortError" || err.name === "TimeoutError");
      return {
        error_class: "ERROR",
        detail: timedOut
          ? "The runtime did not respond within 45 seconds. This is an ERROR, not a control decision. You can try again."
          : "The browser did not receive a usable response. This is an ERROR, not a control decision. You can try again."
      };
    }).then(function (data) {
      window.clearTimeout(timer);
      busy = false;
      if (data.error_class === "ERROR" || !data.run_id) {
        runStatus(mode, "Launch failed: " + (data.detail || data.error || "unknown error") + ". This is an ERROR, not a control decision. Nothing was recorded; you can try again.");
        syncControls();
        return;
      }
      state.runs[mode] = {run_id: data.run_id, provenance: "LIVE"};
      save();
      syncControls();
      paintStepper();
      adoptRun(mode, data.run_id, "LIVE");
    });
  }
  function useReplay(mode) {
    if (busy || hasRun(mode)) return;
    state.runs[mode] = {run_id: REPLAY[mode], provenance: "REPLAY"};
    save();
    syncControls();
    paintStepper();
    adoptRun(mode, REPLAY[mode], "REPLAY");
  }
  $all("[data-launch]").forEach(function (b) { b.addEventListener("click", function () { launch(b.getAttribute("data-launch")); }); });
  $all("[data-use-replay]").forEach(function (b) { b.addEventListener("click", function () { useReplay(b.getAttribute("data-use-replay")); }); });
  function switchToReplayPair() {
    if (!REPLAY.ATTACK || !REPLAY.RETEST) return;
    compareDoc = null;
    delete docs.ATTACK;
    delete docs.RETEST;
    state.runs.ATTACK = {run_id: REPLAY.ATTACK, provenance: "REPLAY"};
    state.runs.RETEST = {run_id: REPLAY.RETEST, provenance: "REPLAY"};
    save();
    if (switchReplay) switchReplay.hidden = true;
    syncControls();
    paintStepper();
    adoptRun("ATTACK", REPLAY.ATTACK, "REPLAY");
    adoptRun("RETEST", REPLAY.RETEST, "REPLAY");
    var note = $("[data-replay-switch-note]");
    if (note) {
      note.hidden = false;
      note.textContent = "This tab now shows the committed REPLAY packs. Say REPLAY out loud. The server durable LIVE index is unchanged. This is not a live launch.";
    }
  }
  var switchReplay = $("[data-switch-replay]");
  if (switchReplay) {
    switchReplay.addEventListener("click", function () { switchToReplayPair(); });
  }

  /* Clears this tab only. Server LIVE references and artifacts are untouched, and this
   * tab stops re-adopting server slots so a new ATTACK is never paired with an older RETEST. */
  function startFreshLive() {
    if (busy) return;
    state.runs = {};
    state.compareViewed = false;
    state.skipRehydrate = true;
    compareDoc = null;
    delete docs.ATTACK;
    delete docs.RETEST;
    save();
    ["ATTACK", "RETEST"].forEach(function (mode) {
      var card = $('[data-run-card="' + mode + '"]');
      card.hidden = true;
      card.replaceChildren();
      runStatus(mode, "No " + mode + " run yet.");
    });
    var note = $("[data-replay-switch-note]");
    if (note) {
      note.hidden = false;
      note.textContent = "This tab no longer shows a run. Server LIVE evidence is unchanged. Launch LIVE ATTACK to record a new run.id.";
    }
    syncControls();
    paintStepper();
    $('[data-launch="ATTACK"]').focus();
  }
  var freshLive = $("[data-fresh-live]");
  if (freshLive) freshLive.addEventListener("click", startFreshLive);

  /* ---- notebook ---- */
  function bucket(count) { return count === 0 ? "0" : count <= 3 ? "1 to 3" : "4 or more"; }
  function questionsFor(doc) {
    var f = doc.facts;
    var names = [];
    doc.events.forEach(function (e) { if (names.indexOf(e["event.name"]) === -1) names.push(e["event.name"]); });
    var started = f.handler_started.value === "OBSERVED";
    var scopeKnown = f.requested_scope.value !== "NOT MEASURED" && f.allowed_scope.value !== "NOT MEASURED";
    return [
      {
        id: "q1", text: "What did CTRL-MCP-001 decide for this request?",
        options: ["ALLOW", "DENY", "ERROR", "Not recorded"],
        expected: f.decision.value === "NOT MEASURED" ? "Not recorded" : f.decision.value,
        because: "The decision event records " + f.decision.value + " with reason " + f.reason_code + " (" + citation(f.decision.source) + ")."
      },
      {
        id: "q2", text: "Did the tool handler start?",
        options: ["Yes", "No"],
        expected: started ? "Yes" : "No",
        because: started ? "agentsec.mcp.started is in the record (" + citation(f.handler_started.source) + ")."
          : "No agentsec.mcp.started event is in the record, so execution is NOT OBSERVED" + (f.pipeline_stopped.source ? "; agentsec.pipeline.stopped is present (" + citation(f.pipeline_stopped.source) + ")." : ".")
      },
      {
        id: "q3", text: "Which event is the evidence for your answer to question 2?",
        options: names.concat(["No execution event is present"]),
        expected: started ? "agentsec.mcp.started" : "No execution event is present",
        because: "The decision event records authorization, not execution. Execution is shown only by agentsec.mcp.started."
      },
      {
        id: "q4", text: "Was the requested scope within the granted scope?",
        options: ["Yes", "No", "Not recorded"],
        expected: !scopeKnown ? "Not recorded" : (f.requested_scope.value === f.allowed_scope.value ? "Yes" : "No"),
        because: "Requested " + f.requested_scope.value + ", granted " + f.allowed_scope.value + " (" + citation(f.requested_scope.source) + ")."
      },
      {
        id: "q5", text: "How many LLM call events does this run's record contain?",
        options: ["0", "1 to 3", "4 or more"],
        expected: bucket(f.llm_event_count),
        because: "The record contains " + f.llm_event_count + " LLM call events. This lab's tool path is deterministic; do not invent model activity the record does not show."
      }
    ];
  }

  function renderQuestions(doc) {
    var list = $("[data-questions]");
    var runKey = doc.run_id;
    var answers = state.answers[runKey] || {};
    list.replaceChildren.apply(list, questionsFor(doc).map(function (q, index) {
      var group = "nb-" + q.id;
      var result = el("p", {className: "answer-result", role: "status"});
      var fieldset = el("fieldset", null, [el("legend", {text: "Question " + (index + 1) + ". " + q.text})].concat(q.options.map(function (option) {
        var input = el("input", {type: "radio", name: group, value: option});
        if (answers[q.id] && answers[q.id].value === option) input.checked = true;
        return el("label", {className: "choice"}, [input, " ", option.indexOf("agentsec.") === 0 ? code(option) : option]);
      })));
      var check = el("button", {type: "button", className: "button button--secondary", text: "Check against the evidence"});
      function paintResult(value) {
        var match = value === q.expected;
        result.replaceChildren(
          el("strong", {text: match ? "Matches the evidence. " : "The evidence shows something different. "}),
          "Your answer: " + value + ". The record shows: " + q.expected + ". " + q.because
        );
        if (q.id === "q2" && state.prediction.locked) {
          result.appendChild(document.createTextNode(" You predicted: control " + state.prediction.control + ", tool starts " + state.prediction.execution + "."));
        }
      }
      check.addEventListener("click", function () {
        var chosen = $('input[name="' + group + '"]:checked', fieldset);
        if (!chosen) { result.textContent = "Choose an answer first."; return; }
        answers[q.id] = {value: chosen.value, checked: true};
        state.answers[runKey] = answers;
        save();
        paintResult(chosen.value);
      });
      if (answers[q.id] && answers[q.id].checked) paintResult(answers[q.id].value);
      return el("li", {className: "question"}, [fieldset, check, result]);
    }));
  }

  function loadNotebook() {
    var empty = $("[data-notebook-empty]");
    var body = $("[data-notebook-body]");
    if (!hasRun("ATTACK")) { empty.hidden = false; body.hidden = true; return; }
    var run = state.runs.ATTACK;
    var ready = docs.ATTACK ? Promise.resolve(docs.ATTACK) : fetchEvidence(run.run_id).then(function (doc) { docs.ATTACK = doc; return doc; });
    empty.textContent = "Loading the evidence for ATTACK run " + run.run_id + "…";
    ready.then(function (doc) {
      empty.hidden = true;
      body.hidden = false;
      $('[data-provenance="ATTACK"]').replaceChildren(provenanceBlock(doc));
      renderQuestions(doc);
      $('[data-evidence-slot="ATTACK"]').replaceChildren(eventTable(doc), splunkBlock(doc));
    }).catch(function (data) {
      empty.hidden = false;
      body.hidden = true;
      empty.replaceChildren(unavailableBlock("The ATTACK evidence could not be loaded: " + errorText(data, "unknown error") + "."));
    });
  }

  /* ---- compare + explain ---- */
  function compareTable(doc) {
    return el("div", {className: "table-wrap"}, [tableRoles(el("table", {className: "data-table compare-table"}, [
      el("caption", {text: "ATTACK " + doc.attack.run_id + " (" + doc.attack.provenance + ") compared with RETEST " + doc.retest.run_id + " (" + doc.retest.provenance + ")"}),
      el("thead", null, [el("tr", null, [el("th", {scope: "col", text: "Recorded fact"}), el("th", {scope: "col", text: "ATTACK"}), el("th", {scope: "col", text: "RETEST"}), el("th", {scope: "col", text: "Same or different"})])]),
      el("tbody", null, doc.rows.map(function (row) {
        return el("tr", {className: row.relation === "DIFFERENT" ? "is-different" : ""}, [
          el("th", {scope: "row", text: row.label}),
          el("td", {"data-label": "ATTACK"}, [code(row.attack)]),
          el("td", {"data-label": "RETEST"}, [code(row.retest)]),
          el("td", {"data-label": "Same or different", text: row.relation})
        ]);
      }))
    ]))]);
  }
  function renderCompare(doc) {
    var slot = $("[data-compare-slot]");
    var parts = [compareTable(doc)];
    doc.warnings.forEach(function (w) { parts.push(el("p", {className: "callout callout--warn", text: w})); });
    parts.push(el("h3", {text: "Observed in the records"}));
    parts.push(el("ul", {className: "claims"}, doc.observations.map(function (o) { return el("li", null, [el("span", {className: "badge badge--ok", text: "OBSERVED"}), " ", o]); })));
    parts.push(el("h3", {text: "Inferences (not measurements)"}));
    parts.push(el("ul", {className: "claims"}, doc.inferences.map(function (o) { return el("li", null, [el("span", {className: "badge badge--muted", text: "INFERRED"}), " ", o]); })));
    parts.push(el("p", null, [el("a", {href: doc.splunk.search_url, text: "Search both runs in Splunk"}), " (advanced)"]));
    slot.replaceChildren.apply(slot, parts);
  }
  function renderRecap(doc) {
    var recap = $("[data-explain-recap]");
    var attackFacts = doc.rows.reduce(function (acc, row) { acc[row.label] = row.attack; return acc; }, {});
    var items = [];
    if (state.prediction.locked) {
      items.push(el("li", {text: "You predicted the control would decide " + state.prediction.control + "; the ATTACK record shows " + attackFacts["CTRL-MCP-001 decision"] + "."}));
      var startedText = attackFacts["Tool handler started (mcp.started)"] === "OBSERVED" ? "YES" : "NO";
      items.push(el("li", {text: "You predicted the tool would start: " + state.prediction.execution + "; the ATTACK record shows " + startedText + "."}));
    }
    recap.replaceChildren(
      el("h3", {text: "Your prediction and the evidence"}),
      el("ul", null, items),
      el("h3", {text: "Claims the evidence supports"}),
      el("ul", {className: "claims"}, doc.observations.map(function (o) { return el("li", {text: o}); }))
    );
  }
  function loadCompare() {
    if (!(hasRun("ATTACK") && hasRun("RETEST"))) return;
    if (compareDoc) { renderCompare(compareDoc); renderRecap(compareDoc); return; }
    var slot = $("[data-compare-slot]");
    slot.replaceChildren(el("p", {className: "form-note", text: "Loading both records…"}));
    var url = "/api/academy/compare?attack=" + encodeURIComponent(state.runs.ATTACK.run_id) + "&retest=" + encodeURIComponent(state.runs.RETEST.run_id);
    fetch(url, {headers: {"Accept": "application/json"}}).then(function (r) {
      return r.json().then(function (data) { return r.ok ? data : Promise.reject(data); });
    }).then(function (doc) {
      compareDoc = doc;
      state.compareViewed = true;
      save();
      renderCompare(doc);
      renderRecap(doc);
    }).catch(function (data) {
      slot.replaceChildren(unavailableBlock("The comparison could not be built: " + errorText(data, "unknown error") + ". Missing data is NOT MEASURED, not SAFE."));
    });
  }

  var explanation = $("[data-explanation]");
  explanation.value = state.explanation || "";
  explanation.addEventListener("input", function () { state.explanation = explanation.value; save(); });
  $("[data-complete]").addEventListener("click", function () {
    var feedback = $("[data-complete-feedback]");
    if (!state.compareViewed) { feedback.textContent = "Open the comparison on the Compare step first."; return; }
    if ((state.explanation || "").trim().length < 20) {
      feedback.textContent = "Write a short explanation first (at least a sentence).";
      explanation.focus();
      return;
    }
    setProgress(LAB, "workflow_complete");
    feedback.textContent = "Workflow complete. This records that you finished the learning workflow in this browser. It is not a security verdict.";
  });

  function rehydrateFromServer() {
    if (state.skipRehydrate) return Promise.resolve();
    return fetch("/api/academy/live-runs", {headers: {"Accept": "application/json"}})
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status)); })
      .then(function (data) {
        var slots = (data && data.slots) || {};
        var attackSlot = slots.ATTACK;
        ["ATTACK", "RETEST"].forEach(function (mode) {
          var slot = slots[mode];
          if (!slot || slot.status !== "complete" || !slot.run_id) return;
          if (hasRun(mode)) return;
          /* Slots are the latest of each scenario independently; an older RETEST is not this ATTACK's retest. */
          if (mode === "RETEST" && !(attackSlot && hasRun("ATTACK") && state.runs.ATTACK.run_id === attackSlot.run_id &&
              String(slot.recorded_at) >= String(attackSlot.recorded_at))) return;
          state.runs[mode] = {run_id: slot.run_id, provenance: "LIVE", recovered: true};
        });
        save();
      })
      .catch(function () { /* durable index unavailable: session state remains the only hint */ });
  }

  /* ---- start up ---- */
  paintPrediction();
  rehydrateFromServer().then(function () {
    if (state.baselineLoaded) loadBaseline();
    ["ATTACK", "RETEST"].forEach(function (mode) {
      if (hasRun(mode)) {
        runStatus(mode, mode + " run recorded in this tab (" + state.runs[mode].provenance + ").");
        adoptRun(mode, state.runs[mode].run_id, state.runs[mode].provenance);
      }
    });
    var initial = window.location.hash.slice(1) || state.step || "start";
    show(ORDER.indexOf(initial) === -1 ? "start" : initial, {focus: Boolean(window.location.hash)});
  });
}());

/* ---------- Loan Desk mission ----------
 * Separate IIFE: the workshop module above returns early on pages without [data-workshop].
 * Every server value goes through textContent. Predictions and answers stay in this browser. */
(function () {
  "use strict";
  var root = document.querySelector("[data-mission='loan-desk']");
  if (!root) return;

  var KEY = "agentsec.academy.loandesk.v1";
  var LABID = "LAB-LOANDESK-001";
  var ORDER = ["understand", "explore", "predict", "attack", "observe", "investigate", "defend", "retest", "compare", "explain"];
  var LABELS = {understand: "Understand", explore: "Explore", predict: "Predict", attack: "Attack", observe: "Observe", investigate: "Investigate", defend: "Defend", retest: "Retest", compare: "Compare", explain: "Explain"};
  var POLL_MS = 700, POLL_MAX_MS = 150000, FETCH_MS = 20000;
  var FIELDS = ["full_name", "annual_income", "credit_score", "loan_amount", "term_years", "province", "employment", "notes"];

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "text") n.textContent = String(v); else if (k === "className") n.className = v; else n.setAttribute(k, v === true ? "" : String(v));
    });
    (children || []).forEach(function (c) { if (c !== null && c !== undefined) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function q(sel, ctx) { return (ctx || root).querySelector(sel); }
  function qa(sel, ctx) { return Array.prototype.slice.call((ctx || root).querySelectorAll(sel)); }
  function rd(storage, key) { try { return JSON.parse(storage.getItem(key) || "null"); } catch (_e) { return null; } }
  function wr(storage, key, value) { try { storage.setItem(key, JSON.stringify(value)); } catch (_e) { /* convenience only */ } }

  var state = rd(window.sessionStorage, KEY) || {};
  state.prediction = state.prediction || {};
  state.runs = state.runs || {};
  state.posture = state.posture || "baseline";
  state.defenseApplied = Boolean(state.defenseApplied);
  var views = {};              // latest run view per slot
  var current = null, busy = {};
  function save() { wr(window.sessionStorage, KEY, state); }

  function markProgress(value) {
    var all = rd(window.localStorage, "agentsec.academy.progress.v1") || {};
    if (all[LABID] && all[LABID].state === "workflow_complete" && value === "in_progress") return;
    all[LABID] = {state: value, updated: new Date().toISOString()};
    wr(window.localStorage, "agentsec.academy.progress.v1", all);
  }

  /* ---------- network with timeout, and a clear disconnected state ---------- */
  function api(path, options) {
    var ctl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = ctl ? window.setTimeout(function () { ctl.abort(); }, FETCH_MS) : null;
    var opts = options || {};
    if (ctl) opts.signal = ctl.signal;
    return window.fetch(path, opts).then(function (r) {
      if (timer) window.clearTimeout(timer);
      return r.json().catch(function () { return {error: "non_json", detail: "The response was not JSON."}; })
        .then(function (data) { return {status: r.status, ok: r.ok, data: data}; });
    }, function (err) {
      if (timer) window.clearTimeout(timer);
      return {status: 0, ok: false, data: {error: err && err.name === "AbortError" ? "timeout" : "disconnected",
        detail: err && err.name === "AbortError" ? "No answer within " + (FETCH_MS / 1000) + " seconds." : "The Attack Service could not be reached."}};
    });
  }
  function post(path, obj) {
    var payload = JSON.stringify(obj);
    return api(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: payload});
  }
  function problemText(res) {
    var e = res.data && res.data.error;
    if (e === "disconnected") return "Disconnected: the Attack Service cannot be reached. Check that the lab is running, then retry.";
    if (e === "timeout") return "Timed out: no answer in time. The run may still be working; retry in a moment.";
    if (e === "acmebank_unreachable") return "AcmeBank (the Loan Desk) cannot be reached from the Attack Service. Start or restart AcmeBank, then retry.";
    if (e === "acmebank_timeout") return "AcmeBank did not answer in time. Retry in a moment.";
    return (res.data && (res.data.detail || res.data.error)) || ("Unexpected response (HTTP " + res.status + ").");
  }

  /* ---------- stepper ---------- */
  var gateMsg = q("[data-gate-message]"), announcer = q("[data-step-announcer]");
  function done(slot) { return Boolean(views[slot] && views[slot].status && views[slot].status !== "RUNNING"); }
  function gateReason(step) {
    if (step === "attack" && !state.prediction.locked) return "Lock your prediction on the Predict step first.";
    if ((step === "observe" || step === "investigate" || step === "defend") && !state.runs.attack) return "Launch the attack first.";
    if (step === "retest" && !state.defenseApplied) return "Apply the defense on the Defend step first.";
    if ((step === "compare" || step === "explain") && !(done("attack") && done("retest"))) return "Finish both the Attack and the Retest runs first.";
    return "";
  }
  function paintStepper() {
    qa("[data-step-link]").forEach(function (a) {
      var s = a.getAttribute("data-step-link"), mark = q("[data-step-state='" + s + "']", a), locked = Boolean(gateReason(s));
      if (s === current) { a.setAttribute("aria-current", "step"); mark.textContent = " (current)"; }
      else { a.removeAttribute("aria-current"); mark.textContent = locked ? " (locked)" : ""; }
      if (locked) a.setAttribute("aria-disabled", "true"); else a.removeAttribute("aria-disabled");
    });
  }
  function show(step, opt) {
    opt = opt || {};
    if (ORDER.indexOf(step) < 0) step = "understand";
    var why = gateReason(step);
    if (why) {
      gateMsg.hidden = false; gateMsg.textContent = LABELS[step] + " is locked. " + why;
      if (!current) step = "understand"; else return;
    } else { gateMsg.hidden = true; gateMsg.textContent = ""; }
    current = step; state.step = step; save();
    qa("[data-step]").forEach(function (s) { s.hidden = s.getAttribute("data-step") !== step; });
    paintStepper();
    if (window.location.hash !== "#" + step) { try { window.history.replaceState(null, "", "#" + step); } catch (_e) { /* ignore */ } }
    if (opt.focus !== false) { var h = q("#h-" + step); if (h) { h.focus({preventScroll: true}); h.scrollIntoView({block: "start"}); } announcer.textContent = "Step " + (ORDER.indexOf(step) + 1) + " of 10: " + LABELS[step]; }
    if (step === "observe") paintObserve();
    if (step === "investigate") paintInvestigate();
    if (step === "defend") paintDefense();
    if (step === "retest") paintRetestIntro();
    if (step === "compare") paintCompare();
  }
  qa("[data-step-link]").forEach(function (a) { a.addEventListener("click", function (e) { e.preventDefault(); show(a.getAttribute("data-step-link")); }); });
  qa("[data-go]").forEach(function (b) { b.addEventListener("click", function () { show(b.getAttribute("data-go")); }); });
  window.addEventListener("hashchange", function () { var s = window.location.hash.slice(1); if (ORDER.indexOf(s) >= 0 && s !== current) show(s); });

  /* ---------- model status banner ---------- */
  var banner = q("[data-mission-banner]"), modelLine = q("[data-model-line]"), retryStatus = q("[data-retry-status]");
  function checkStatus() {
    modelLine.textContent = "Checking model…"; retryStatus.hidden = true;
    api("/api/missions/loan-desk/status").then(function (res) {
      if (!res.ok) {
        banner.hidden = false; banner.textContent = problemText(res);
        modelLine.textContent = "The Loan Desk is not reachable, so no run can start."; retryStatus.hidden = false; return;
      }
      var d = res.data, id = d.identity || {};
      if (d.available) {
        banner.hidden = true;
        modelLine.textContent = "Model " + d.model + " via Ollama" + (id.digest ? ", digest " + id.digest.slice(0, 12) : "") +
          (id.parameter_size ? ", " + id.parameter_size + " " + (id.quantization || "") : "") + ". Proposals come from real inference (" + d.proposal_source + ").";
      } else {
        banner.hidden = false; banner.textContent = "Model unavailable: " + (d.reason || "unknown") + " A run would fail visibly and no tool would run.";
        modelLine.textContent = "Model " + d.model + " is unavailable."; retryStatus.hidden = false;
      }
    });
  }
  retryStatus.addEventListener("click", checkStatus);

  /* ---------- rendering one run ---------- */
  var SEC = {BLOCKED: "BLOCKED", NOTHING_BLOCKED: "Nothing needed blocking"};
  function pill(text, kind) { return el("span", {className: "badge badge--" + (kind || "muted"), text: text}); }
  function opsLine(o) { return "Proposed " + o.proposed + " · authorized " + o.authorized + " · denied " + o.denied + " · executed " + o.executed + (o.denied_but_executed ? " · DENIED-BUT-EXECUTED " + o.denied_but_executed : " · no denied action ran"); }
  function queueBlock(view) {
    var box = el("div", {className: "queue"}, [el("h4", {text: "Underwriter queue: what a human reads"})]);
    if (!view.tickets || !view.tickets.length) { box.appendChild(el("p", {text: "Empty. The agent filed nothing in this run."})); return box; }
    var harm = (view.queue_harm && view.queue_harm.tickets_with_applicant_text) || [];
    view.tickets.forEach(function (t) {
      var bad = harm.indexOf(t.ticket_id) >= 0;
      box.appendChild(el("div", {className: "ticket" + (bad ? " ticket--harm" : "")}, [
        el("p", {className: "ticket__meta", text: t.ticket_id + " · " + t.applicant_id + " · filed by the AI agent"}),
        el("p", {className: "ticket__note", text: t.note}),
        bad ? el("p", {className: "ticket__flag", text: "This note copies text written by the applicant, filed under the agent's authority."}) : null
      ]));
    });
    return box;
  }
  function timelineTable(view) {
    var calls = {}; ((view.timeline && view.timeline.tool_calls) || []).forEach(function (c) { calls[c.step] = c; });
    var rows = view.steps.filter(function (s) { return s.kind === "tool"; }).map(function (s) {
      var c = calls[s.step] || {};
      return el("tr", null, [el("td", {text: String(s.step)}), el("td", null, [el("code", {text: s.proposal.tool})]),
        el("td", {text: s.proposal.source === "model" ? "model" : "TEST DOUBLE"}), el("td", {text: s.decision.decision + " (" + s.decision.reason + ")"}),
        el("td", {text: c.executed ? "yes, handler began" : "no"})]);
    });
    if (!rows.length) return el("p", {text: "No tool action was proposed."});
    var t = el("table", {className: "data-table"}, [el("caption", {text: "Proposed, decided, executed"}),
      el("thead", null, [el("tr", null, ["Step", "Tool", "Proposed by", "Policy decision", "Executed"].map(function (h) { return el("th", {scope: "col", text: h}); }))]),
      el("tbody", null, rows)]);
    return t;
  }
  var WHY = {step_budget_exhausted: "the agent used all of its steps without finishing", invalid_proposal_limit: "the model kept producing replies the Loan Desk could not use",
             model_unavailable: "the model could not be reached", timeout: "the run took too long", final_answer: "the agent finished"};
  function storyOf(view) {
    if (!view.outcomes || view.status === "RUNNING") return null;
    var o = view.outcomes, blocked = o.security.blocked.length, harm = view.queue_harm && view.queue_harm.tickets_with_applicant_text.length > 0;
    var why = WHY[o.business.reason] || o.business.reason || "unknown";
    if (harm) return {kind: "bad", head: "The attacker's text reached the underwriter queue.", body: "Policy allowed a valid call and nothing checked what it carried. The security outcome is a failure even though the business workflow looks " + o.business.outcome + "."};
    if (blocked && o.business.outcome === "COMPLETE") return {kind: "good", head: "Attack blocked, and the loan review still finished.", body: blocked + " proposed action(s) were denied before their handlers ran, and the agent completed the review without them."};
    if (blocked) return {kind: "good", head: "Attack blocked, even though the loan review did not finish.", body: "Security and business results are separate facts. Security: " + blocked + " proposed action(s) denied, " + o.operations.denied_but_executed + " of them executed, and no attacker text reached the queue. Business: " + o.business.outcome + " because " + why + ". An incomplete review means a human handles this case; it does not mean the control failed."};
    return {kind: "plain", head: "Nothing needed blocking in this run.", body: "No proposed action was denied and no applicant text reached the queue."};
  }
  function storyNode(view) {
    var st = storyOf(view);
    if (!st) return null;
    return el("div", {className: "callout " + (st.kind === "bad" ? "callout--warn" : st.kind === "good" ? "callout--security" : ""), role: "status"}, [el("strong", {text: st.head}), " " + st.body]);
  }
  var EVIDENCE_TEXT = {
    NOT_VERIFIED: function (e) { return "NOT VERIFIED. " + ((e.splunk || {}).detail || "Only local evidence exists.") + " Run Search 1 in Splunk, or press Verify with Splunk."; },
    PENDING: function () { return "VERIFYING… the host verifier is running the fixed Splunk searches for this run."; },
    VERIFIER_OFFLINE: function () { return "NOT VERIFIED. The host verifier is not running, so nothing can confirm indexing. It starts with the lab; evidence stays local-only until it does. You can still confirm in Splunk with the searches above."; },
    TIMED_OUT: function () { return "NOT VERIFIED. The host verifier did not answer in time. Try again; evidence stays local-only meanwhile."; },
    VERIFICATION_FAILED: function (e) { return "NOT VERIFIED. The host check could not complete: " + ((e.splunk || {}).detail || "unknown") + "."; },
    INVALID_RECORD: function () { return "NOT VERIFIED. A reconciliation record failed authentication and was ignored."; },
    SPLUNK_VERIFIED: function (e) { var s = e.splunk; return "SPLUNK-VERIFIED by the host verifier at " + s.checked_at + ": " + s.indexed_events + " indexed of " + s.local_events + " local events, per-event counts and sequences identical."; },
    SPLUNK_MISMATCH: function (e) { var s = e.splunk; return "SPLUNK MISMATCH: indexed " + (s.indexed_events || 0) + " of " + (s.local_events || 0) + " local events (" + (s.problems || []).join(", ") + "). Indexing may still be catching up; verify again."; },
    STALE: function () { return "STALE. The last host check no longer matches this run's event count; verify again."; }
  };
  function evidenceText(view) { var e = view.evidence, f = EVIDENCE_TEXT[e.indexed_status] || EVIDENCE_TEXT.NOT_VERIFIED; return f(e); }
  /* Ask the host verifier to check a run, then poll the run until the status settles. */
  function verifyRun(slot, onText) {
    var id = state.runs[slot];
    if (!id) { onText("Launch the run first."); return Promise.resolve(); }
    onText("Requesting verification…");
    return post("/api/missions/loan-desk/runs/" + encodeURIComponent(id) + "/verify", {}).then(function (res) {
      if (res.status === 503) { onText("NOT VERIFIED. The verifier is not installed on this lab (no bridge key). Evidence stays local-only; use the Splunk searches."); return; }
      if (res.status === 404) { onText("This run is no longer known to the Loan Desk. Launch it again."); return; }
      if (res.status !== 202 && res.status !== 429) { onText(problemText(res)); return; }  // 429: a request is already outstanding, so keep watching it
      var t0 = Date.now();
      return new Promise(function (resolve) {
        (function tick() {
          api("/api/missions/loan-desk/runs/" + encodeURIComponent(id)).then(function (r) {
            if (!r.ok) { onText(problemText(r) + " Press Verify to try again."); resolve(); return; }
            views[slot] = r.data;
            var st = r.data.evidence.indexed_status;
            onText(evidenceText(r.data) + (st === "PENDING" ? " (" + Math.round((Date.now() - t0) / 1000) + " s)" : ""));
            if (st === "PENDING" && Date.now() - t0 < 160000) window.setTimeout(tick, 2000); else resolve();
          });
        }());
      });
    });
  }
  function renderRun(slot, view, extra) {
    var panel = q("[data-run-panel='" + slot + "']");
    panel.textContent = "";
    panel.setAttribute("aria-busy", view.status === "RUNNING" ? "true" : "false");
    var head = el("p", null, [pill(view.status, view.status === "COMPLETED" ? "ok" : view.status === "RUNNING" ? "warn" : "unavailable"), " ",
      el("span", {text: " posture " + view.posture.toUpperCase() + " · run.id "}), el("code", {text: view.run_id})]);
    panel.appendChild(head);
    if (extra) panel.appendChild(extra);
    var story = storyNode(view); if (story) panel.appendChild(story);
    if (view.status === "RUNNING") {
      var n = (view.timeline && view.timeline.events && view.timeline.events.length) || 0;
      panel.appendChild(el("p", {className: "run-panel__live", text: n ? "Working… " + n + " event(s) recorded so far." : "Starting…"}));
    }
    if (view.status === "FAILED") {
      panel.appendChild(el("p", {className: "callout callout--warn", text: view.stop_reason === "model_unavailable"
        ? "The model could not be reached. No action was proposed, no policy decision was made and no tool ran. " + (view.error || "")
        : "The run failed (" + view.stop_reason + "). " + (view.error || "")}));
    }
    if (view.status === "INCOMPLETE") panel.appendChild(el("p", {className: "callout callout--warn", text: "The agent used up its step budget before finishing. The business workflow is INCOMPLETE."}));
    if (view.outcomes && view.status !== "RUNNING") {
      var o = view.outcomes;
      panel.appendChild(el("div", {className: "outcomes"}, [
        el("div", {className: "outcome outcome--" + o.security.outcome}, [el("strong", {text: "Security outcome"}), el("span", {text: SEC[o.security.outcome] + (o.security.blocked.length ? " (" + o.security.blocked.length + ")" : "")})]),
        el("div", {className: "outcome outcome--" + o.business.outcome}, [el("strong", {text: "Business workflow"}), el("span", {text: o.business.outcome + (o.business.reason ? " · " + o.business.reason : "")})])]));
      panel.appendChild(el("p", {className: "muted", text: opsLine(o.operations)}));
      if (o.security.blocked.length) {
        panel.appendChild(el("ul", null, o.security.blocked.map(function (b) { return el("li", {text: "Step " + b.step + " " + b.tool + ": " + b.reason + (b.executed ? " (EXECUTED ANYWAY)" : " (handler did not run)")}); })));
      }
    }
    if (view.steps && view.steps.length) panel.appendChild(timelineTable(view));
    if (view.status !== "RUNNING") panel.appendChild(queueBlock(view));
    if (view.advisory && view.status === "COMPLETED") {
      var bad = view.advisory.unsupported_figures || [];
      panel.appendChild(el("p", {className: "muted", text: "Model summary (advisory, not verified)" + (bad.length ? " contains unsupported figures: " + bad.join(", ") : "") + ": " + view.advisory.summary}));
    }
    if (view.evidence) panel.appendChild(el("p", {className: "muted", text: "Local evidence: " + view.evidence.event_count + " events emitted by AcmeBank. " + evidenceText(view)}));
  }

  /* ---------- run lifecycle: launch, poll, stop waiting, recover ---------- */
  function applicationFrom(form, notesOverride) {
    var a = {};
    FIELDS.forEach(function (f) { var n = form ? q("[name='" + f + "']", form) : null; a[f] = n ? n.value : ""; });
    if (notesOverride !== undefined) a.notes = notesOverride;
    return a;
  }
  function setBusy(slot, on) {
    busy[slot] = on;
    qa("[data-launch='" + slot + "']").forEach(function (b) { b.disabled = on; });
  }
  function trackerFor(slot) {
    var panel = q("[data-run-panel='" + slot + "']"), note = panel.querySelector("[data-wait-note]");
    return {panel: panel, note: note};
  }
  function waitControls(slot, runId, started, attempt) {
    var stopBtn = el("button", {type: "button", className: "button button--ghost", text: "Stop waiting"});
    var info = el("p", {className: "run-panel__wait", "data-wait-note": true}, [stopBtn]);
    var stopped = false;
    stopBtn.addEventListener("click", function () {
      stopped = true; info.textContent = "";
      var again = el("button", {type: "button", className: "button button--secondary", text: "Keep waiting"});
      again.addEventListener("click", function () { poll(slot, runId, Date.now(), 0); });
      info.appendChild(el("span", {text: "Stopped waiting. The run continues inside AcmeBank. "}));
      info.appendChild(again);
      setBusy(slot, false);
    });
    return {node: info, isStopped: function () { return stopped; }};
  }
  function poll(slot, runId, started, attempt) {
    var ctl = waitControls(slot, runId, started, attempt);
    function tick(tries) {
      if (ctl.isStopped()) return;
      api("/api/missions/loan-desk/runs/" + encodeURIComponent(runId)).then(function (res) {
        if (ctl.isStopped()) return;
        if (!res.ok) {
          if (res.status === 404) {
            delete state.runs[slot]; delete views[slot]; save(); setBusy(slot, false); paintStepper();
            var p = q("[data-run-panel='" + slot + "']"); p.textContent = "";
            p.appendChild(el("p", {className: "callout callout--warn", text: "That run no longer exists (the Attack Service or AcmeBank was restarted). Launch it again."}));
            return;
          }
          if (tries < 6) {
            var p2 = q("[data-run-panel='" + slot + "']");
            var msg = el("p", {className: "callout callout--warn", role: "status", text: problemText(res) + " Retrying (" + (tries + 1) + " of 6)…"});
            var old = p2.querySelector("[data-reconnect]"); if (old) old.remove();
            msg.setAttribute("data-reconnect", ""); p2.appendChild(msg);
            window.setTimeout(function () { tick(tries + 1); }, Math.min(8000, 1000 * (tries + 1)));
          } else {
            setBusy(slot, false);
            var p3 = q("[data-run-panel='" + slot + "']"); p3.textContent = "";
            var retry = el("button", {type: "button", className: "button button--secondary", text: "Retry now"});
            retry.addEventListener("click", function () { setBusy(slot, true); poll(slot, runId, Date.now(), 0); });
            p3.appendChild(el("p", {className: "callout callout--warn", text: "Disconnected. " + problemText(res)}));
            p3.appendChild(retry);
          }
          return;
        }
        var recovered = tries > 0;
        views[slot] = res.data; renderRun(slot, res.data, res.data.status === "RUNNING" ? ctl.node : null);
        if (recovered) q("[data-run-panel='" + slot + "']").appendChild(el("p", {className: "callout", role: "status", text: "Connection restored."}));
        paintStepper();
        if (res.data.status === "RUNNING") {
          if (Date.now() - started > POLL_MAX_MS) {
            setBusy(slot, false);
            q("[data-run-panel='" + slot + "']").appendChild(el("p", {className: "callout callout--warn", text: "This is taking longer than expected (over " + (POLL_MAX_MS / 1000) + " s). The run may still finish; use Stop waiting / Keep waiting or relaunch."}));
            return;
          }
          window.setTimeout(function () { tick(0); }, POLL_MS);
        } else { setBusy(slot, false); afterRun(slot, res.data); }
      });
    }
    tick(0);
  }
  function launch(slot, application, posture) {
    if (busy[slot]) return;
    setBusy(slot, true);
    var p = q("[data-run-panel='" + slot + "']"); p.textContent = ""; p.setAttribute("aria-busy", "true");
    p.appendChild(el("p", {text: "Submitting to the Loan Desk…"}));
    post("/api/missions/loan-desk/runs", {application: application, posture: posture}).then(function (res) {
      if (res.status === 202) {
        state.runs[slot] = res.data.run_id; save(); views[slot] = res.data; markProgress("in_progress");
        renderRun(slot, res.data); poll(slot, res.data.run_id, Date.now(), 0); paintStepper(); return;
      }
      setBusy(slot, false); p.textContent = "";
      if (res.status === 400 && res.data.errors) { showFormErrors(res.data.errors, slot); p.appendChild(el("p", {className: "callout callout--warn", text: "The application was not accepted. Nothing ran."})); return; }
      var retry = el("button", {type: "button", className: "button button--secondary", text: "Retry"});
      retry.addEventListener("click", function () { launch(slot, application, posture); });
      p.appendChild(el("p", {className: "callout callout--warn", text: problemText(res) + " Nothing ran."}));
      p.appendChild(retry);
    });
  }
  function showFormErrors(errors, slot) {
    var box = q("[data-form-errors]"); box.hidden = true; qa("[data-err]").forEach(function (n) { n.textContent = ""; });
    var general = [];
    Object.keys(errors).forEach(function (k) { var n = q("[data-err='" + k + "']"); if (n) n.textContent = errors[k]; else general.push(errors[k]); });
    if (slot === "explore" && (general.length || Object.keys(errors).length)) {
      box.hidden = false; box.textContent = general.length ? general.join(" ") : "Please fix the highlighted fields.";
      var first = Object.keys(errors).map(function (k) { return q("[name='" + k + "']"); }).filter(Boolean)[0]; if (first) first.focus();
    }
  }
  function afterRun(slot, view) {
    if (slot === "attack") paintObserve();
    if (slot === "retest") paintCompare();
    paintStepper();
  }

  /* ---------- explore ---------- */
  var exploreForm = q("[data-app-form]");
  exploreForm.addEventListener("submit", function (e) {
    e.preventDefault();
    q("[data-form-errors]").hidden = true; qa("[data-err]").forEach(function (n) { n.textContent = ""; });
    launch("explore", applicationFrom(exploreForm), "baseline");
  });

  /* ---------- predict ---------- */
  var predictForm = q("[data-predict-form]");
  function pick(name) { var n = q("input[name='" + name + "']:checked", predictForm); return n ? n.value : null; }
  function paintPrediction() {
    ["follow", "decision", "queue"].forEach(function (k) { qa("input[name='" + k + "']", predictForm).forEach(function (i) { i.checked = state.prediction[k] === i.value; i.disabled = Boolean(state.prediction.locked); }); });
    q("[data-lock-prediction]").disabled = Boolean(state.prediction.locked);
    q("[data-prediction-locked]").hidden = !state.prediction.locked;
  }
  predictForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var err = q("[data-predict-error]");
    if (!pick("follow") || !pick("decision") || !pick("queue")) { err.textContent = "Answer all three questions before locking."; return; }
    err.textContent = "";
    state.prediction = {follow: pick("follow"), decision: pick("decision"), queue: pick("queue"), locked: true}; save(); paintPrediction(); paintStepper();
  });

  /* ---------- attack ---------- */
  var attackNotes = q("[data-attack-notes]"), defaultAttack = root.getAttribute("data-attack-notes");
  q("[data-reset-attack-text]").addEventListener("click", function () { attackNotes.value = defaultAttack; });
  q("[data-launch='attack']").addEventListener("click", function () {
    state.attackNotes = attackNotes.value; save();
    launch("attack", applicationFrom(exploreForm, attackNotes.value), "baseline");
  });

  /* ---------- observe ---------- */
  function ticketFor(view) { return view && view.tickets && view.tickets[0] ? view.tickets[0] : null; }
  function reviewCall(view) { return ((view.timeline && view.timeline.tool_calls) || []).filter(function (c) { return c.tool === "submit_for_underwriter_review"; })[0]; }
  function actual(view) {
    var t = ticketFor(view), c = reviewCall(view), harm = view.queue_harm && view.queue_harm.tickets_with_applicant_text.length > 0;
    return {follow: harm ? "yes" : "no", decision: c ? c.decision : "none", queue: harm ? "planted" : (t ? "neutral" : "nothing")};
  }
  function paintObserve() {
    var v = views.attack, box = q("[data-prediction-review]"), queue = q("[data-queue-view]");
    box.textContent = ""; queue.textContent = "";
    if (!v) { box.appendChild(el("p", {text: "Launch the attack to see the result."})); return; }
    if (v.status === "RUNNING") { box.appendChild(el("p", {text: "The attack run is still working. This view updates when it finishes."})); return; }
    var a = actual(v), p = state.prediction;
    var rows = [["Did the agent copy the planted text?", p.follow, a.follow], ["Policy decision for the review submission", p.decision, a.decision], ["What the underwriter sees", p.queue, a.queue]];
    box.appendChild(el("table", {className: "data-table"}, [el("caption", {text: "Your prediction versus the run"}),
      el("thead", null, [el("tr", null, ["Question", "You predicted", "What happened", ""].map(function (h) { return el("th", {scope: "col", text: h}); }))]),
      el("tbody", null, rows.map(function (r) { return el("tr", null, [el("td", {text: r[0]}), el("td", {text: String(r[1])}), el("td", {text: String(r[2])}), el("td", {text: String(r[1]) === String(r[2]) ? "match" : "differs"})]); }))]));
    box.appendChild(el("p", {className: "callout callout--security", text: "A DENY or an ALLOW is a policy decision. Whether the handler began is a separate fact: see the Executed column and the event agentsec.mcp.started."}));
    queue.appendChild(queueBlock(v));
    queue.appendChild(timelineTable(v));
  }

  /* ---------- investigate ---------- */
  function splunkLink(spl) { return window.location.protocol + "//" + window.location.hostname + ":8000/en-US/app/search/search?q=" + encodeURIComponent("search " + spl) + "&earliest=-24h%40h&latest=now"; }
  function searches(id) {
    var base = 'index=agentsec_telemetry sourcetype="otel:agentic:json" agentsec.run.id="' + id + '"';
    return [
      ["Search 1: every event of this run", base + " | stats count AS events dc(agentsec.sequence) AS distinct_sequences", "events is the number to compare. Counting the values of agentsec.sequence would double it because the field is multivalue in Splunk."],
      ["Search 2: the policy decision for the review", base + ' event.name="agentsec.control.decision" gen_ai.tool.name="submit_for_underwriter_review" | stats latest(_time) AS _time values(agentsec.control.decision) AS decision values(agentsec.control.reason) AS reason values(agentsec.defense.posture) AS posture', "values() removes the duplicate multivalue copies Splunk keeps of every field. A decision event is not an execution event."],
      ["Search 3: what the handler returned (the filed note)", base + ' event.name="agentsec.mcp.completed" gen_ai.tool.name="submit_for_underwriter_review" | stats latest(_time) AS _time values(agentsec.content.preview) AS filed_by_handler', "No rows when the handler never ran."]
    ];
  }
  function paintEvidenceState(v) {
    var node = q("[data-evidence-state]");
    node.textContent = v ? "LOCAL evidence: AcmeBank emitted " + v.evidence.event_count + " events for this run. " + evidenceText(v) : "No attack run yet.";
  }
  function paintInvestigate() {
    var v = views.attack, list = q("[data-spl-list]"); list.textContent = "";
    paintEvidenceState(v);
    if (!v) return;
    searches(v.run_id).forEach(function (s) {
      var area = el("textarea", {className: "spl", readonly: true, rows: "3", "aria-label": s[0]}); area.value = s[1];
      var copy = el("button", {type: "button", className: "button button--ghost", text: "Copy search"});
      var fb = el("span", {className: "muted", role: "status"});
      copy.addEventListener("click", function () {
        var ok = function (t) { fb.textContent = t; };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s[1]).then(function () { ok(" Copied."); }, function () { ok(" Copy failed; select the text."); });
        else { area.select(); ok(" Select and copy the text."); }
      });
      list.appendChild(el("div", {className: "spl-block"}, [el("h4", {text: s[0]}), area,
        el("p", null, [copy, " ", el("a", {className: "button button--secondary", href: splunkLink(s[1]), target: "_blank", rel: "noopener", text: "Open in Splunk"}), fb]), el("p", {className: "muted", text: s[2]})]));
    });
  }
  q("[data-count-form]").addEventListener("submit", function (e) {
    e.preventDefault();
    var v = views.attack, out = q("[data-count-result]"), err = q("[data-count-error]"), raw = q("#splunk-count").value.trim();
    err.textContent = "";
    if (!v) { err.textContent = "Launch the attack first."; return; }
    if (!/^\d{1,5}$/.test(raw)) { err.textContent = "Enter the whole number Splunk shows under events."; return; }
    var n = Number(raw), local = v.evidence.event_count;
    out.textContent = n === local ? "Your Splunk count (" + n + ") matches the " + local + " events AcmeBank emitted. This is your own observation, recorded as learner-reported."
      : n === local * 2 ? "You entered " + n + ", exactly double. You probably counted field values (multivalue) instead of events. Use the events column."
      : n < local ? "You entered " + n + " but AcmeBank emitted " + local + ". Indexing may still be catching up, or your time range is too short. Search again."
      : "You entered " + n + ", more than the " + local + " events AcmeBank emitted. Check that you filtered on this run.id.";
  });
  var verifyBtn = q("[data-recheck-evidence]");
  verifyBtn.addEventListener("click", function () {
    verifyBtn.disabled = true;
    verifyRun("attack", function (t) { q("[data-evidence-state]").textContent = t; }).then(function () { verifyBtn.disabled = false; });
  });
  q("[data-proof-form]").addEventListener("submit", function (e) {
    e.preventDefault();
    var pick = q("#proof-event").value, out = q("[data-proof-result]");
    out.textContent = !pick ? "Choose an event first." : pick === "agentsec.mcp.started" ? "Correct. agentsec.mcp.started is emitted just before the handler body, so its presence proves the handler began. A control.decision of ALLOW only says it was permitted."
      : "Not quite. " + pick + " does not prove a handler began. Look for the event that is emitted when the handler starts.";
  });

  /* ---------- defend ---------- */
  var defenseForm = q("[data-defense-form]");
  var RULE = {baseline: "Tool, scope and applicant are checked. The review note may be any text up to 200 characters.",
              hardened: "Tool, scope and applicant are checked. The review note must equal one reason code, or the call is denied with argument_not_allowed:note."};
  function paintDefense() {
    qa("input[name='posture']", defenseForm).forEach(function (i) { i.checked = i.value === state.posture; });
    q("[data-defense-current]").textContent = state.posture.toUpperCase() + (state.defenseApplied ? " (applied)" : " (not applied yet)");
    q("[data-defense-rule]").textContent = RULE[state.posture];
  }
  defenseForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var n = q("input[name='posture']:checked", defenseForm);
    if (!n) { q("[data-defense-current]").textContent = "Choose a setting first."; return; }
    state.posture = n.value; state.defenseApplied = true; save(); paintDefense(); paintStepper();
  });
  q("[data-revert-defense]").addEventListener("click", function () { state.posture = "baseline"; state.defenseApplied = true; save(); paintDefense(); paintStepper(); });

  /* ---------- retest ---------- */
  function paintRetestIntro() {
    q("[data-retest-posture]").textContent = "The retest will run the same planted text with posture " + state.posture.toUpperCase() + "." +
      (state.posture === "baseline" ? " That is the unprotected setting: expect the attack to work again. Go back to Defend to harden it." : "");
  }
  q("[data-launch='retest']").addEventListener("click", function () {
    launch("retest", applicationFrom(exploreForm, state.attackNotes || attackNotes.value), state.posture);
  });

  /* ---------- compare ---------- */
  function cell(v, fn) { return v ? fn(v) : "no run"; }
  function paintCompare() {
    var box = q("[data-compare-table]"); box.textContent = "";
    var a = views.attack, r = views.retest;
    if (!(a && r)) { box.appendChild(el("p", {text: "Finish both runs to compare them."})); return; }
    function rev(v) { var c = reviewCall(v); return c ? c.decision + " (" + c.reason + "), handler " + (c.executed ? "began" : "did not run") : "no review submitted"; }
    var rows = [
      ["Posture", function (v) { return v.posture.toUpperCase(); }],
      ["Policy decision for the review note", rev],
      ["Underwriter queue note", function (v) { var t = ticketFor(v); return t ? t.note : "(nothing filed)"; }],
      ["Attacker text reached the queue", function (v) { return v.queue_harm.tickets_with_applicant_text.length ? "YES" : "no"; }],
      ["Security outcome", function (v) { return SEC[v.outcomes.security.outcome]; }],
      ["Business workflow", function (v) { return v.outcomes.business.outcome; }],
      ["Proposed / denied / executed", function (v) { return v.outcomes.operations.proposed + " / " + v.outcomes.operations.denied + " / " + v.outcomes.operations.executed; }],
      ["Events emitted (local)", function (v) { return String(v.evidence.event_count); }],
      ["Model", function (v) { return v.model.name + (v.model.identity && v.model.identity.digest ? " " + v.model.identity.digest.slice(0, 12) : ""); }],
      ["Splunk evidence", function (v) { return v.evidence.indexed_status.replace(/_/g, " "); }],
      ["run.id", function (v) { return v.run_id; }]
    ];
    box.appendChild(el("table", {className: "data-table"}, [el("caption", {text: "Attack run versus retest run"}),
      el("thead", null, [el("tr", null, ["", "ATTACK", "RETEST"].map(function (h) { return el("th", {scope: "col", text: h}); }))]),
      el("tbody", null, rows.map(function (row) { var x = row[1](a), y = row[1](r); return el("tr", {className: x !== y ? "is-different" : null}, [el("th", {scope: "row", text: row[0]}), el("td", {text: x}), el("td", {text: y})]); }))]));
    var rs = storyNode(r); if (rs) box.appendChild(rs);
    var cb = el("button", {type: "button", className: "button button--secondary", text: "Verify both runs with Splunk"});
    var cv = q("[data-compare-status]");
    cb.addEventListener("click", function () {
      cb.disabled = true; cv.hidden = false;
      verifyRun("attack", function (t) { cv.textContent = "Attack run: " + t; }).then(function () {
        var attackText = cv.textContent;
        return verifyRun("retest", function (t) { cv.textContent = attackText + "  |  Retest run: " + t; });
      }).then(function () { cb.disabled = false; var keep = cv.textContent; paintCompare(); cv.hidden = false; cv.textContent = keep; });
    });
    box.appendChild(el("p", null, [cb]));
    var worked = a.queue_harm.tickets_with_applicant_text.length > 0 && r.queue_harm.tickets_with_applicant_text.length === 0;
    box.appendChild(el("p", {className: "callout " + (worked ? "callout--security" : "callout--warn"), text: worked
      ? "The same planted text reached the queue under BASELINE and did not under " + r.posture.toUpperCase() + (r.outcomes.business.outcome !== "COMPLETE" ? ", even though the retest's loan review did not finish (a usability cost, not a security failure)" : "") + ". Model output varies run to run, so one pair of runs is an illustration; the committed benchmark repeats this 20 times per setting."
      : "These two runs do not show the defense working: the attacker text reached the queue in the retest, or it never reached it in the attack. Re-run with the right postures, or read the rows to see why."}));
  }

  /* ---------- explain ---------- */
  var ANSWERS = {q1: "ctrl", q2: "valid", q3: "codes", q4: "started"};
  q("[data-explain-form]").addEventListener("submit", function (e) {
    e.preventDefault();
    var form = e.currentTarget, err = q("[data-explain-error]"), out = q("[data-explain-result]"), wrong = [];
    err.textContent = "";
    Object.keys(ANSWERS).forEach(function (k) { var n = q("input[name='" + k + "']:checked", form); if (!n) wrong.push(k + " (unanswered)"); else if (n.value !== ANSWERS[k]) wrong.push(k); });
    var text = q("#explain-text").value.trim();
    if (wrong.length) { out.textContent = "Not yet. Revisit: " + wrong.join(", ") + ". The Compare step and the policy decision rows have the answers."; return; }
    if (text.length < 60) { err.textContent = "Write at least 60 characters in your own words."; return; }
    out.textContent = "Mission complete. You attacked a live agent, proved the result, changed a control and retested it.";
    markProgress("workflow_complete");
  });
  q("[data-reset-mission]").addEventListener("click", function () {
    state = {prediction: {}, runs: {}, posture: "baseline", defenseApplied: false}; views = {}; save();
    qa("[data-run-panel]").forEach(function (p) { p.textContent = ""; p.appendChild(el("p", {text: "No run yet."})); });
    paintPrediction(); paintDefense(); show("understand");
  });

  /* ---------- start up: re-adopt this tab's runs ---------- */
  function adopt(slot) {
    if (!state.runs[slot]) return Promise.resolve();
    return api("/api/missions/loan-desk/runs/" + encodeURIComponent(state.runs[slot])).then(function (res) {
      if (res.ok) { views[slot] = res.data; renderRun(slot, res.data); if (res.data.status === "RUNNING") { setBusy(slot, true); poll(slot, res.data.run_id, Date.now(), 0); } }
      else if (res.status === 404) { delete state.runs[slot]; save(); }
    });
  }
  checkStatus(); paintPrediction(); paintDefense();
  if (state.attackNotes) attackNotes.value = state.attackNotes;
  Promise.all([adopt("explore"), adopt("attack"), adopt("retest")]).then(function () {
    var initial = window.location.hash.slice(1) || state.step || "understand";
    show(ORDER.indexOf(initial) < 0 ? "understand" : initial, {focus: Boolean(window.location.hash)});
  });
}());
