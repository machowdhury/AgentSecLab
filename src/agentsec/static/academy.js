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
  function provenanceBlock(doc) {
    var badge = el("span", {className: "badge " + (doc.provenance === "LIVE" ? "badge--live" : "badge--replay"), text: doc.provenance});
    var facts = doc.facts;
    var list = el("dl", {className: "facts-grid"}, [
      el("div", null, [el("dt", {text: "run.id"}), el("dd", null, [code(doc.run_id)])]),
      el("div", null, [el("dt", {text: "Source"}), el("dd", null, [code(doc.source)])]),
      el("div", null, [el("dt", {text: "Source sha256"}), el("dd", null, [code(doc.source_sha256)])]),
      el("div", null, [el("dt", {text: "Recorded"}), el("dd", {text: (facts.first_timestamp || "NOT MEASURED") + " to " + (facts.last_timestamp || "NOT MEASURED") + " (UTC)"})]),
      el("div", null, [el("dt", {text: "Recorded mode and profile"}), el("dd", {text: facts.testbed_mode + " · " + facts.security_profile})]),
      el("div", null, [el("dt", {text: "Events in record"}), el("dd", {text: String(facts.event_count)})])
    ]);
    var block = el("div", {className: "provenance-card"}, [
      el("p", null, [badge, " ", el("span", {text: doc.provenance_text})]),
      list
    ]);
    if (doc.launch_response) {
      block.appendChild(el("p", {className: "form-note", text: "Launch response (independent source): runtime handler count " + doc.launch_response.runtime_handler_count + ". " + doc.launch_response.note}));
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
    baselineSlot.replaceChildren(el("p", {className: "form-note", text: "Loading the recorded baseline…"}));
    fetchEvidence(REPLAY.BASELINE).then(function (doc) {
      renderEvidence(baselineSlot, doc);
      state.baselineLoaded = true;
      save();
    }).catch(function (data) {
      baselineSlot.replaceChildren(el("p", {className: "callout callout--warn", text: errorText(data, "The baseline could not be loaded. That is missing evidence, not a result.")}));
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
      el("p", null, [el("span", {className: "badge " + (doc.provenance === "LIVE" ? "badge--live" : "badge--replay"), text: doc.provenance}), " run.id ", code(doc.run_id), " ", copyButton, copyFeedback]),
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
      card.replaceChildren(el("p", null, ["run.id ", code(runId)]), retry);
      return null;
    });
  }

  function launch(mode) {
    if (busy || hasRun(mode)) return;
    busy = true;
    syncControls();
    runStatus(mode, "Launching LIVE " + mode + ". Launch controls are disabled until it finishes.");
    fetch("/api/launch", {
      method: "POST",
      headers: {"Content-Type": "application/json", "Accept": "application/json"},
      body: JSON.stringify({lab_id: LAB, specimen_id: SPECIMEN[mode], mode: mode, execution: "live"})
    }).then(function (r) {
      return r.json().catch(function () { return {error_class: "ERROR", detail: "The response was not JSON."}; });
    }).catch(function () {
      return {error_class: "ERROR", detail: "The browser did not receive a usable response."};
    }).then(function (data) {
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
      empty.textContent = "The ATTACK evidence could not be loaded: " + errorText(data, "unknown error") + ". That is missing evidence, not a result.";
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
      slot.replaceChildren(el("p", {className: "callout callout--warn", text: "The comparison could not be built: " + errorText(data, "unknown error") + ". Missing data is NOT MEASURED, not SAFE."}));
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

  /* ---- start up ---- */
  paintPrediction();
  if (state.baselineLoaded) loadBaseline();
  ["ATTACK", "RETEST"].forEach(function (mode) {
    if (hasRun(mode)) {
      runStatus(mode, mode + " run recorded in this tab (" + state.runs[mode].provenance + ").");
      adoptRun(mode, state.runs[mode].run_id, state.runs[mode].provenance);
    }
  });
  var initial = window.location.hash.slice(1) || state.step || "start";
  show(ORDER.indexOf(initial) === -1 ? "start" : initial, {focus: Boolean(window.location.hash)});
}());
