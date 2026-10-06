/* Shared learner-UI helpers. Does not call Ollama or change control decisions. */
(function (window) {
  "use strict";

  function statusFromResult(data) {
    if (!data || typeof data !== "object") {
      return "ERROR";
    }
    if (data.terminal === "completed_denied") {
      return "DENIED";
    }
    if (data.terminal === "completed_allowed") {
      return "COMPLETED";
    }
    return "ERROR";
  }

  function applyState(statusEl, liveEl, state, message) {
    if (statusEl) {
      statusEl.dataset.state = state;
      statusEl.textContent = state;
    }
    if (liveEl) {
      liveEl.textContent = message || state;
    }
  }

  function setBusy(formEl, buttonEl, busy) {
    if (formEl) {
      formEl.setAttribute("aria-busy", busy ? "true" : "false");
    }
    if (buttonEl) {
      buttonEl.disabled = Boolean(busy);
    }
  }

  function fillRunId(inputEl, value) {
    if (!inputEl) {
      return;
    }
    inputEl.value = value || "";
    inputEl.title = value || "";
  }

  function copyFromInput(inputEl) {
    if (!inputEl || !inputEl.value) {
      return Promise.resolve(false);
    }
    inputEl.focus();
    inputEl.select();
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(inputEl.value).then(
        function () { return true; },
        function () { return document.execCommand("copy"); }
      );
    }
    return Promise.resolve(document.execCommand("copy"));
  }

  function hops(data) {
    return data && Array.isArray(data.hops) ? data.hops : [];
  }

  function firstDecision(data) {
    var list = hops(data);
    for (var i = 0; i < list.length; i += 1) {
      if (list[i]["control.decision"]) {
        return String(list[i]["control.decision"]);
      }
    }
    return "";
  }

  function anyTrue(data, field) {
    return hops(data).some(function (hop) {
      return hop[field] === true;
    });
  }

  function learnerHref(url, loc) {
    var page = loc || window.location;
    if (!url) {
      return url;
    }
    if (url.charAt(0) === "/" && url.charAt(1) !== "/") {
      var splunkPath = url === "/en-US" || url.indexOf("/en-US/") === 0;
      if (!page.port || page.port === "8000" || !splunkPath) {
        return url;
      }
      return page.protocol + "//" + page.hostname + ":8000" + url;
    }
    var parsed;
    try {
      parsed = new URL(url, page.origin);
    } catch (err) {
      return url;
    }
    if (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "::1") {
      var port = parsed.port ? ":" + parsed.port : "";
      return page.protocol + "//" + page.hostname + port + parsed.pathname + parsed.search + parsed.hash;
    }
    return url;
  }

  function rewriteLearnerLinks(root, loc) {
    var scope = root || document;
    var nodes = scope.querySelectorAll("a[href]");
    for (var i = 0; i < nodes.length; i += 1) {
      var raw = nodes[i].getAttribute("href");
      if (!raw) {
        continue;
      }
      nodes[i].setAttribute("href", learnerHref(raw, loc));
    }
  }

  function learnerRunState(data) {
    if (!data || data.error_class === "ERROR") {
      return {
        state: "RUN FAILED",
        message: "The launch did not complete. This is not a control DENY."
      };
    }
    var terminal = (data.runtime && data.runtime.terminal) || data.terminal || "";
    if (terminal === "completed_denied") {
      return {
        state: "RUN DENIED",
        message: "The control denied this run. Authorization is not execution. The evidence line is separate and is not a Splunk verdict."
      };
    }
    if (terminal === "completed_allowed" || terminal === "run_completed") {
      return {
        state: "RUN COMPLETED",
        message: "Launcher terminal " + terminal + ". Completion is not proof the attack succeeded. The evidence line is separate and is not a Splunk verdict."
      };
    }
    if (terminal === "run_failed") {
      return {
        state: "RUN FAILED",
        message: "The launcher reported run_failed. This is not a control DENY."
      };
    }
    if (data.probe_error || data.evidence_state === "EVIDENCE_CHECK_UNAVAILABLE") {
      return {
        state: "EVIDENCE CHECK UNAVAILABLE",
        message: "The evidence probe could not run. This is not absence of evidence and not a control DENY."
      };
    }
    if (data.evidence_timeout) {
      return {
        state: "CHECK TIMED OUT",
        message: "The evidence check timed out while waiting for indexing. This is not a control DENY."
      };
    }
    if (!terminal) {
      return {
        state: "RUN IN PROGRESS",
        message: "The launcher has not reported a terminal state. This is not a control decision."
      };
    }
    return {
      state: "RUN FAILED",
      message: "The launch did not complete. This is not a control DENY."
    };
  }

  function evidencePresentation(data) {
    if (!data || data.probe_error || data.evidence_state === "EVIDENCE_CHECK_UNAVAILABLE") {
      var reason = data && data.probe_error ? " (" + data.probe_error + ")" : "";
      return {
        state: "EVIDENCE CHECK UNAVAILABLE",
        message: "The evidence probe could not run" + reason + ". This is not absence of evidence, not DENY, and not a Splunk verdict. Search remains authoritative."
      };
    }
    if (data.evidence_timeout) {
      return {
        state: "CHECK TIMED OUT",
        message: "The evidence check timed out while waiting for indexing. This is not a control DENY. Search remains authoritative."
      };
    }
    if (data.evidence_state === "EVIDENCE_READY" || data.splunk_verified === true) {
      return {
        state: "EVIDENCE CONFIRMED",
        message: "Splunk returned at least one event for this run.id. evidence_state=EVIDENCE_READY. That is not SAFE and not a control verdict."
      };
    }
    if (data.evidence_state === "WAITING_FOR_EVIDENCE") {
      return {
        state: "WAITING FOR INDEXING",
        message: "No indexed event was returned yet. This is not DENY and not a probe failure. Search remains authoritative."
      };
    }
    return null;
  }

  function afterPaint() {
    return new Promise(function (resolve) {
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(resolve);
      });
    });
  }

  var SESSION_KEY = "agentsec.learner.session.v1";

  function readSession() {
    try {
      var raw = window.sessionStorage.getItem(SESSION_KEY);
      var parsed = raw ? JSON.parse(raw) : {};
      if (!parsed || typeof parsed !== "object") {
        return {predictions: {}, runs: []};
      }
      parsed.predictions = parsed.predictions || {};
      parsed.runs = Array.isArray(parsed.runs) ? parsed.runs : [];
      return parsed;
    } catch (err) {
      return {predictions: {}, runs: []};
    }
  }

  function writeSession(data) {
    try {
      window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(data));
    } catch (err) {
      return;
    }
  }

  function savePrediction(labId, prediction) {
    var session = readSession();
    session.predictions[labId || "lab"] = {
      control: prediction.control || "UNKNOWN",
      execution: prediction.execution || "UNKNOWN",
      at: new Date().toISOString()
    };
    writeSession(session);
  }

  function predictionFor(labId) {
    var session = readSession();
    return session.predictions[labId || "lab"] || null;
  }

  function recordLaunch(entry) {
    var session = readSession();
    var row = {
      mode: entry.mode || "",
      runId: entry.runId || "",
      labId: entry.labId || "",
      state: entry.state || "",
      at: entry.at || new Date().toISOString(),
      terminal: entry.terminal || "",
      evidenceState: entry.evidenceState || "",
      decision: entry.decision || "",
      llmCallCount: entry.llmCallCount
    };
    session.runs.unshift(row);
    session.runs = session.runs.slice(0, 12);
    writeSession(session);
  }

  function historyText(row) {
    var client = "LAST KNOWN CLIENT STATE: " + (row.state || "UNKNOWN");
    var terminal = row.terminal ? String(row.terminal) : "NOT IN THIS TAB";
    var evidence = row.evidenceState ? String(row.evidenceState) : "NOT IN THIS TAB";
    return [
      row.mode || "",
      client,
      "launcher terminal=" + terminal,
      "evidence=" + evidence,
      "not a Splunk verdict",
      row.runId || "",
      row.at || ""
    ].join(" · ");
  }

  function renderSession(listEl) {
    if (!listEl) {
      return;
    }
    var runs = readSession().runs;
    listEl.replaceChildren();
    if (!runs.length) {
      var empty = document.createElement("li");
      empty.textContent = "No launches in this browser tab yet. A reload keeps this list. It is not an account and not a verdict.";
      listEl.appendChild(empty);
      return;
    }
    runs.forEach(function (row) {
      var item = document.createElement("li");
      item.textContent = historyText(row);
      listEl.appendChild(item);
    });
  }

  function pairSessionRuns(runs, labId) {
    if (!labId || !Array.isArray(runs)) {
      return null;
    }
    var attack = null;
    var retest = null;
    for (var i = 0; i < runs.length; i += 1) {
      var row = runs[i];
      if (!row || row.labId !== labId || !row.runId) {
        continue;
      }
      if (!attack && row.mode === "ATTACK") {
        attack = row;
      }
      if (!retest && row.mode === "RETEST") {
        retest = row;
      }
    }
    if (!attack || !retest || attack.runId === retest.runId) {
      return null;
    }
    return {attack: attack, retest: retest};
  }

  function applyLauncherRecord(row, body) {
    var runtime = body && body.runtime ? body.runtime : {};
    var terminal = runtime.terminal || (body && body.terminal) || row.terminal || "";
    var view = {
      runtime: runtime,
      terminal: terminal,
      evidence_state: (body && body.evidence_state) || row.evidenceState || "",
      evidence_timeout: Boolean(body && body.evidence_timeout),
      probe_error: (body && body.probe_error) || "",
      error_class: body && body.error_class
    };
    var label = learnerRunState(view);
    var next = {
      mode: row.mode,
      runId: row.runId,
      labId: row.labId,
      state: label.state,
      at: row.at,
      terminal: terminal,
      evidenceState: view.evidence_state,
      decision: firstDecision(runtime) || row.decision || "",
      llmCallCount: runtime.llm_call_count === undefined || runtime.llm_call_count === null
        ? row.llmCallCount
        : runtime.llm_call_count,
      recordSource: "launcher-record"
    };
    return next;
  }

  function captureLaunch(data, mode, labId) {
    if (!data || !data.runId && !data.run_id) {
      return;
    }
    var runtime = data.runtime || {};
    var label = learnerRunState(data);
    recordLaunch({
      mode: mode || "",
      runId: data.run_id || data.runId || "",
      labId: labId || "",
      state: label.state,
      terminal: runtime.terminal || data.terminal || "",
      evidenceState: data.evidence_state || "",
      decision: firstDecision(runtime) || "",
      llmCallCount: runtime.llm_call_count
    });
    var list = document.getElementById("session-history");
    if (list) {
      renderSession(list);
    }
    paintSessionPair(labId || (list && list.getAttribute("data-lab-id")) || "");
  }

  function paintSessionPair(labId) {
    var pairEl = document.getElementById("session-pair");
    if (!pairEl) {
      return;
    }
    var pair = pairSessionRuns(readSession().runs, labId);
    if (!pair) {
      pairEl.textContent = "No ATTACK and RETEST pair for this lab in this tab. LAST KNOWN CLIENT STATE. Not indexed evidence.";
      return;
    }
    pairEl.textContent = "Paired from this tab for " + labId + ": ATTACK " + pair.attack.runId + " · RETEST " + pair.retest.runId + ". LAST KNOWN CLIENT STATE. Not indexed evidence. Splunk remains the evidence authority.";
  }

  function refreshLauncherRecords(listEl) {
    var session = readSession();
    if (!session.runs.length || typeof fetch !== "function") {
      renderSession(listEl);
      return Promise.resolve(session.runs);
    }
    var jobs = session.runs.map(function (row) {
      if (!row.runId) {
        return Promise.resolve(row);
      }
      return fetch("/api/launches/" + encodeURIComponent(row.runId)).then(function (response) {
        if (!response.ok) {
          return row;
        }
        return response.json().then(function (body) {
          return applyLauncherRecord(row, body);
        });
      }).catch(function () {
        return row;
      });
    });
    return Promise.all(jobs).then(function (runs) {
      session.runs = runs;
      writeSession(session);
      renderSession(listEl);
      return runs;
    });
  }

  window.AgentSecUI = {
    statusFromResult: statusFromResult,
    applyState: applyState,
    setBusy: setBusy,
    fillRunId: fillRunId,
    copyFromInput: copyFromInput,
    hops: hops,
    firstDecision: firstDecision,
    anyTrue: anyTrue,
    learnerHref: learnerHref,
    rewriteLearnerLinks: rewriteLearnerLinks,
    learnerRunState: learnerRunState,
    evidencePresentation: evidencePresentation,
    afterPaint: afterPaint,
    savePrediction: savePrediction,
    predictionFor: predictionFor,
    recordLaunch: recordLaunch,
    renderSession: renderSession,
    historyText: historyText,
    pairSessionRuns: pairSessionRuns,
    applyLauncherRecord: applyLauncherRecord,
    readSessionRuns: function () { return readSession().runs; },
    refreshLauncherRecords: refreshLauncherRecords,
    captureLaunch: captureLaunch,
    paintSessionPair: paintSessionPair
  };

  if (typeof document !== "undefined" && document.addEventListener) {
  document.addEventListener("DOMContentLoaded", function () {
    var list = document.getElementById("session-history");
    if (!list || list.getAttribute("data-agentsec-managed") !== "1") {
      return;
    }
    var labId = list.getAttribute("data-lab-id") || "";
    refreshLauncherRecords(list).then(function () {
      paintSessionPair(labId);
    });
  });
  }
})(window);
