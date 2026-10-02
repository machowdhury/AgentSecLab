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
      if (!page.port || page.port === "8000") {
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
    if (data.evidence_timeout) {
      return {
        state: "RUN TIMED OUT",
        message: "The evidence check timed out. This is not a control DENY and not a security decision."
      };
    }
    var terminal = (data.runtime && data.runtime.terminal) || data.terminal;
    if (terminal === "completed_denied") {
      return {
        state: "RUN DENIED",
        message: "The control denied this run. Authorization is not execution."
      };
    }
    if (terminal === "completed_allowed") {
      if (data.evidence_state === "WAITING_FOR_EVIDENCE") {
        return {
          state: "RUN IN PROGRESS",
          message: "The runtime finished. Searchable evidence is not ready yet. This is not a control DENY."
        };
      }
      return {
        state: "RUN COMPLETED",
        message: "The runtime completed. Copy the run.id and open Search. Completion is not proof the attack succeeded."
      };
    }
    return {
      state: "RUN FAILED",
      message: "The launch did not complete. This is not a control DENY."
    };
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
    var terminal = runtime.terminal || (body && body.terminal) || "";
    var next = {
      mode: row.mode,
      runId: row.runId,
      labId: row.labId,
      state: row.state,
      at: row.at,
      terminal: terminal || row.terminal || "",
      evidenceState: (body && body.evidence_state) || row.evidenceState || "",
      decision: firstDecision(runtime) || row.decision || "",
      llmCallCount: runtime.llm_call_count === undefined || runtime.llm_call_count === null
        ? row.llmCallCount
        : runtime.llm_call_count,
      recordSource: "launcher-record"
    };
    return next;
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
    afterPaint: afterPaint,
    savePrediction: savePrediction,
    predictionFor: predictionFor,
    recordLaunch: recordLaunch,
    renderSession: renderSession,
    historyText: historyText,
    pairSessionRuns: pairSessionRuns,
    readSessionRuns: function () { return readSession().runs; },
    refreshLauncherRecords: refreshLauncherRecords
  };
})(window);
