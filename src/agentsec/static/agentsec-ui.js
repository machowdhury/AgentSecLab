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

  function afterPaint() {
    return new Promise(function (resolve) {
      window.requestAnimationFrame(function () {
        window.requestAnimationFrame(resolve);
      });
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
    afterPaint: afterPaint
  };
})(window);
