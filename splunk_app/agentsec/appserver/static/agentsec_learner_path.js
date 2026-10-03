/* Learner navigation state for this browser. Not indexed evidence. */
(function (window) {
  "use strict";
  var KEY = "agentsec.learner.progress.v1";
  var STATES = ["NOT STARTED", "IN PROGRESS", "INVESTIGATED"];
  var CATALOG = [
  {
    "id": "ws_lab_pi_001",
    "title": "Direct Prompt Injection",
    "level": "L1",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_pi_001"
  },
  {
    "id": "ws_lab_mcp_001",
    "title": "Tool Authorization",
    "level": "L1",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_mcp_001"
  },
  {
    "id": "ws_lab_mcp_003",
    "title": "Scope Escalation",
    "level": "L1",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_mcp_003"
  },
  {
    "id": "ws_lab_mcp_004",
    "title": "Parameter / Resource Authorization",
    "level": "L1",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_mcp_004"
  },
  {
    "id": "ws_lab_rag_context",
    "title": "RAG / Retrieved Context",
    "level": "L2",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_rag_context"
  },
  {
    "id": "ws_lab_memory_security",
    "title": "Persistent Memory",
    "level": "L2",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_memory_security"
  },
  {
    "id": "ws_lab_mcp_005",
    "title": "Tool Result Trust",
    "level": "L2",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_mcp_005"
  },
  {
    "id": "ws_lab_mcp_catalog",
    "title": "Tool Catalog",
    "level": "L2",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_mcp_catalog"
  },
  {
    "id": "ws_lab_scanner_runtime_evidence",
    "title": "Scanner + Runtime Evidence",
    "level": "L2",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_scanner_runtime_evidence"
  },
  {
    "id": "ws_lab_external_evaluation_garak",
    "title": "External Security Toolbox",
    "level": "L2",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_external_evaluation_garak"
  },
  {
    "id": "ws_lab_agent_goal_integrity",
    "title": "Goal / Instruction Integrity",
    "level": "L3",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_agent_goal_integrity"
  },
  {
    "id": "ws_lab_agent_delegation",
    "title": "Agent Identity / Delegation",
    "level": "L3",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_agent_delegation"
  },
  {
    "id": "ws_lab_mcp_006",
    "title": "Confused Deputy",
    "level": "L3",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_mcp_006"
  },
  {
    "id": "ws_lab_agentsec_capstone",
    "title": "Lending Assistant Investigation",
    "level": "L5",
    "mode": "LIVE",
    "href": "/en-US/app/agentsec/ws_lab_agentsec_capstone"
  },
  {
    "id": "ws_lab_splunk_defender_bridge",
    "title": "Splunk Defender Bridge",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_splunk_defender_bridge"
  },
  {
    "id": "ws_lab_blue_team_incident",
    "title": "AcmeBank Incident AI-2026-001",
    "level": "L6",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_blue_team_incident"
  },
  {
    "id": "ws_lab_detection_engineering",
    "title": "Detection Engineering \u2014 Prove Your Coverage",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_detection_engineering"
  },
  {
    "id": "ws_lab_threat_modeling",
    "title": "AcmeBank Agentic Customer Operations Platform",
    "level": "L7",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_threat_modeling"
  },
  {
    "id": "ws_lab_agent_identity_nhi",
    "title": "Agent Identity and Non-Human IAM",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_agent_identity_nhi"
  },
  {
    "id": "ws_lab_a2a_auth_delegation",
    "title": "A2A Authentication and Delegation",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_a2a_auth_delegation"
  },
  {
    "id": "ws_lab_hitl_approval",
    "title": "Human Approval and Action Binding",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_hitl_approval"
  },
  {
    "id": "ws_lab_credential_lifetime",
    "title": "Short-Lived Credential Lifetime",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_credential_lifetime"
  },
  {
    "id": "ws_lab_privacy_data_governance",
    "title": "AcmeBank Incident PRIV-2026-001",
    "level": "L8",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_privacy_data_governance"
  },
  {
    "id": "ws_lab_purpose_authorization",
    "title": "RAG Purpose Authorization",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_purpose_authorization"
  },
  {
    "id": "ws_lab_recall_isolation",
    "title": "Memory Ownership and Isolation",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_recall_isolation"
  },
  {
    "id": "ws_lab_asset_inventory",
    "title": "AI Asset Inventory",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_asset_inventory"
  },
  {
    "id": "ws_lab_component_provenance",
    "title": "Component Provenance",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_component_provenance"
  },
  {
    "id": "ws_lab_code_agent_bounds",
    "title": "Code Agent Bounds",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_code_agent_bounds"
  },
  {
    "id": "ws_lab_change_bounds",
    "title": "Change Bounds",
    "level": "checkpoint",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_change_bounds"
  },
  {
    "id": "ws_lab_multi_stage_incident",
    "title": "Acme Bank Incident AGENT-2026-009",
    "level": "L9",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_multi_stage_incident"
  },
  {
    "id": "ws_lab_advanced_capstone",
    "title": "Acme Bank Capstone MASTER-2026-001",
    "level": "L10",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_lab_advanced_capstone"
  },
  {
    "id": "ws_agentsec_mastery",
    "title": "Mastery Check",
    "level": "L10",
    "mode": "REPLAY",
    "href": "/en-US/app/agentsec/ws_agentsec_mastery"
  }
];

  function read() {
    try {
      var raw = window.localStorage.getItem(KEY);
      var parsed = raw ? JSON.parse(raw) : {};
      var workshops = parsed && parsed.workshops ? parsed.workshops : {};
      return {workshops: workshops};
    } catch (err) {
      return {workshops: {}};
    }
  }

  function write(data) {
    window.localStorage.setItem(KEY, JSON.stringify({workshops: data.workshops || {}}));
  }

  function stateFor(id) {
    var value = read().workshops[id];
    return STATES.indexOf(value) === -1 ? "NOT STARTED" : value;
  }

  function setState(id, state) {
    if (STATES.indexOf(state) === -1) {
      throw new Error("progress state is not a security result");
    }
    var data = read();
    data.workshops[id] = state;
    write(data);
    return state;
  }

  function reset() {
    window.localStorage.removeItem(KEY);
  }

  function summary() {
    var counts = {"NOT STARTED": 0, "IN PROGRESS": 0, "INVESTIGATED": 0};
    CATALOG.forEach(function (row) {
      counts[stateFor(row.id)] += 1;
    });
    return counts;
  }

  function nextWorkshop() {
    var inProgress = null;
    var notStarted = null;
    CATALOG.forEach(function (row) {
      var state = stateFor(row.id);
      if (!inProgress && state === "IN PROGRESS") {
        inProgress = row;
      }
      if (!notStarted && state === "NOT STARTED") {
        notStarted = row;
      }
    });
    return inProgress || notStarted || CATALOG[CATALOG.length - 1];
  }

  function render(root) {
    root.replaceChildren();
    var hero = document.createElement("header");
    hero.className = "agentsec-path-hero";
    var title = document.createElement("h2");
    title.className = "agentsec-path-title";
    title.textContent = "Your path";
    hero.appendChild(title);
    var intro = document.createElement("p");
    intro.className = "agentsec-path-intro";
    intro.textContent = "LAST KNOWN CLIENT STATE for learning navigation. Not indexed evidence. Not a control decision. INVESTIGATED means you marked the workshop, not that the system is safe.";
    hero.appendChild(intro);
    root.appendChild(hero);
    var counts = summary();
    var next = nextWorkshop();
    var tally = document.createElement("section");
    tally.id = "agentsec-progress-tally";
    tally.className = "agentsec-path-summary";
    tally.setAttribute("aria-label", "Learning progress summary");
    var tallyLead = document.createElement("p");
    tallyLead.className = "agentsec-path-summary-lead";
    tallyLead.textContent = "INVESTIGATED " + counts["INVESTIGATED"] + " of " + CATALOG.length + " · next: " + next.title;
    tally.appendChild(tallyLead);
    [["INVESTIGATED", counts["INVESTIGATED"]], ["IN PROGRESS", counts["IN PROGRESS"]], ["NOT STARTED", counts["NOT STARTED"]]].forEach(function (pair) {
      var chip = document.createElement("p");
      chip.className = "agentsec-path-chip agentsec-path-chip-" + pair[0].toLowerCase().replace(" ", "-");
      chip.textContent = pair[0] + " " + pair[1];
      tally.appendChild(chip);
    });
    root.appendChild(tally);
    CATALOG.forEach(function (row) {
      var state = stateFor(row.id);
      var item = document.createElement("section");
      item.className = "agentsec-path-card agentsec-path-card-" + state.toLowerCase().replace(" ", "-");
      var heading = document.createElement("h3");
      heading.className = "agentsec-path-card-title";
      var link = document.createElement("a");
      link.className = "agentsec-path-card-link";
      link.href = row.href;
      link.textContent = row.level + " · " + row.title + " · " + row.mode;
      heading.appendChild(link);
      item.appendChild(heading);
      var status = document.createElement("p");
      status.id = "status-" + row.id;
      status.className = "agentsec-path-status";
      status.textContent = state;
      item.appendChild(status);
      ["IN PROGRESS", "INVESTIGATED"].forEach(function (nextState) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "agentsec-path-btn" + (nextState === "INVESTIGATED" ? " agentsec-path-btn-investigated" : "");
        button.textContent = nextState === "IN PROGRESS" ? "Mark in progress" : "Mark investigated";
        button.addEventListener("click", function () {
          setState(row.id, nextState);
          render(root);
        });
        item.appendChild(button);
      });
      root.appendChild(item);
    });
    var resetButton = document.createElement("button");
    resetButton.type = "button";
    resetButton.id = "agentsec-progress-reset";
    resetButton.className = "agentsec-path-btn agentsec-path-reset";
    resetButton.textContent = "Reset learning progress";
    resetButton.addEventListener("click", function () {
      reset();
      render(root);
    });
    root.appendChild(resetButton);
    var note = document.createElement("p");
    note.className = "agentsec-path-note";
    note.textContent = "Reset clears this browser list only. It does not delete Splunk data, Attack Service records, or security decisions.";
    root.appendChild(note);
  }

  function mount() {
    if (typeof document === "undefined" || !document.getElementById) {
      return false;
    }
    var root = document.getElementById("agentsec-progress");
    if (!root || root.getAttribute("data-agentsec-mounted") === "1") {
      return false;
    }
    if (document.head && !document.getElementById("agentsec-progress-style")) {
      var style = document.createElement("style");
      style.id = "agentsec-progress-style";
      style.textContent = [
        "#agentsec-progress{font-family:system-ui,'Segoe UI',sans-serif;color:#17202A;background:#F6F8FB;padding:1rem 1.25rem 1.5rem;max-width:52rem}",
        ".agentsec-path-hero{margin:0 0 1rem}",
        ".agentsec-path-title{margin:0 0 .4rem;color:#0B1F33;font-size:1.6rem;line-height:1.25}",
        ".agentsec-path-intro,.agentsec-path-note{margin:.35rem 0 0;color:#3D4654;max-width:46rem}",
        ".agentsec-path-summary{display:flex;flex-wrap:wrap;gap:.6rem;align-items:stretch;margin:0 0 1.1rem;padding:1rem;background:#fff;border:1px solid #D9E0E7;border-radius:6px}",
        ".agentsec-path-summary-lead{flex:1 1 16rem;margin:0;font-weight:650;color:#0B1F33}",
        ".agentsec-path-chip{margin:0;min-height:2.5rem;padding:.55rem .75rem;border-radius:6px;border:1px solid #D9E0E7;background:#F6F8FB;font-weight:650}",
        ".agentsec-path-chip-investigated{background:#E8F3E9;color:#2E7D32;border-color:#C8E0C9}",
        ".agentsec-path-chip-in-progress{background:#F6EBD8;color:#B7791F;border-color:#E6D2A8}",
        ".agentsec-path-chip-not-started{background:#F0F3F6;color:#3D4654}",
        ".agentsec-path-card{background:#fff;border:1px solid #D9E0E7;border-radius:6px;padding:1rem 1.1rem;margin:0 0 .75rem}",
        ".agentsec-path-card-not-started{border-left:4px solid #8AA0B4}",
        ".agentsec-path-card-in-progress{border-left:4px solid #B7791F}",
        ".agentsec-path-card-investigated{border-left:4px solid #2E7D32}",
        ".agentsec-path-card-title{margin:0 0 .35rem;font-size:1.05rem}",
        ".agentsec-path-card-link{color:#007F86;text-decoration:none}",
        ".agentsec-path-card-link:hover{text-decoration:underline}",
        ".agentsec-path-status{margin:.15rem 0 .7rem;font-weight:700;letter-spacing:.02em}",
        ".agentsec-path-card-not-started .agentsec-path-status{color:#3D4654}",
        ".agentsec-path-card-in-progress .agentsec-path-status{color:#B7791F}",
        ".agentsec-path-card-investigated .agentsec-path-status{color:#2E7D32}",
        ".agentsec-path-btn{min-height:2.75rem;margin:.2rem .5rem .2rem 0;padding:.55rem .9rem;border:1px solid #0B1F33;border-radius:6px;background:#fff;color:#0B1F33;font:inherit;font-weight:650;cursor:pointer}",
        ".agentsec-path-btn:hover{background:#E8EEF5}",
        ".agentsec-path-btn:active{background:#D9E0E7}",
        ".agentsec-path-btn-investigated{background:#0B1F33;color:#fff}",
        ".agentsec-path-btn-investigated:hover{background:#007F86;border-color:#007F86}",
        ".agentsec-path-reset{display:block;margin:1rem 0 .4rem;background:#fff}",
        "#agentsec-progress button:focus,#agentsec-progress a:focus{outline:3px solid #007F86;outline-offset:2px}"
      ].join("");
      document.head.appendChild(style);
    }
    render(root);
    root.setAttribute("data-agentsec-mounted", "1");
    return true;
  }

  // Splunk Classic Dashboard can evaluate script="..." before the HTML panel
  // exists. readyState is already past "loading", so DOMContentLoaded is not
  // enough. splunkjs/mvc/simplexml/ready! is the supported dashboard-ready
  // hook. If #agentsec-progress is still absent, a MutationObserver and a
  // 50-attempt, 100ms timer wait for it, then stop. Both stop on success.
  var waiter = null;
  var MAX_WAIT_ATTEMPTS = 50;
  var WAIT_MS = 100;

  function stopWaiter() {
    if (!waiter) {
      return;
    }
    if (waiter.observer) {
      waiter.observer.disconnect();
    }
    if (waiter.timer && typeof clearTimeout === "function") {
      clearTimeout(waiter.timer);
    }
    waiter = null;
  }

  function ensureMounted() {
    var root = typeof document !== "undefined" && document.getElementById
      ? document.getElementById("agentsec-progress")
      : null;
    if (root && root.getAttribute("data-agentsec-mounted") === "1") {
      stopWaiter();
      return true;
    }
    if (mount()) {
      stopWaiter();
      return true;
    }
    return false;
  }

  function armWaiter() {
    if (ensureMounted() || waiter) {
      return;
    }
    waiter = {attempts: 0, observer: null, timer: null};
    if (typeof MutationObserver === "function" && document.documentElement) {
      waiter.observer = new MutationObserver(function () {
        ensureMounted();
      });
      waiter.observer.observe(document.documentElement, {childList: true, subtree: true});
    }
    if (typeof setTimeout !== "function") {
      return;
    }
    function tick() {
      if (!waiter) {
        return;
      }
      waiter.attempts += 1;
      if (ensureMounted() || waiter.attempts >= MAX_WAIT_ATTEMPTS) {
        stopWaiter();
        return;
      }
      waiter.timer = setTimeout(tick, WAIT_MS);
    }
    waiter.timer = setTimeout(tick, WAIT_MS);
  }

  function begin() {
    if (typeof require === "function") {
      try {
        require(["splunkjs/mvc/simplexml/ready!"], function () {
          armWaiter();
        });
      } catch (err) {
        armWaiter();
      }
    }
    armWaiter();
  }

  function start() {
    if (typeof document === "undefined" || !document.addEventListener) {
      return;
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", begin);
      return;
    }
    begin();
  }

  window.AgentSecProgress = {
    KEY: KEY,
    STATES: STATES,
    CATALOG: CATALOG,
    read: read,
    setState: setState,
    reset: reset,
    summary: summary,
    stateFor: stateFor,
    mount: mount
  };

  start();
})(window);
