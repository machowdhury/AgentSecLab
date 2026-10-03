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

  function render(root) {
    var data = read();
    root.replaceChildren();
    var intro = document.createElement("p");
    intro.textContent = "LAST KNOWN CLIENT STATE for learning navigation. Not indexed evidence. Not a control decision.";
    root.appendChild(intro);
    var counts = summary();
    var tally = document.createElement("p");
    tally.id = "agentsec-progress-tally";
    tally.textContent = "INVESTIGATED " + counts["INVESTIGATED"] + " · IN PROGRESS " + counts["IN PROGRESS"] + " · NOT STARTED " + counts["NOT STARTED"];
    root.appendChild(tally);
    CATALOG.forEach(function (row) {
      var item = document.createElement("section");
      var heading = document.createElement("h3");
      var link = document.createElement("a");
      link.href = row.href;
      link.textContent = row.level + " · " + row.title + " · " + row.mode;
      heading.appendChild(link);
      item.appendChild(heading);
      var status = document.createElement("p");
      status.id = "status-" + row.id;
      status.textContent = stateFor(row.id);
      item.appendChild(status);
      ["IN PROGRESS", "INVESTIGATED"].forEach(function (state) {
        var button = document.createElement("button");
        button.type = "button";
        button.textContent = state === "IN PROGRESS" ? "Mark in progress" : "Mark investigated";
        button.addEventListener("click", function () {
          setState(row.id, state);
          render(root);
        });
        item.appendChild(button);
      });
      root.appendChild(item);
    });
    var resetButton = document.createElement("button");
    resetButton.type = "button";
    resetButton.id = "agentsec-progress-reset";
    resetButton.textContent = "Reset learning progress";
    resetButton.addEventListener("click", function () {
      reset();
      render(root);
    });
    root.appendChild(resetButton);
    var note = document.createElement("p");
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
      style.textContent = "#agentsec-progress button:focus{outline:3px solid #0B1F33;outline-offset:2px}";
      document.head.appendChild(style);
    }
    render(root);
    root.setAttribute("data-agentsec-mounted", "1");
    return true;
  }

  function start() {
    if (typeof document === "undefined" || !document.addEventListener) {
      return;
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", mount);
      return;
    }
    mount();
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
