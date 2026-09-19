# Official Splunk Agent Skills — AgentSec mapping

Catalog inspected: https://splunkbase.splunk.com/skills (2026-09-15). Names below are catalog names. Do not invent skills.

Consult a skill only when the current task matches. Do not apply the whole catalog to every search.

## Use for AgentSec KO work

| Official skill | AgentSec task |
|----------------|---------------|
| **Splunk Search** | Bounded read-only live search execution (when `splunkctl` / CLI is the execution path). Not a substitute for field-contract or `/spl-validate`. |
| **Search Performance Optimizer** | Optimize an **existing** search from evidence after the security question is fixed. Never change the question to make it cheaper. |
| **Search and Dashboard Troubleshooter** | Diagnose broken Studio data sources, saved searches, tokens, or empty/wrong results from evidence. |
| **Field Extraction and CIM Mapping** | `props.conf` JSON extraction, CIM applicability review. AgentSec `agentsec.*` / `gen_ai.*` fields are often CIM NOT APPLICABLE — document, do not force. |
| **Knowledge Object Governance** | Duplicate searches, naming, app context, permissions, schedule, enabled/disabled, dependencies, stale objects. |
| **Dashboard, Report, and Alert Performance Advisor** | Studio/report/alert latency and scheduling **without** changing SPL semantics. |
| **Report Authoring Specialist** | Report contract/readiness when AgentSec adds a true report (not a hunt pasted into a report). |
| **Alerting and Notable Workflows** | Alerts, notables, risk workflows. AgentSec currently has **no** ES notable. Do not add one to complete a lab. |
| **Data Model and Search Acceleration** | Only if AgentSec later introduces data models or acceleration. Today: none. Assess readiness; do not invent a DM to look enterprise. |
| **Data Source Onboarding Advisor** | New telemetry sources (new sourcetype/index). Existing path is OTLP → collector → HEC → `agentsec_telemetry` / `otel:agentic:json`. |
| **Ingestion Pipeline Design** | Evidence-bound ingest design when changing collector/HEC/index contracts. |
| **HEC Setup and Troubleshooting** | Local HEC health, tokens, index routing. Do not treat `otlp.ok` as Splunk success. |
| **App and Add-on Lifecycle Advisor** | `splunk_app/agentsec` packaging, `app.conf`, named-volume staging vs external install. |

## Sometimes useful, not default KO gates

| Official skill | When |
|----------------|------|
| **Splunk Product Question Navigator** | Current product-behavior questions from public Splunk docs. |
| **Splunk Dashboard Converter** | Only if converting classic Simple XML to Studio **while preserving SPL**. AgentSec workshops are already Studio. |
| **Forwarder and Data Ingest Doctor** | Forwarder/ingest path diagnosis. AgentSec local path is collector+HEC, not a UF fleet. |
| **Index and Storage Management Advisor** | Retention/index design for `agentsec_telemetry`. Rare in this lab. |
| **Custom Visualization Builder** | Only if AgentSec ships a custom viz. Default is Studio tables + markdown. |

## Not applicable to AgentSec lab KO engineering (do not force)

Splunk Cloud Admin Copilot; Deployment Server and Forwarder Fleet Management; Indexer Cluster Health and Troubleshooting; Search Head Cluster Health and Troubleshooting; Splunk Identity and SAML Readiness Advisor; Splunk Setup Page Builder; Upgrade and Security Readiness Router (and sibling upgrade skills); Vulnerability Remediation and Compliance Readiness; Splunk License and Capacity Planning Advisor; Incident Diagnosis Specialist; Splunk Health Monitoring and Diagnostic Collection; Splunk Enterprise Administration Advisor (except a light read-only check of app permissions if packaging changes).

These are production-ops or Cloud skills. AgentSec is a local learning range.
