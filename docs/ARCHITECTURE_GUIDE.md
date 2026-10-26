# Architecture

- **AcmeBank** (port 5000): the target application with deliberately vulnerable profiles.
- **Attack Service** (port 5001): a closed launcher for educational attacks; also serves the Academy at `/learn`. A catch-all `/learn/<path>` route serves the React shell, so new client routes need no backend change.
- **Splunk** (port 8000): receives telemetry through an OpenTelemetry collector and HEC, which stay private to the compose network.
- **Academy UI** (`academy-ui/`): a React app built into `src/agentsec/static/learn` (built assets are tracked).
- **Evidence models**: `scripts/{assurance,eval,risk,governance}_model.py` validate committed evidence; the matching `scripts/export_*.py` produce deterministic JSON consumed by the UI (`--check` verifies nothing drifted). Large evidence is loaded on demand.

Evidence never carries scores or compliance claims; validators reject them. See the [Security boundary](SECURITY_BOUNDARY.md) and the earlier [architecture notes](ARCHITECTURE.md).
