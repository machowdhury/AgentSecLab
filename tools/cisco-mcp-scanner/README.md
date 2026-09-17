# Isolated Cisco mcp-scanner pin (Phase 9B)

Do **not** install this into the AgentSec runtime virtualenv.

```text
uv venv tools/cisco-mcp-scanner/.venv
uv pip install --python tools/cisco-mcp-scanner/.venv -r tools/cisco-mcp-scanner/requirements.txt
```

Pin: `cisco-ai-mcp-scanner==4.8.4` (see `pin.json`). Canonical scan is static YARA only.
