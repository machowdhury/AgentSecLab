#!/bin/bash
# Start Ollama, wait for the API, pull the lab model. No extra "security" models.
set -e

MODEL="${OLLAMA_MODEL:-llama3.2:1b}"
MAX_WAIT="${OLLAMA_STARTUP_WAIT_SEC:-300}"

echo "[ollama_init] Starting Ollama server..."
ollama serve &
OLLAMA_PID=$!

ollama_api_ready() {
    if command -v curl >/dev/null 2>&1; then
        curl -sf "http://127.0.0.1:11434/api/tags" >/dev/null 2>&1
        return $?
    fi
    ollama list >/dev/null 2>&1
}

echo "[ollama_init] Waiting for Ollama API (max ${MAX_WAIT}s)..."
WAITED=0
until ollama_api_ready; do
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[ollama_init] ERROR: Ollama API not ready within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done
echo "[ollama_init] Ollama API ready after ${WAITED}s"

# Each configured model is pulled unless Ollama already lists it under exactly that name (`latest` assumed when no tag is given, the same rule as the
# application): a substring or another tag of the family does not count. OLLAMA_MODEL serves the AcmeBank labs; LOANDESK_MODEL (set by the installer, empty
# otherwise) serves the Loan Desk, which needs its own model because the 1b one does not finish its loop. A failed pull never stops the others.
pull_model() {
    MODEL="$1"
    case "${MODEL##*/}" in *:*) WANT="$MODEL" ;; *) WANT="$MODEL:latest" ;; esac
    if ollama list | awk 'NR > 1 { print $1 }' | grep -Fxq -- "$WANT"; then
        echo "[ollama_init] Model '$MODEL' already present"
    else
        echo "[ollama_init] Pulling model '$MODEL'..."
        if ollama pull "$MODEL"; then
            echo "[ollama_init] Model '$MODEL' pulled."
        else
            echo "[ollama_init] WARNING: could not pull '$MODEL'."
            echo "[ollama_init] The model is required for LIVE generation and is currently absent."
            echo "[ollama_init] Command: docker exec agentsec_ollama ollama pull $MODEL"
            echo "[ollama_init] If the error is certificate or TLS verification, fix trust at the host or image trust layer. Do not disable certificate verification."
            echo "[ollama_init] AcmeBank /health stays degraded until the model is listed. Academy REPLAY does not need the model."
        fi
    fi
}

pull_model "$MODEL"
LOANDESK="${LOANDESK_MODEL:-}"
if [ -n "$LOANDESK" ] && [ "$LOANDESK" != "$MODEL" ]; then
    pull_model "$LOANDESK"
fi

echo "[ollama_init] Ready."
wait "$OLLAMA_PID"
