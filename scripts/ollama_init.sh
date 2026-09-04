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

if ollama list | grep -q "$MODEL"; then
    echo "[ollama_init] Model '$MODEL' already present"
else
    echo "[ollama_init] Pulling model '$MODEL'..."
    ollama pull "$MODEL"
fi

echo "[ollama_init] Ready."
wait "$OLLAMA_PID"
