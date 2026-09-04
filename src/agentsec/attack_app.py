"""Attack Service — untrusted HTTP client. It never calls Ollama or skips controls."""

from __future__ import annotations

import logging
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request

from agentsec.attacks import ATK_002
from agentsec.settings import get_settings

logger = logging.getLogger("agentsec.attack")

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class AcmeBankClient:
    def __init__(self, base_url: str, post_fn=None) -> None:
        self.base_url = base_url.rstrip("/")
        self._post_fn = post_fn

    def process(self, payload: dict) -> tuple[int, dict]:
        if self._post_fn is not None:
            return self._post_fn("/api/v1/process", payload)
        try:
            response = requests.post(
                f"{self.base_url}/api/v1/process",
                json=payload,
                timeout=180,
            )
            data = response.json()
            return response.status_code, data
        except requests.RequestException as exc:
            return 503, {"error": f"cannot reach AcmeBank: {exc}"}


def create_app(client: AcmeBankClient | None = None) -> Flask:
    settings = get_settings()
    client = client or AcmeBankClient(settings.acmebank_url)
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.config["SECRET_KEY"] = settings.flask_secret_key
    app.config["AGENTSEC_ATTACK_CLIENT"] = client

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "healthy",
                "service": "attack-service",
                "version": settings.version,
                "acmebank_url": client.base_url,
            }
        )

    @app.get("/")
    def index():
        return render_template(
            "attack.html",
            attack=ATK_002,
            version=settings.version,
        )

    @app.get("/api/attacks")
    def list_attacks():
        return jsonify(
            {
                "attacks": [
                    {
                        "attack_id": ATK_002.attack_id,
                        "name": ATK_002.name,
                        "technique_id": ATK_002.technique_id,
                        "expected_defended": ATK_002.expected_defended,
                    }
                ]
            }
        )

    @app.post("/api/attacks/ATK-002")
    def fire_atk_002():
        body = request.get_json(silent=True) or {}
        # Attackers may try to skip controls; AcmeBank ignores these fields.
        payload = {
            "input": ATK_002.payload,
            "user_id": "attacker-lab",
            "attack_id": ATK_002.attack_id,
            "technique_id": ATK_002.technique_id,
            "skip_control": bool(body.get("skip_control", False)),
            "security_profile": body.get("security_profile"),
            "testbed_mode": body.get("testbed_mode", "LIVE"),
        }
        status, data = client.process(payload)
        return jsonify(data), status

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s %(message)s")
    settings = get_settings()
    app = create_app()
    app.run(host=settings.bind_host, port=settings.attack_port, threaded=True)


if __name__ == "__main__":
    main()
