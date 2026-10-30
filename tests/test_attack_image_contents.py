"""The Attack Service must start from the files the Docker image really contains, not from the whole repository. A real-host run found the service exiting at start-up because the
image did not carry learning/assurance/: every offline test had run from the repo checkout. This test builds the image's /app from the Dockerfile's own COPY lines and starts the app there."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODE = """
import json
from agentsec.attack_app import AcmeBankClient, create_app
app = create_app(AcmeBankClient("http://127.0.0.1:9"))
c = app.test_client()
a = c.get("/api/assurance/overview?tab=recorded")
print(json.dumps({"status": a.status_code, "state": a.get_json().get("state"), "runs": a.get_json().get("provenance", {}).get("runs"),
                  "cfg": c.get("/api/learn/config").status_code, "inv": c.get("/api/assurance/runs/11111111-1111-4111-8111-111111111111/findings").status_code}))
"""


def image_root(tmp: Path) -> Path:
    app = tmp / "app"
    app.mkdir()
    for line in (ROOT / "docker/Dockerfile.attack").read_text().splitlines():
        m = re.match(r"COPY\s+(?!--)(\S+)\s+(\S+)\s*$", line)
        if not m:
            continue
        src, dst = ROOT / m.group(1), app / m.group(2).removeprefix("./").removeprefix("/app/")
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    return app


def test_the_app_starts_and_serves_assurance_from_only_what_the_image_copies(tmp_path):
    app = image_root(tmp_path)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTSEC_")}
    env.update(PYTHONPATH=str(app / "src"), AGENTSEC_SCHEMA_PATH=str(app / "schemas/security_event.schema.json"), AGENTSEC_ARTIFACTS_DIR=str(tmp_path / "artifacts"), AGENTSEC_OTEL_ENABLED="false")
    p = subprocess.run([sys.executable, "-c", CODE], cwd=app, env={**env, "PYTHONPATH": str(app / "src")}, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-1500:]
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out == {"status": 200, "state": "ok", "runs": 53, "cfg": 200, "inv": 200}, out
