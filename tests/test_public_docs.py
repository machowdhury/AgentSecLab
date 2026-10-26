"""Public docs: relative links resolve, referenced scripts and flags exist."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").glob("*.md"))]
NEW = ["README.md", "CONTRIBUTING.md", "docs/README.md", "docs/GETTING_STARTED.md", "docs/LEARNER_GUIDE.md",
       "docs/INSTRUCTOR_GUIDE.md", "docs/ARCHITECTURE_GUIDE.md", "docs/EVALUATION_AND_RISK_GUIDE.md",
       "docs/GOVERNANCE_GUIDE.md", "docs/PROJECT_REFERENCE.md"]


def test_new_docs_links_resolve():
    for rel in NEW:
        f = ROOT / rel
        for t in re.findall(r"\]\(([^)]+)\)", f.read_text(encoding="utf-8")):
            if t.startswith(("http", "#", "mailto:")):
                continue
            assert (f.parent / t.split("#")[0]).resolve().exists(), (rel, t)


def test_documented_scripts_and_flags_exist():
    text = (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")
    for s in set(re.findall(r"\./scripts/([\w.-]+\.sh)", text)):
        assert (ROOT / "scripts" / s).exists(), s
    up = (ROOT / "scripts/lab-up.sh").read_text(encoding="utf-8")
    for flag in ("--build", "--no-wait", "--remote"):
        assert flag in up, flag
    down = (ROOT / "scripts/lab-down.sh").read_text(encoding="utf-8")
    for flag in ("--remove-containers", "--purge", "--yes-delete-all-lab-data"):
        assert flag in down, flag
    assert (ROOT / "scripts/build_academy_ui.sh").exists()


def test_documented_routes_exist():
    router = (ROOT / "academy-ui/src/router.tsx").read_text(encoding="utf-8")
    for r in ("governance", "risk", "evals"):
        assert f'"{r}"' in router
