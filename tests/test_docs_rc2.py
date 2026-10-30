"""Documentation checks for the RC2 guides: every relative link and anchor resolves, the images exist, the workshop catalog covers the Academy registry exactly,
and the installer keys, commands and environment names the guides print are the real ones. Reads files only; no Docker, no network."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.installer.config import InstallConfig

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "README.md"] + [ROOT / "docs" / n for n in (
    "INSTALLATION_AND_DEPLOYMENT.md", "LEARNER_GUIDE.md", "WORKSHOP_CATALOG.md", "BENEFITS_AND_SECURITY_ARCHITECTURE.md", "VISUAL_GUIDE.md", "README.md",
    "INSTALLER.md", "GATEWAY.md", "QUICKSTART.md", "GETTING_STARTED.md", "REMOTE_ACCESS.md", "LOCAL_DOCKER_LAB.md", "DEPLOYMENT_READINESS.md",
    "SPLUNK_INTEGRATION.md", "LOAN_DESK_MISSION.md", "AI_SECURITY_ASSURANCE.md")]
NEW = [p for p in DOCS if p.name in ("README.md", "INSTALLATION_AND_DEPLOYMENT.md", "LEARNER_GUIDE.md", "WORKSHOP_CATALOG.md", "BENEFITS_AND_SECURITY_ARCHITECTURE.md", "VISUAL_GUIDE.md")]


def slug(heading: str) -> str:
    """GitHub's anchor rule: lower case, drop everything but letters, digits, spaces, hyphens and underscores, spaces become hyphens."""
    h = re.sub(r"[`*_]{1}", lambda m: "_" if m.group(0) == "_" else "", heading.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    out = {slug(m.group(2)) for m in re.finditer(r"^(#{1,6})\s+(.*?)\s*$", text, re.M)}
    out |= set(re.findall(r'<a id="([^"]+)"', text))
    return out


def links(path: Path):
    text = re.sub(r"```.*?```", "", path.read_text(encoding="utf-8"), flags=re.S)          # code blocks hold commands, not links
    text = re.sub(r"`[^`\n]*`", "", text)
    for m in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)\)", text):
        yield m.group(1)




def test_screenshots_exist_and_are_all_used():
    used = set()
    for doc in NEW:
        used |= {Path(t).name for t in links(doc) if t.endswith(".png")}
    on_disk = {p.name for p in (ROOT / "docs" / "images").glob("*.png")}
    assert used and used <= on_disk, used - on_disk
    assert on_disk <= used, f"unused screenshots: {on_disk - used}"


def test_the_catalog_covers_the_registry_exactly_with_the_documented_counts():
    from agentsec.lab_registry import load_registry
    reg = [e["lab_id"] for e in load_registry()["entries"]]
    guides = json.loads((ROOT / "learning/academy/workshop_guides.json").read_text())["guides"]
    text = (ROOT / "docs/WORKSHOP_CATALOG.md").read_text(encoding="utf-8")
    heads = re.findall(r"^\*\*`(LAB-[A-Z0-9-]+)`\*\* · level (L\d+) · \*\*(LIVE|RECORDED|SIMULATED)", text, re.M)
    assert sorted(h[0] for h in heads) == sorted(reg) and len(reg) == 32, "every registered workshop, once"
    assert "## Orientation" in text and "**33**" in text                               # 32 labs plus the Orientation page
    kinds = {"live": "LIVE", "recorded": "RECORDED", "simulated packet": "SIMULATED"}
    assert all(kinds[guides[i]["kind"]] == k for i, _, k in heads), "mode must match the workshop guide"
    count = lambda k: sum(1 for _, _, m in heads if m == k)
    assert (count("LIVE"), count("RECORDED"), count("SIMULATED")) == (13, 8, 11)
    for lab, *_ in heads:
        assert f'<a id="{lab.lower()}"></a>' in text and f"(#{lab.lower()})" in text   # contents row and entry both exist
        assert (ROOT / "learning/level_1" / lab).is_dir()


def test_the_readme_and_guides_state_the_same_workshop_numbers():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "33 workshops" in readme and "Thirteen of them run live" in readme and "20 of 33 run no agent" in readme
    assert "13 of the 33" in (ROOT / "docs/LEARNER_GUIDE.md").read_text(encoding="utf-8")


def _set_flags(text: str):
    for m in re.finditer(r"--set\s+([a-z_.]+)=([^\s`)\\]+)", text):
        if m.group(1) != "key":                              # "--set key=value" is the placeholder in the syntax description
            yield m.group(1), m.group(2)


@pytest.mark.parametrize("doc", NEW + [ROOT / "docs/INSTALLER.md"], ids=lambda p: p.name)
def test_every_documented_set_key_is_a_real_installer_setting(doc):
    for key, value in _set_flags(doc.read_text(encoding="utf-8")):
        node: dict = {}
        cur = node
        parts = key.split(".")
        for p in parts[:-1]:
            cur[p] = {}; cur = cur[p]
        cur[parts[-1]] = {"true": True, "false": False}.get(value, int(value) if value.isdigit() else value.strip("\\"))
        InstallConfig.from_dict(node)                       # raises ConfigError for an unknown key or a wrong type


def test_documented_commands_exist_and_the_example_configuration_parses():
    from agentsec.installer import cli
    src = Path(cli.__file__).read_text(encoding="utf-8")
    choices = re.search(r'choices=\[([^\]]*)\]', src).group(1)
    allowed = set(re.findall(r'"([a-z-]+)"', choices))
    used = set()
    for doc in NEW:
        used |= set(re.findall(r"\./agentsec\b[^\n]*?\b(install|preflight|plan|status|up|down|logs|rollback|print-config|validate)\b", doc.read_text(encoding="utf-8")))
    assert used and used <= allowed, used - allowed
    block = re.search(r"Example file \(TESTED with `print-config`\):\n```json\n(.*?)```", (ROOT / "docs/INSTALLER.md").read_text(encoding="utf-8"), re.S).group(1)
    assert InstallConfig.from_dict(json.loads(block)).gateway.ctf is True


def test_the_documented_environment_variables_are_the_ones_the_installer_writes():
    import sys
    sys.path.insert(0, str(ROOT))
    from agentsec.installer import render
    from agentsec.installer.config import Locks
    written = set()
    for d in ({"gateway": {"ctf": True}, "splunk": {"mode": "bundled", "rest_url": "https://splunk:8089", "token_file": "/x/t", "ca_file": "/x/c"}}, {"ollama": {"mode": "host"}}):
        cfg = InstallConfig.from_dict(d)
        written |= set(render.parse_env(render.build_plan(cfg, Locks.load(), {"platform": "Linux/x86_64", "volume_prefixes": []}, None).files[".env"]))
    section = re.search(r"### Generated environment variables.*?\n(.*?)\n## Upgrade, backup", (ROOT / "docs/INSTALLER.md").read_text(encoding="utf-8"), re.S).group(1)
    documented = set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", section))
    assert documented and documented <= written, documented - written


def test_the_measured_figures_are_stated_as_measurements_not_requirements():
    t = (ROOT / "docs/INSTALLER.md").read_text(encoding="utf-8")
    for fig in ("about 25 GiB", "about 6 GiB", "9 to 10 minutes"):
        assert fig in t
    assert "**No minimum is claimed.**" in t and "They are **not** minimum requirements" in t
    for forbidden in ("minimum requirement of", "guaranteed", "at least 16 GiB"):
        assert forbidden not in t


def test_no_new_guide_overclaims_what_was_not_tested():
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in NEW)
    for must in ("does **not** run CSA's MAESTRO Threat Analyzer", "does not implement MAESTRO v2", "VERIFICATION UNAVAILABLE", "NOT TESTED", "simulated"):
        assert must in corpus or must.lower() in corpus.lower(), must
    for bad in ("MAESTRO v2 is implemented", "all 33 workshops are live", "VERIFIED by default"):
        assert bad.lower() not in corpus.lower(), bad
    assert not re.search(r"(?<!not )everything is behind one", corpus, re.I)


def test_the_install_commands_in_the_guide_and_readme_use_real_settings_and_both_paths_are_present():
    from agentsec.installer.config import Locks, validate
    guide = (ROOT / "docs/INSTALLATION_AND_DEPLOYMENT.md").read_text(encoding="utf-8")
    for heading in ("## LOCAL: install on your own Ubuntu computer", "## REMOTE: Ubuntu server or cloud VM, open it directly from your laptop"):
        assert heading in guide
    assert "ssh -N -L" not in guide                                       # no tunnel is needed for normal browser access
    modes = set()
    for doc in (ROOT / "README.md", ROOT / "docs/INSTALLATION_AND_DEPLOYMENT.md"):
        text = re.sub(r"\\\n\s*", " ", doc.read_text(encoding="utf-8"))   # join shell line continuations
        for line in re.findall(r"^\./agentsec --non-interactive.*--apply install", text, re.M):
            cfg = InstallConfig.from_dict({})
            for k, v in re.findall(r"--set (\S+)=(\S+)", line):
                section, _, key = k.partition(".")
                target = cfg if not key else getattr(cfg, section)
                setattr(target, key or section, {"true": True}.get(v, int(v) if v.isdigit() else v))
            cfg.ack_external_controls = "--ack-external-controls" in line
            assert not [f for f in validate(cfg, Locks.load()) if f.level == "ERROR"], line
            modes.add((cfg.deployment, cfg.gateway.bind))
    assert modes == {("localhost", "127.0.0.1"), ("organization", "0.0.0.0")}      # LOCAL stays loopback-only; REMOTE publishes only the gateway
