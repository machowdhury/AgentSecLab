"""Host and container scripts check model presence by EXACT name (review L6): no substring or family match, `latest` assumed for an untagged name."""
import os, stat, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
PRESENT = ROOT / "scripts/model_present.sh"
LIST = "NAME            ID      SIZE    MODIFIED\n{rows}"


def present(want, names, mode="text"):
    if mode == "json":
        stdin = '{"models":[' + ",".join(f'{{"name":"{n}","digest":"d"}}' for n in names) + "]}"
        cmd = ["sh", str(PRESENT), "--json", want]
    else:
        stdin = LIST.format(rows="".join(f"{n}  abc  1.3 GB  2 days ago\n" for n in names))
        cmd = ["sh", str(PRESENT), want]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True).returncode


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("want,names,expect", [
    ("llama3.2:1b", ["llama3.2:1b"], 0),
    ("llama3.2:1b", ["llama3.2:latest"], 1),                  # same family, other tag
    ("llama3.2", ["llama3.2:1b"], 1),                         # untagged means :latest, not "any llama3.2" (the old substring grep said present)
    ("llama3.2", ["llama3.2:latest"], 0),
    ("llama3", ["llama3.2:1b"], 1),                           # prefix
    ("llama3.2:1b", ["xllama3.2:1b"], 1), ("llama3.2:1b", ["llama3.2:1b-instruct-q8_0"], 1),
    ("llama3.2:1b", ["LLAMA3.2:1B"], 1),                      # no case folding
    ("localhost:5000/team/model", ["localhost:5000/team/model:latest"], 0),
    ("llama3.2:1b", [], 1),
])
def test_exact_presence(mode, want, names, expect):
    assert present(want, names, mode) == expect


def test_the_header_line_is_never_a_model_name():
    assert present("NAME", []) == 1


def test_usage_error_without_a_name():
    assert subprocess.run(["sh", str(PRESENT)], input="", capture_output=True, text=True).returncode == 2


def _init_run(tmp_path, model, installed, loandesk=None, fail=()):
    """Runs the real container entrypoint with a fake `ollama` and `curl` on PATH; returns the list of `ollama pull` calls."""
    bindir = tmp_path / "bin"; bindir.mkdir()
    log = tmp_path / "calls.log"
    (bindir / "ollama").write_text(f'#!/bin/sh\ncase "$1" in\n serve) exit 0;;\n list) printf "NAME ID SIZE MODIFIED\\n"; for n in {" ".join(installed) or "x"}; do [ "$n" = x ] && continue; printf "%s abc 1GB now\\n" "$n"; done;;\n pull) echo "pull $2" >> "{log}"; case " {" ".join(fail)} " in *" $2 "*) exit 1;; esac;;\nesac\n')
    (bindir / "curl").write_text("#!/bin/sh\nexit 0\n")
    for f in bindir.iterdir(): f.chmod(f.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "OLLAMA_MODEL": model, "OLLAMA_STARTUP_WAIT_SEC": "5"}
    if loandesk is not None:
        env["LOANDESK_MODEL"] = loandesk
    p = subprocess.run(["bash", str(ROOT / "scripts/ollama_init.sh")], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("model,installed,pulls", [
    ("llama3.2:1b", ["llama3.2:1b"], []),                      # already there: no pull
    ("llama3.2:1b", ["llama3.2:latest"], ["pull llama3.2:1b"]),  # another tag of the family does not satisfy it
    ("llama3.2", ["llama3.2:1b"], ["pull llama3.2"]),          # untagged means :latest; the 1b is not it
    ("llama3.2", ["llama3.2:latest"], []),
    ("llama3", ["llama3.2:1b"], ["pull llama3"]),              # a prefix is not a match
])
def test_container_entrypoint_pulls_unless_the_exact_model_is_listed(tmp_path, model, installed, pulls):
    assert _init_run(tmp_path, model, installed) == pulls


def test_host_scripts_use_the_exact_check_and_no_substring_grep_remains():
    for name in ("lab-ready.sh", "lab-preflight.sh"):
        text = (ROOT / "scripts" / name).read_text()
        assert "scripts/model_present.sh" in text, name
    assert 'grep -q "$MODEL"' not in (ROOT / "scripts/lab-preflight.sh").read_text()
    assert 'grep -q "$MODEL"' not in (ROOT / "scripts/ollama_init.sh").read_text()
    assert 'grep -q "\\"name\\":\\"${MODEL}\\""' not in (ROOT / "scripts/lab-ready.sh").read_text()


@pytest.mark.parametrize("loandesk,installed,fail,pulls", [
    ("llama3.2:latest", [], (), ["pull llama3.2:1b", "pull llama3.2:latest"]),     # the installer's default: both roles are provisioned
    ("llama3.2:latest", ["llama3.2:1b", "llama3.2:latest"], (), []),
    ("llama3.2:latest", ["llama3.2:1b"], (), ["pull llama3.2:latest"]),
    ("llama3.2:1b", [], (), ["pull llama3.2:1b"]),                                  # the same model for both roles is pulled once
    ("", [], (), ["pull llama3.2:1b"]),                                             # the legacy lab never sets it: unchanged
    (None, [], (), ["pull llama3.2:1b"]),
    ("llama3.2:latest", [], ("llama3.2:1b",), ["pull llama3.2:1b", "pull llama3.2:latest"]),   # a failed pull never stops the other
])
def test_container_entrypoint_also_provisions_the_loan_desk_model(tmp_path, loandesk, installed, fail, pulls):
    assert _init_run(tmp_path, "llama3.2:1b", installed, loandesk=loandesk, fail=fail) == pulls
