"""T24 (destructive to the POC only; opt-in): scoped cleanup removes every POC resource and nothing else."""
import json, os
import pytest
from conftest import EVID, POC, check, protected_snapshot, sh

pytestmark = pytest.mark.skipif(os.environ.get("POC_RUN_CLEANUP") != "1", reason="opt-in: set POC_RUN_CLEANUP=1")


def poc_leftovers():
    c = [n for n in sh("docker", "ps", "-a", "--format", "{{.Names}}").stdout.split() if "agentsec-gw-poc" in n]
    i = [n for n in sh("docker", "images", "--format", "{{.Repository}}:{{.Tag}}").stdout.split() if n.startswith("agentsec-gw-poc/")]
    n = [x for x in sh("docker", "network", "ls", "--format", "{{.Name}}").stdout.split() if "agentsec-gw-poc" in x]
    return c, i, n


def test_t24_scoped_cleanup_leaves_the_real_lab_untouched():
    before = json.loads((EVID / ".snap" / "protected_before.json").read_text())
    p = sh("sh", str(POC / "scripts" / "run_poc.sh"), "cleanup", "--yes")
    c, i, n = poc_leftovers()
    after = json.loads(json.dumps(protected_snapshot()))
    same = before == after
    check("T24", p.returncode == 0 and not (c or i or n) and not (POC / ".runtime").exists() and same,
          f"cleanup rc {p.returncode}; POC containers/images/networks left: {len(c)}/{len(i)}/{len(n)}; .runtime removed; protected lab snapshot identical (containers, mounts, networks, 25 volumes)")
