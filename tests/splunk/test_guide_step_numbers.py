"""The 'step N of M' counter in every guided workshop comes from the curriculum (apply_guided_learning.workshop_rows), not from when the shell was written."""
import importlib.util, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("apply_guided_learning", ROOT / "scripts/apply_guided_learning.py")
agl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agl)


def test_every_guided_view_shows_its_canonical_step_number():
    rows = {r["view"]: r for r in agl.workshop_rows(json.loads(agl.CURRICULUM_PATH.read_text(encoding="utf-8")))}
    seen = 0
    for view, row in rows.items():
        xml = agl.VIEWS / f"{view}.xml"
        if not xml.is_file():
            continue
        m = re.search(r"· step (\d+) of (\d+) ·", xml.read_text(encoding="utf-8"))
        if m:
            seen += 1
            assert (int(m.group(1)), int(m.group(2))) == (row["position"], row["total"]), view
    assert seen >= 25
