"""The public export keeps linked docs, drops the rest, and never leaves a link to a file it dropped."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("bpe", Path(__file__).resolve().parents[1] / "scripts/build_public_export.py")
bpe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bpe)

CFG = {"included_dirs": [], "roots": ["README.md"], "excluded_dirs": ["docs/reviews"], "excluded_tests": [], "excluded_files": []}
DOCS = {
    "README.md": "[a](docs/A.md) ![i](docs/images/x.png) [r](docs/reviews/R.md) [web](https://x.org) [up](docs/B.md#s)",
    "docs/A.md": "[back](../README.md) [r](reviews/R.md)",
    "docs/B.md": "text",
    "docs/Z.md": "orphan",
    "docs/images/x.png": "",
    "docs/reviews/R.md": "internal",
}


def test_select_and_rewrite():
    files = list(DOCS)
    keep, drop = bpe.select(files, CFG, DOCS.__getitem__)
    assert set(keep) == {"README.md", "docs/A.md", "docs/B.md", "docs/images/x.png"}
    assert {f for f, _ in drop} == {"docs/Z.md", "docs/reviews/R.md"}
    out = bpe.rewrite("README.md", DOCS["README.md"], set(keep), "(private)")
    assert "(docs/reviews/R.md)" not in out and "r (private)" in out
    assert "[web](https://x.org)" in out and "![i](docs/images/x.png)" in out and "[up](docs/B.md#s)" in out
    assert bpe.rewrite("docs/A.md", DOCS["docs/A.md"], set(keep), "")  == "[back](../README.md) r"


def test_resolve():
    assert bpe.resolve("docs/A.md", "../README.md") == "README.md"
    assert bpe.resolve("docs/A.md", "https://x") is None and bpe.resolve("docs/A.md", "#frag") is None
