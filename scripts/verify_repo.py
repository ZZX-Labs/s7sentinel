from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE", "CREDITS.md",
    "CODE_OF_CONDUCT.md", "GOVERNANCE.md", "SUPPORT.md", "CHANGELOG.md",
    "ROADMAP.md", "NOTICE.md", "CITATION.cff", "pyproject.toml",
]


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            fail(f"missing required repository file: {rel}")

    init_text = (ROOT / "s7sentinel" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if not m:
        fail("could not parse package version")
    version = m.group(1)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{version}"' not in pyproject:
        fail("pyproject version does not match package version")

    for path in (ROOT / "s7sentinel").glob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for path in (ROOT / "tests").glob("test_*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    print(f"Repository structure OK; version {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
