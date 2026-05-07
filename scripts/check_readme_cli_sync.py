#!/usr/bin/env python3
"""README와 실제 CLI 옵션 최소 동기화 체크."""

from __future__ import annotations

import subprocess
from pathlib import Path

REQUIRED_FLAGS = [
    "--xml2csv", "--diff", "--base", "--curr", "--out",
    "--asset", "--only-changes", "--open-only", "--categories",
]


def main() -> int:
    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")

    cp = subprocess.run(["python", "nmapParser.py", "--help"], capture_output=True, text=True)
    if cp.returncode != 0:
        print("[FAIL] nmapParser.py --help 실행 실패")
        print(cp.stderr)
        return 1
    help_text = cp.stdout

    missing_in_readme = [f for f in REQUIRED_FLAGS if f not in text]
    missing_in_help = [f for f in REQUIRED_FLAGS if f not in help_text]

    if missing_in_readme or missing_in_help:
        if missing_in_readme:
            print("[FAIL] README 누락 옵션:", ", ".join(missing_in_readme))
        if missing_in_help:
            print("[FAIL] --help 누락 옵션:", ", ".join(missing_in_help))
        return 1

    print("[OK] README/CLI 옵션 동기화 통과")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
