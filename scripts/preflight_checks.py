#!/usr/bin/env python3
"""릴리즈 전 최소 점검 스크립트."""

from __future__ import annotations

import subprocess

CHECKS = [
    ["python", "-m", "py_compile", "nmapParser.py", "scripts/check_readme_cli_sync.py", "scripts/generate_service_checklist.py"],
    ["python", "scripts/check_readme_cli_sync.py"],
    ["python", "-m", "unittest", "-q", "tests/test_diff_cli.py"],
]


def main() -> int:
    for cmd in CHECKS:
        print("[RUN]", " ".join(cmd))
        cp = subprocess.run(cmd)
        if cp.returncode != 0:
            print("[FAIL]", " ".join(cmd))
            return cp.returncode
    print("[OK] preflight checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
