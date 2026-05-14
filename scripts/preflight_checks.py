#!/usr/bin/env python3
"""릴리즈 전 최소 점검 스크립트."""

from __future__ import annotations

import subprocess
import sys

PYTHON = sys.executable or "python3"

CHECKS = [
    [PYTHON, "-m", "py_compile",
     "nmapParser.py", "xlsx_io.py", "nse_extract.py", "report_generator.py",
     "scripts/check_readme_cli_sync.py", "scripts/check_readme_options_sync.py",
     "scripts/generate_service_checklist.py", "scripts/migrate_categories_to_13col.py"],
    [PYTHON, "scripts/check_readme_cli_sync.py"],
    [PYTHON, "scripts/check_readme_options_sync.py"],
    [PYTHON, "nmapParser.py", "--check-config", "--options", "options.xlsx", "--categories", "categories.xlsx"],
    [PYTHON, "-m", "unittest", "-q",
     "tests.test_command_building", "tests.test_config_loading", "tests.test_diff_cli",
     "tests.test_csv_collect", "tests.test_file_location_workflow", "tests.test_nse_extract",
     "tests.test_report_generator", "tests.test_report_file_list_policy",
     "tests.test_xlsx_report_workflow_final", "tests.test_xml_collect_workflow"],
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
