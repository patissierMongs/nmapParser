# -*- coding: utf-8 -*-
"""파일 위치/산출물 workflow 회귀 테스트."""

import os
import tempfile
import unittest
from unittest import mock

import nmapParser as np


class FileLocationWorkflowTest(unittest.TestCase):
    def test_workspace_dirs_follow_env_then_data_dir_then_temp(self):
        with tempfile.TemporaryDirectory() as td:
            env_root = os.path.join(td, "env-root")
            data_root = os.path.join(td, "data-root")
            with mock.patch.dict(os.environ, {"NMAPPARSER_OUTPUT_DIR": env_root}):
                self.assertEqual(np.get_workspace_root(data_root), os.path.abspath(env_root))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("NMAPPARSER_OUTPUT_DIR", None)
                self.assertEqual(np.get_workspace_root(data_root), os.path.abspath(data_root))
                self.assertTrue(np.get_workspace_root(None).endswith(os.path.join("nmapParser")))

    def test_workspace_subdirs_are_stable(self):
        root = os.path.abspath("/tmp/example-workspace")
        self.assertEqual(np.get_scans_dir(root), os.path.join(root, "scans"))
        self.assertEqual(np.get_collected_dir(root), os.path.join(root, "collected"))
        self.assertEqual(np.get_collected_latest_dir(root), os.path.join(root, "collected", "latest"))
        self.assertEqual(np.get_reports_dir(root), os.path.join(root, "reports"))

    def test_default_scan_output_folder_lives_under_scans(self):
        with tempfile.TemporaryDirectory() as td:
            out = np.default_scan_output_folder(data_dir=td)
            self.assertTrue(out.startswith(os.path.join(os.path.abspath(td), "scans") + os.sep), out)
            self.assertRegex(os.path.basename(out), r"^\d{8}_\d{6}$")

    def test_collect_csv_candidates_excludes_managed_dirs_and_dedups(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "workspace")
            scans = os.path.join(src, "scans", "a")
            collected_latest = os.path.join(src, "collected", "latest")
            reports = os.path.join(src, "reports")
            old_collected = os.path.join(src, "_collected_20260101_000000")
            dst = os.path.join(src, "collected", "20260514_130000")
            for d in (scans, collected_latest, reports, old_collected, dst):
                os.makedirs(d, exist_ok=True)
            with open(os.path.join(scans, "a.csv"), "w", encoding="utf-8") as f:
                f.write("IP,프로토콜,포트\n10.0.0.1,tcp,80\n")
            with open(os.path.join(scans, "dup.csv"), "w", encoding="utf-8") as f:
                f.write("IP,프로토콜,포트\n10.0.0.1,tcp,80\n")
            for d, name in ((collected_latest, "latest.csv"), (reports, "report_input.csv"), (old_collected, "old.csv"), (dst, "dst.csv")):
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("IP,프로토콜,포트\n10.0.0.2,tcp,443\n")

            paths, skipped = np.collect_csv_candidates(
                src, dst,
                exclude_dirs=[np.get_collected_dir(src), np.get_reports_dir(src)],
            )
            self.assertEqual([p.name for p in paths], ["a.csv"])
            self.assertEqual(skipped, 1)

    def test_refresh_latest_collected_replaces_previous_csvs_only(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "collected", "20260514_130000")
            latest = os.path.join(td, "collected", "latest")
            os.makedirs(src, exist_ok=True)
            os.makedirs(latest, exist_ok=True)
            with open(os.path.join(src, "new.csv"), "w", encoding="utf-8") as f:
                f.write("new")
            with open(os.path.join(src, "ignore.txt"), "w", encoding="utf-8") as f:
                f.write("ignore")
            with open(os.path.join(src, "new.xml"), "w", encoding="utf-8") as f:
                f.write("xml")
            with open(os.path.join(latest, "old.csv"), "w", encoding="utf-8") as f:
                f.write("old")
            with open(os.path.join(latest, "old.xml"), "w", encoding="utf-8") as f:
                f.write("oldxml")

            failures = np.refresh_latest_collected(src, latest)

            self.assertEqual(failures, [])
            self.assertEqual(sorted(os.listdir(latest)), ["new.csv", "new.xml"])
            with open(os.path.join(latest, "new.csv"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "new")
            with open(os.path.join(latest, "new.xml"), encoding="utf-8") as f:
                self.assertEqual(f.read(), "xml")


if __name__ == "__main__":
    unittest.main()
