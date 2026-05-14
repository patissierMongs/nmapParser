# -*- coding: utf-8 -*-
"""CSV 취합 대상 선정 회귀 테스트."""

import os
import tempfile
import unittest
from pathlib import Path

import nmapParser as np


class CsvCollectTests(unittest.TestCase):
    def test_collect_csv_candidates_skips_previous_collected_dirs_and_dedups(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "_collected_20260513_120000").mkdir()
            (root / "a" / "one.csv").write_text("IP,Port\n1.1.1.1,80\n", encoding="utf-8")
            (root / "b" / "copy.csv").write_text("IP,Port\n1.1.1.1,80\n", encoding="utf-8")
            (root / "b" / "two.csv").write_text("IP,Port\n2.2.2.2,443\n", encoding="utf-8")
            (root / "_collected_20260513_120000" / "old.csv").write_text("old\n", encoding="utf-8")

            dst = root / "_collected_20260513_130000"
            dst.mkdir()
            paths, skipped_dup = np.collect_csv_candidates(str(root), str(dst))

            names = sorted(p.name for p in paths)
            self.assertEqual(names, ["one.csv", "two.csv"])
            self.assertEqual(skipped_dup, 1)
            self.assertTrue(all("_collected_" not in os.fspath(p.parent) for p in paths))


if __name__ == "__main__":
    unittest.main()
