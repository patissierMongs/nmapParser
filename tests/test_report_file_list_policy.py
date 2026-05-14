# -*- coding: utf-8 -*-
"""리포트 증적 파일 목록 위치 정책 테스트."""

import os
import tempfile
import unittest

import report_generator as rg


class ReportFileListPolicyTest(unittest.TestCase):
    def test_file_list_treats_xlsx_reports_as_outputs_not_input_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ("scan.xml", "scan.nmap", "scan.gnmap", "scan.log", "scan.csv", "report_20260514_130000.xlsx", "scan.xlsx"):
                with open(os.path.join(td, name), "wb") as f:
                    f.write(b"x")

            sheet = rg._build_sheet_file_list_final(td)
            filenames = [row[2] for row in sheet["rows"]]

            self.assertIn("scan.xml", filenames)
            self.assertIn("scan.nmap", filenames)
            self.assertIn("scan.gnmap", filenames)
            self.assertIn("scan.log", filenames)
            self.assertIn("scan.csv", filenames)
            self.assertNotIn("report_20260514_130000.xlsx", filenames)
            self.assertNotIn("scan.xlsx", filenames)


if __name__ == "__main__":
    unittest.main()
