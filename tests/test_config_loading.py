# -*- coding: utf-8 -*-
"""Excel 설정 파일 로딩/진단 회귀 테스트."""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts"))

import migrate_categories_to_13col
import nmapParser as np
import xlsx_io


class ConfigLoadingTests(unittest.TestCase):
    def _xlsx(self, rows):
        td = tempfile.mkdtemp()
        path = os.path.join(td, "config.xlsx")
        xlsx_io.write_xlsx(path, rows)
        return path

    def test_options_loader_accepts_common_header_aliases(self):
        path = self._xlsx([
            ["옵션명", "명령어", "사용여부", "선택그룹", "설명"],
            ["DNS 역조회 안 함", "-n", "1", "", "PTR 조회 생략"],
        ])

        rows, errors = np.load_options_xlsx(path)

        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "DNS 역조회 안 함")
        self.assertEqual(rows[0]["option"], "-n")
        self.assertTrue(rows[0]["enabled"])
        self.assertEqual(rows[0]["desc"], "PTR 조회 생략")

    def test_categories_loader_accepts_common_header_aliases(self):
        path = self._xlsx([
            ["서비스", "포트", "category", "risk", "memo"],
            ["customsvc", "12345", "업무", "중", "현장 확인"],
        ])

        catmap, errors = np.load_categories_xlsx(path)

        self.assertEqual(errors, [])
        self.assertIn("customsvc", catmap)
        self.assertEqual(catmap["customsvc"]["port"], "12345")
        self.assertEqual(catmap["customsvc"]["category"], "업무")
        self.assertEqual(catmap["customsvc"]["risk"], "중")
        self.assertEqual(catmap["customsvc"]["memo"], "현장 확인")

    def test_loader_reports_duplicate_alias_headers(self):
        path = self._xlsx([
            ["스캔 옵션", "옵션명", "옵션", "활성화"],
            ["A", "B", "-n", "1"],
        ])

        rows, errors = np.load_options_xlsx(path)

        self.assertEqual(rows, [])
        self.assertTrue(any("같은 의미의 헤더가 중복" in e for e in errors), errors)

    def test_check_config_cli_returns_nonzero_for_invalid_file(self):
        path = self._xlsx([
            ["스캔 옵션", "옵션"],
            ["DNS", "-n"],
        ])

        proc = subprocess.run(
            [sys.executable, "nmapParser.py", "--check-config", "--options", path],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("FAIL", proc.stdout)
        self.assertIn("필수 헤더", proc.stdout)

    def test_options_default_writer_preserves_existing_user_layout(self):
        path = self._xlsx([
            ["담당자", "옵션", "스캔 옵션", "활성화", "빈열"],
            ["홍길동", "-n", "DNS 역조회 안 함", "1", "사용자값"],
        ])

        np.write_default_options_xlsx(path)
        rows = xlsx_io.read_xlsx(path)

        self.assertEqual(rows[0], ["담당자", "옵션", "스캔 옵션", "활성화", "빈열"])
        self.assertEqual(len(rows[1]), len(rows[0]))
        self.assertEqual(rows[1][0], "")
        self.assertEqual(rows[1][1], np.DEFAULT_OPTIONS[0][1])
        self.assertEqual(rows[1][2], np.DEFAULT_OPTIONS[0][0])
        self.assertEqual(rows[1][3], np.DEFAULT_OPTIONS[0][2])
        self.assertEqual(rows[1][4], "")

    def test_categories_default_writer_preserves_existing_user_layout(self):
        path = self._xlsx([
            ["점검자", "표준포트", "nmap서비스명", "분류", "점검메모", "빈열"],
            ["홍길동", "22", "ssh", "원격관리", "확인", "사용자값"],
        ])

        np.write_default_categories_xlsx(path)
        rows = xlsx_io.read_xlsx(path)

        self.assertEqual(rows[0], ["점검자", "표준포트", "nmap서비스명", "분류", "점검메모", "빈열"])
        self.assertEqual(len(rows[1]), len(rows[0]))
        self.assertEqual(rows[1][0], "")
        self.assertEqual(rows[1][1], "22")
        self.assertEqual(rows[1][2], "ssh")
        self.assertEqual(rows[1][3], "원격접속")
        self.assertEqual(rows[1][4], "")
        self.assertEqual(rows[1][5], "")

    def test_categories_migration_preserves_existing_user_layout(self):
        path = self._xlsx([
            ["점검자", "포트", "서비스", "분류", "빈열"],
            ["홍길동", "22", "ssh", "원격관리", "사용자값"],
        ])

        result = migrate_categories_to_13col.migrate_path(path)
        rows = xlsx_io.read_xlsx(path)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(rows[0], ["점검자", "포트", "서비스", "분류", "빈열"])
        self.assertEqual(rows[1], ["홍길동", "22", "ssh", "원격관리", "사용자값"])
        self.assertEqual(len(rows[-1]), len(rows[0]))
        self.assertEqual(rows[-1][0], "")
        self.assertEqual(rows[-1][4], "")



if __name__ == "__main__":
    unittest.main()
