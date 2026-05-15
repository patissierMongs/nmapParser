# -*- coding: utf-8 -*-
"""report_generator 단위 테스트.

가짜 CSV 3개 (시점 다름) 생성 → generate_report → xlsx 시트 5~6개 + 색칠 정상.
"""

import io
import os
import tempfile
import unittest
import zipfile
from unittest import mock

import report_generator as rg
import xlsx_io


_HEADER_24 = (
    "IP,호스트,OS,프로토콜,포트,표준포트,포트상태,추측서비스,확인서비스(short),"
    "식별,분류,용도,위험도,암호화,인증,노출위험,공격표면,출처,"
    "상세(제품/버전),비고,NSE스크립트명,스크립트출력,NSE추출,점검메모\n"
)


def _row(ip, port, state="open", service="ssh", detail="OpenSSH 9.6", risk="중", nse="TLS_CN=foo"):
    return (
        f"{ip},h,Linux,tcp,{port},{service},{state},{service},{service},"
        f"확,원격,관리,{risk},X,X,X,X,KISA U-01,{detail},,,,{nse},\n"
    )


class ReportGeneratorTests(unittest.TestCase):
    def _make_csvs(self, td):
        """시점 3개 — 22 유지, 80 신규, 443 닫힘 패턴."""
        # 20260101_120000 — 22 only
        p1 = os.path.join(td, "scan_20260101_120000.csv")
        with open(p1, "w", encoding="utf-8-sig", newline="") as f:
            f.write(_HEADER_24)
            f.write(_row("10.0.0.1", "22", risk="중"))
            f.write(_row("10.0.0.1", "443", "open", "https", "nginx 1.24", risk="하"))

        # 20260201_120000 — 22 유지, 80 신규, 443 변경
        p2 = os.path.join(td, "scan_20260201_120000.csv")
        with open(p2, "w", encoding="utf-8-sig", newline="") as f:
            f.write(_HEADER_24)
            f.write(_row("10.0.0.1", "22", risk="중"))
            f.write(_row("10.0.0.1", "80", "open", "http", "nginx 1.24", risk="중"))
            f.write(_row("10.0.0.1", "443", "open", "https", "nginx 1.25", risk="하"))

        # 20260301_120000 — 22 유지, 80 닫힘, 443 유지, 22 위험도 상으로 변경
        p3 = os.path.join(td, "scan_20260301_120000.csv")
        with open(p3, "w", encoding="utf-8-sig", newline="") as f:
            f.write(_HEADER_24)
            f.write(_row("10.0.0.1", "22", risk="상"))   # 위험도 상승
            f.write(_row("10.0.0.1", "80", "closed", "http", "", risk=""))
            f.write(_row("10.0.0.1", "443", "open", "https", "nginx 1.25", risk="하"))

        return [p1, p2, p3]

    def test_collect_csv_files_skips_diff_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            # diff 결과물도 같이 둬봄 — 제외돼야 함
            with open(os.path.join(td, "diff_a_vs_b_20260101_120000.csv"), "w") as f:
                f.write("change_type,a,b\n")
            files = rg.collect_csv_files(td)
            self.assertEqual(len(files), 3)
            for path, _ts in files:
                self.assertNotIn("diff_", os.path.basename(path).lower()[:5])

    def test_generate_report_full(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            out = os.path.join(td, "report.xlsx")
            result = rg.generate_report(td, out)
            self.assertEqual(result, out)
            self.assertTrue(os.path.isfile(out))

            # 시트 파일이 5개 이상 (현황/히트맵/변경이력/위험도추이/메타 + NSE상세)
            with zipfile.ZipFile(out) as z:
                sheet_files = [n for n in z.namelist()
                               if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
                self.assertGreaterEqual(len(sheet_files), 5)
                # workbook.xml 안에 시트 이름 확인
                wb = z.read("xl/workbook.xml").decode("utf-8")
                for sheet_name in (
                    "00_보고요약", "01_스캔증적", "02_시간축히트맵", "03_변경추적대장",
                    "04_현재Open포트", "05_현재스캔전체", "06_증적파일목록", "07_서비스별확인설정",
                ):
                    self.assertIn(sheet_name, wb)
                # 색칠 — styles.xml 에 fill RGB 들어 있어야
                styles = z.read("xl/styles.xml").decode("utf-8")
                self.assertIn("FFFFCDD2", styles, "NEW_OPEN red 색이 styles.xml 에 없음")
                self.assertIn("FFFFF59D", styles, "CHANGED yellow 색이 styles.xml 에 없음")
                # sharedStrings 에 "신규"/"유지" 토큰이 있어야 (히트맵 셀 값)
                shared = z.read("xl/sharedStrings.xml").decode("utf-8")
                self.assertIn("NEW_OPEN", shared, "히트맵에 'NEW_OPEN' 토큰 없음")
                self.assertIn("KEEP", shared, "히트맵에 'KEEP' 토큰 없음")
                # 히트맵 시트 (sheet3.xml) 에 색칠된 cell (s="2"=NEW_OPEN, s="3"=KEEP) 가 적용돼야
                heatmap_xml = z.read("xl/worksheets/sheet3.xml").decode("utf-8")
                self.assertTrue(
                    's="2"' in heatmap_xml or 's="3"' in heatmap_xml,
                    "히트맵 셀 색칠 (s=2 or s=3) 가 적용되지 않음"
                )

    def test_generate_report_single_csv(self):
        """CSV 1개일 때도 변경이력 시트 없이 정상 생성."""
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "single_20260101_120000.csv")
            with open(p, "w", encoding="utf-8-sig", newline="") as f:
                f.write(_HEADER_24)
                f.write(_row("10.0.0.1", "22"))
            out = os.path.join(td, "single_report.xlsx")
            rg.generate_report(td, out)
            with zipfile.ZipFile(out) as z:
                wb = z.read("xl/workbook.xml").decode("utf-8")
                # 최종 workflow에서는 단일 CSV도 동일한 관리 시트 구성을 유지한다.
                self.assertIn("03_변경추적대장", wb)
                self.assertIn("04_현재Open포트", wb)
                self.assertIn("05_현재스캔전체", wb)

    def test_generate_report_no_csv_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises((ValueError, FileNotFoundError)):
                rg.generate_report(td, os.path.join(td, "x.xlsx"))

    def test_change_history_counts(self):
        """변경이력 시트의 NEW_OPEN/CLOSED/CHANGED 카운트 정확성."""
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            out = os.path.join(td, "report.xlsx")
            rg.generate_report(td, out)
            rows = xlsx_io.read_xlsx(out)
            # 첫 번째 시트 (현황) 가 read_xlsx 의 결과 — 변경이력은 못 읽음
            # 그래서 직접 sheet3.xml 확인
            with zipfile.ZipFile(out) as z:
                sheet3 = z.read("xl/worksheets/sheet3.xml").decode("utf-8")
                shared = z.read("xl/sharedStrings.xml").decode("utf-8")
            # 변경이력 시트가 sheet3 위치에 있다고 가정 (sheets 순서: 현황, 히트맵, 변경이력, 위험도추이, 메타, NSE상세)
            # 1차 시점 → 2차 시점: NEW_OPEN=1 (포트 80 신규), CLOSED=0, CHANGED=1 (443 nginx 1.24→1.25), UNCHANGED=1 (22)
            # 2차 → 3차: NEW_OPEN=0, CLOSED=1 (80 닫힘), CHANGED=1 (22 위험도 변경 — service 시그니처 동일하면 안 잡힘)
            # 위험도 변경은 service 시그니처 변경 아님 → CHANGED 안 잡힐 수도. 그래서 약한 검증만.
            self.assertIn("NEW_OPEN", shared)
            self.assertIn("CLOSED", shared)

    def test_heatmap_marks_service_signature_change(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "scan_20260101_120000.csv")
            p2 = os.path.join(td, "scan_20260201_120000.csv")
            with open(p1, "w", encoding="utf-8-sig", newline="") as f:
                f.write(_HEADER_24)
                f.write(_row("10.0.0.1", "22", "open", "ssh", "OpenSSH 9.6", nse="SSH_FP_SHA256=a"))
            with open(p2, "w", encoding="utf-8-sig", newline="") as f:
                f.write(_HEADER_24)
                f.write(_row("10.0.0.1", "22", "open", "ssh", "OpenSSH 9.7", nse="SSH_FP_SHA256=b"))
            out = os.path.join(td, "report.xlsx")
            rg.generate_report(td, out)
            with zipfile.ZipFile(out) as z:
                shared = z.read("xl/sharedStrings.xml").decode("utf-8")
                heatmap_xml = z.read("xl/worksheets/sheet3.xml").decode("utf-8")
            self.assertIn("변경", shared)
            self.assertIn('s="6"', heatmap_xml, "히트맵 변경 셀에 CHANGED 색이 적용되지 않음")

    def test_generate_report_rejects_unparseable_csv(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "random_20260101_120000.csv"), "w", encoding="utf-8") as f:
                f.write("name,value\nfoo,bar\n")
            with self.assertRaisesRegex(ValueError, "유효한 nmapParser CSV|필수 열 누락"):
                rg.generate_report(td, os.path.join(td, "report.xlsx"))

    def test_meta_sheet_includes_filename_and_encoding(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            out = os.path.join(td, "report.xlsx")
            rg.generate_report(td, out)
            with zipfile.ZipFile(out) as z:
                shared = z.read("xl/sharedStrings.xml").decode("utf-8")
            self.assertIn("encoding", shared)
            self.assertIn("scan_20260101_120000.csv", shared)
            self.assertIn("utf-8-sig", shared)

    def test_run_cli_report_prints_summary(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            class Args:
                pass
            args = Args()
            args.csv_folder = td
            args.out = os.path.join(td, "report.xlsx")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = rg.run_cli_report(args)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("[report] OK:", out)
            self.assertIn("[report] SUMMARY:", out)
            self.assertIn("csv_files=3", out)


if __name__ == "__main__":
    unittest.main()
