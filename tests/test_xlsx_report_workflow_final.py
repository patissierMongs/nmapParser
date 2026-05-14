# -*- coding: utf-8 -*-
"""XLSX 중심 최종 보고 workflow 회귀 테스트."""

import os
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

import report_generator as rg


_HEADER_24 = (
    "IP,호스트,OS,프로토콜,포트,표준포트,포트상태,추측서비스,확인서비스(short),"
    "식별,분류,용도,위험도,암호화,인증,노출위험,공격표면,출처,"
    "상세(제품/버전),비고,NSE스크립트명,스크립트출력,NSE추출,점검메모\n"
)


def _write_csv(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(_HEADER_24)
        for r in rows:
            f.write(r)


def _row(ip, port, state="open", service="ssh", detail="OpenSSH 9.6", risk="중", nse=""):
    return (
        f"{ip},host,Linux,tcp,{port},{service},{state},{service},{service},"
        f"확인,원격접속,관리,{risk},암호화,사용자,노출위험,공격표면,출처,{detail},비고,script,output,{nse},\n"
    )


def _sheet_names(path):
    with zipfile.ZipFile(path) as z:
        root = ET.fromstring(z.read("xl/workbook.xml"))
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    return [s.attrib["name"] for s in root.find("m:sheets", ns)]


class FinalXlsxWorkflowTests(unittest.TestCase):
    def _make_csvs(self, td):
        _write_csv(os.path.join(td, "phase1_20260507_103018.csv"), [
            _row("10.0.0.1", "22", "open", "ssh", "OpenSSH 9.6", "중", "SSH_FP_SHA256=a"),
            _row("10.0.0.2", "443", "open", "https", "nginx 1.24", "상", "TLS_CN=portal.local; HTTP_Title=Portal"),
        ])
        _write_csv(os.path.join(td, "phase1_20260514_110032.csv"), [
            _row("10.0.0.1", "22", "open", "ssh", "OpenSSH 9.7", "중", "SSH_FP_SHA256=b"),
            _row("10.0.0.2", "443", "closed", "https", "", "상", ""),
            _row("10.0.0.3", "3306", "open", "mysql", "MySQL", "중", "Raw_FirstLine=MySQL handshake"),
        ])

    def test_generate_report_uses_final_excel_sheet_names(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            out = os.path.join(td, "report.xlsx")
            rg.generate_report(td, out)
            self.assertEqual(_sheet_names(out), [
                "00_보고요약",
                "01_스캔증적",
                "02_시간축히트맵",
                "03_변경추적대장",
                "04_조치이력",
                "05_현재Open포트",
                "06_현재스캔전체",
                "07_증적파일목록",
                "08_서비스별확인설정",
                "09_NSE분해",
            ])

    def test_heatmap_headers_are_decomposed_for_excel_filtering(self):
        with tempfile.TemporaryDirectory() as td:
            self._make_csvs(td)
            sheet = rg._build_sheet_heatmap_final([
                ("20260507_103018", rg._read_csv_rows(os.path.join(td, "phase1_20260507_103018.csv"))[0]),
                ("20260514_110032", rg._read_csv_rows(os.path.join(td, "phase1_20260514_110032.csv"))[0]),
            ])
            headers = sheet["headers"]
            self.assertNotIn("IP:port/proto", headers)
            for h in ("IP", "IP대역", "프로토콜", "포트", "현재상태", "마지막변경유형"):
                self.assertIn(h, headers)
            self.assertNotIn("포트번호정수", headers)

    def test_individual_xlsx_has_port_evidence_and_service_sheets(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "phase1_20260514_110032.csv")
            _write_csv(csv_path, [_row("10.0.0.3", "3306", "open", "mysql", "MySQL", "중", "Raw_FirstLine=MySQL handshake")])
            xlsx_path = os.path.join(td, "phase1_20260514_110032.xlsx")
            rg.generate_individual_xlsx(csv_path, xlsx_path)
            self.assertEqual(_sheet_names(xlsx_path), ["포트현황", "스캔증적", "서비스별확인"])
    def test_different_scan_ranges_mark_missing_latest_as_unobserved_not_closed_or_new(self):
        with tempfile.TemporaryDirectory() as td:
            first = os.path.join(td, "phase1_20260507_103018.csv")
            second = os.path.join(td, "phase2_20260514_110032.csv")
            _write_csv(first, [_row("10.0.0.1", "22", "open", "ssh", "OpenSSH 9.6")])
            _write_csv(second, [_row("10.0.0.2", "443", "open", "https", "nginx")])
            snapshots = [
                ("20260507_103018", rg._read_csv_rows(first)[0]),
                ("20260514_110032", rg._read_csv_rows(second)[0]),
            ]
            per_tp = rg._build_snapshot_maps(snapshots)

            self.assertEqual(rg._state_token_timeline(per_tp, "10.0.0.1:22/tcp")[0], ["NEW_OPEN", "UNOBSERVED"])
            self.assertEqual(rg._change_type_for_key(per_tp, "10.0.0.1:22/tcp"), "UNOBSERVED")
            tracking = rg._build_sheet_tracking_final(snapshots)
            self.assertNotIn("10.0.0.1", "\n".join(",".join(row) for row in tracking["rows"]))

    def test_user_added_columns_are_ignored_and_missing_optional_columns_load_as_blank(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "edited_20260514_110032.csv")
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,프로토콜,포트,포트상태,확인서비스(short),사용자추가컬럼\n")
                f.write("10.0.0.9,tcp,8080,open,http,사용자메모\n")
            rows, _enc = rg._read_csv_rows(path)
            self.assertEqual(rg._key_for_row(rows[0]), "10.0.0.9:8080/tcp")
            self.assertEqual(rg._state_for_row(rows[0]), "open")
            self.assertEqual(rg._risk_for_row(rows[0]), "")


if __name__ == "__main__":
    unittest.main()
