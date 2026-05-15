# -*- coding: utf-8 -*-
"""시간축 보고서 보정 요구 회귀 테스트."""

import os
import tempfile
import unittest

import report_generator as rg


_HEADER_24 = (
    "IP,호스트,OS,프로토콜,포트,표준포트,포트상태,추측서비스,확인서비스(short),"
    "식별,분류,용도,위험도,암호화,인증,노출위험,공격표면,출처,"
    "상세(제품/버전),비고,NSE스크립트명,스크립트출력,NSE추출,점검메모\n"
)


def _write_csv(path, rows, header=_HEADER_24):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(header)
        for row in rows:
            f.write(row)


def _row(ip, port, state="open", service="ssh", detail="OpenSSH", risk="중", nse=""):
    return (
        f"{ip},host,Linux,tcp,{port},{service},{state},{service},{service},"
        f"확인,원격접속,관리,{risk},암호화,인증,노출위험,공격표면,출처,{detail},비고,script,output,{nse},\n"
    )


class ReportCorrectionScopeOpenSummaryTests(unittest.TestCase):
    def test_nse_summary_order_only_change_is_keep(self):
        snapshots = [
            ("20260501_090000", [{
                "IP": "10.0.0.1", "프로토콜": "tcp", "포트": "443", "포트상태": "open",
                "확인서비스(short)": "https", "상세(제품/버전)": "nginx",
                "NSE추출": "TLS_CN=portal; HTTP_Title=Portal",
            }]),
            ("20260508_090000", [{
                "IP": "10.0.0.1", "프로토콜": "tcp", "포트": "443", "포트상태": "open",
                "확인서비스(short)": "https", "상세(제품/버전)": "nginx",
                "NSE추출": "HTTP_Title=Portal; TLS_CN=portal",
            }]),
        ]
        per_tp = rg._build_snapshot_maps(snapshots)
        self.assertEqual(rg._change_type_for_key(per_tp, "10.0.0.1:443/tcp"), "KEEP")
        tracking = rg._build_sheet_tracking_final(snapshots)
        self.assertEqual(tracking["rows"], [])

    def test_generate_report_rejects_missing_required_state_header(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad_20260501_090000.csv")
            _write_csv(
                path,
                ["10.0.0.1,host,Linux,tcp,22,ssh,ssh,ssh\n"],
                header="IP,호스트,OS,프로토콜,포트,표준포트,추측서비스,확인서비스(short)\n",
            )
            with self.assertRaisesRegex(ValueError, "필수 열 누락.*포트상태"):
                rg.generate_report(td, os.path.join(td, "report.xlsx"))

    def test_duplicate_timestamp_labels_are_made_unique(self):
        with tempfile.TemporaryDirectory() as td:
            a = os.path.join(td, "teamA_20260501_090000.csv")
            b = os.path.join(td, "teamB_20260501_090000.csv")
            _write_csv(a, [_row("10.0.0.1", "22")])
            _write_csv(b, [_row("10.0.0.2", "443", service="https")])
            files = rg.collect_csv_files(td)
            labels = [label for _path, label in files]
            self.assertEqual(labels, ["20260501_090000", "20260501_090000_2"])

    def test_current_open_sheet_filters_open_and_full_sheet_keeps_all_states(self):
        latest = [
            {"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"},
            {"IP": "10.0.0.2", "프로토콜": "tcp", "포트": "80", "포트상태": "closed", "확인서비스(short)": "http"},
            {"IP": "10.0.0.3", "프로토콜": "tcp", "포트": "443", "포트상태": "filtered", "확인서비스(short)": "https"},
        ]
        open_sheet = rg._build_sheet_current_open_ports_final("20260508_090000", latest)
        full_sheet = rg._build_sheet_current_ports_final("20260508_090000", latest)
        self.assertEqual(open_sheet["name"], "04_현재Open포트")
        self.assertEqual(full_sheet["name"], "05_현재스캔전체")
        self.assertEqual(len(open_sheet["rows"]), 1)
        self.assertEqual(len(full_sheet["rows"]), 3)
        self.assertIn("open", open_sheet["rows"][0])

    def test_tracking_uses_actual_file_stem_for_evidence_names(self):
        snapshots = [
            ("20260501_090000", [{"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "443", "포트상태": "open", "확인서비스(short)": "https", "상세(제품/버전)": "nginx1"}]),
            ("20260508_090000", [{"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "443", "포트상태": "open", "확인서비스(short)": "https", "상세(제품/버전)": "nginx2"}]),
        ]
        file_meta = [
            ("20260501_090000", "company_internal_week1_20260501_090000_export.csv", "utf-8-sig"),
            ("20260508_090000", "company_internal_week2_20260508_090000_export.csv", "utf-8-sig"),
        ]
        tracking = rg._build_sheet_tracking_final(snapshots, file_meta=file_meta)
        xml_idx = tracking["headers"].index("원본XML")
        log_idx = tracking["headers"].index("원본LOG")
        self.assertEqual(tracking["rows"][0][xml_idx], "company_internal_week2_20260508_090000_export.xml")
        self.assertEqual(tracking["rows"][0][log_idx], "company_internal_week2_20260508_090000_export.log")

    def test_scope_metadata_distinguishes_out_of_scope_from_unobserved(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", [{"IP": "10.0.1.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
        ]
        per_tp = rg._build_snapshot_maps(snapshots)
        scope_info = {
            "week1": rg._parse_scope_targets("10.0.0.0/24"),
            "week2": rg._parse_scope_targets("10.0.1.0/24"),
        }
        self.assertEqual(
            rg._state_token_timeline(per_tp, "10.0.0.5:22/tcp", scope_info=scope_info)[0],
            ["NEW_OPEN", "OUT_OF_SCOPE"],
        )
        self.assertEqual(rg._change_type_for_key(per_tp, "10.0.0.5:22/tcp", scope_info=scope_info), "OUT_OF_SCOPE")

        same_scope = {"week1": rg._parse_scope_targets("10.0.0.0/24"), "week2": rg._parse_scope_targets("10.0.0.0/24")}
        self.assertEqual(
            rg._state_token_timeline(per_tp, "10.0.0.5:22/tcp", scope_info=same_scope)[0],
            ["NEW_OPEN", "UNOBSERVED"],
        )

    def test_port_scope_distinguishes_not_scanned_port_from_unobserved(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "80", "포트상태": "open", "확인서비스(short)": "http"}]),
        ]
        per_tp = rg._build_snapshot_maps(snapshots)
        port_80_only = {"week2": rg._parse_scope_targets("10.0.0.0/24", ports="80")}
        self.assertEqual(
            rg._state_token_timeline(per_tp, "10.0.0.5:22/tcp", scope_info=port_80_only)[0],
            ["NEW_OPEN", "OUT_OF_SCOPE"],
        )
        port_22_included = {"week2": rg._parse_scope_targets("10.0.0.0/24", ports="22,80")}
        self.assertEqual(
            rg._state_token_timeline(per_tp, "10.0.0.5:22/tcp", scope_info=port_22_included)[0],
            ["NEW_OPEN", "UNOBSERVED"],
        )

    def test_log_scope_parser_keeps_nmap_port_range(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "scan_20260508_090000.csv")
            _write_csv(csv_path, [_row("10.0.0.5", "80")])
            with open(os.path.splitext(csv_path)[0] + ".log", "w", encoding="utf-8") as f:
                f.write("[명령] nmap -sS -p 80,443 10.0.0.0/24 -oA scan_20260508_090000\n")
            scope = rg._load_scope_for_csv(csv_path, rg._read_csv_rows(csv_path)[0])
            self.assertTrue(rg._ip_in_scope("10.0.0.5", scope))
            self.assertTrue(rg._port_in_scope("443", "tcp", scope))
            self.assertFalse(rg._port_in_scope("22", "tcp", scope))

    def test_xml_scaninfo_scope_marks_unscanned_top_port_as_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            week1 = os.path.join(td, "localhost_20260515_104352.csv")
            week2 = os.path.join(td, "localhost_20260515_105713.csv")
            _write_csv(week1, [_row("127.0.0.1", "12222", service="unknown")])
            _write_csv(week2, [_row("127.0.0.1", "135", service="msrpc")])
            with open(os.path.splitext(week2)[0] + ".xml", "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?><nmaprun>'
                    '<scaninfo type="syn" protocol="tcp" numservices="3" services="80,135,443"/>'
                    '<host><address addr="127.0.0.1" addrtype="ipv4"/></host>'
                    '</nmaprun>'
                )

            rows1 = rg._read_csv_rows(week1)[0]
            rows2 = rg._read_csv_rows(week2)[0]
            scope_info = {
                "20260515_104352": rg._load_scope_for_csv(week1, rows1),
                "20260515_105713": rg._load_scope_for_csv(week2, rows2),
            }
            per_tp = rg._build_snapshot_maps([("20260515_104352", rows1), ("20260515_105713", rows2)])
            self.assertFalse(rg._port_in_scope("12222", "tcp", scope_info["20260515_105713"]))
            self.assertEqual(
                rg._state_token_timeline(per_tp, "127.0.0.1:12222/tcp", scope_info=scope_info)[0],
                ["NEW_OPEN", "OUT_OF_SCOPE"],
            )

    def test_heatmap_displays_scope_tokens_in_korean(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "80", "포트상태": "open", "확인서비스(short)": "http"}]),
        ]
        scope_info = {"week2": rg._parse_scope_targets("10.0.0.0/24", ports="80")}
        heatmap = rg._build_sheet_heatmap_final(snapshots, scope_info=scope_info)
        text = "\n".join("|".join(row) for row in heatmap["rows"])
        self.assertIn("신규OPEN", text)
        self.assertIn("대상아님", text)
        self.assertNotIn("OUT_OF_SCOPE", text)

    def test_ipv6_heatmap_keeps_ip_and_port_columns_intact(self):
        snapshots = [
            ("week1", [{"IP": "2001:db8::10", "프로토콜": "tcp", "포트": "443", "포트상태": "open", "확인서비스(short)": "https"}]),
            ("week2", [{"IP": "2001:db8::10", "프로토콜": "tcp", "포트": "443", "포트상태": "open", "확인서비스(short)": "https"}]),
        ]
        heatmap = rg._build_sheet_heatmap_final(snapshots)
        row = heatmap["rows"][0]
        self.assertEqual(row[1], "2001:db8::10")
        self.assertEqual(row[5], "tcp")
        self.assertEqual(row[6], "443")

    def test_xml_target_specification_takes_precedence_over_observed_addresses(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "scan_20260508_090000.csv")
            _write_csv(csv_path, [_row("10.0.0.2", "22")])
            with open(os.path.splitext(csv_path)[0] + ".xml", "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?><nmaprun>'
                    '<target specification="10.0.0.0/24"/>'
                    '<scaninfo type="syn" protocol="tcp" services="22"/>'
                    '<host><address addr="10.0.0.2" addrtype="ipv4"/></host>'
                    '</nmaprun>'
                )
            scope = rg._load_scope_for_csv(csv_path, rg._read_csv_rows(csv_path)[0])
            self.assertTrue(rg._ip_in_scope("10.0.0.1", scope))
            self.assertTrue(rg._port_in_scope("22", "tcp", scope))

    def test_xml_args_scope_used_when_target_element_is_missing(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "scan_20260508_090000.csv")
            _write_csv(csv_path, [_row("10.0.0.2", "22")])
            with open(os.path.splitext(csv_path)[0] + ".xml", "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?><nmaprun args="nmap -sS -p 22 10.0.0.0/24 -oA scan">'
                    '<scaninfo type="syn" protocol="tcp" services="22"/>'
                    '<host><address addr="10.0.0.2" addrtype="ipv4"/></host>'
                    '</nmaprun>'
                )
            scope = rg._load_scope_for_csv(csv_path, rg._read_csv_rows(csv_path)[0])
            self.assertTrue(rg._ip_in_scope("10.0.0.99", scope))
            self.assertTrue(rg._port_in_scope("22", "tcp", scope))

    def test_observed_xml_addresses_alone_do_not_make_missing_host_out_of_scope(self):
        with tempfile.TemporaryDirectory() as td:
            week1 = os.path.join(td, "scan_20260501_090000.csv")
            week2 = os.path.join(td, "scan_20260508_090000.csv")
            _write_csv(week1, [_row("10.0.0.5", "22")])
            _write_csv(week2, [_row("10.0.0.6", "22")])
            with open(os.path.splitext(week2)[0] + ".xml", "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?><nmaprun>'
                    '<scaninfo type="syn" protocol="tcp" services="22"/>'
                    '<host><address addr="10.0.0.6" addrtype="ipv4"/></host>'
                    '</nmaprun>'
                )
            snapshots = [
                ("20260501_090000", rg._read_csv_rows(week1)[0]),
                ("20260508_090000", rg._read_csv_rows(week2)[0]),
            ]
            scope_info = {"20260508_090000": rg._load_scope_for_csv(week2, snapshots[1][1])}
            tokens = rg._state_token_timeline(
                rg._build_snapshot_maps(snapshots), "10.0.0.5:22/tcp", scope_info=scope_info
            )[0]
            self.assertEqual(tokens, ["NEW_OPEN", "UNOBSERVED"])

    def test_filtered_after_open_is_not_reported_as_closed(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "filtered", "확인서비스(short)": "ssh"}]),
        ]
        per_tp = rg._build_snapshot_maps(snapshots)
        self.assertEqual(rg._state_token_timeline(per_tp, "10.0.0.5:22/tcp")[0], ["NEW_OPEN", "FILTERED"])
        self.assertEqual(rg._change_type_for_key(per_tp, "10.0.0.5:22/tcp"), "FILTERED")

    def test_xml_mixed_target_spec_keeps_observed_address_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "scan_20260508_090000.csv")
            _write_csv(csv_path, [_row("10.0.1.25", "22")])
            with open(os.path.splitext(csv_path)[0] + ".xml", "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0"?><nmaprun>'
                    '<target specification="10.0.0.0/24 10.0.1.1-50"/>'
                    '<scaninfo type="syn" protocol="tcp" services="22"/>'
                    '<host><address addr="10.0.1.25" addrtype="ipv4"/></host>'
                    '</nmaprun>'
                )
            scope = rg._load_scope_for_csv(csv_path, rg._read_csv_rows(csv_path)[0])
            self.assertTrue(rg._ip_in_scope("10.0.0.5", scope))
            self.assertTrue(rg._ip_in_scope("10.0.1.25", scope))

    def test_out_of_scope_gap_breaks_open_continuity(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", []),
            ("week3", [{"IP": "10.0.0.5", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
        ]
        scope_info = {
            "week2": rg._parse_scope_targets("10.0.1.0/24", ports="22"),
        }
        tokens = rg._state_token_timeline(rg._build_snapshot_maps(snapshots), "10.0.0.5:22/tcp", scope_info=scope_info)[0]
        self.assertEqual(tokens, ["NEW_OPEN", "OUT_OF_SCOPE", "NEW_OPEN"])

    def test_collect_csv_files_ignores_exported_report_sheet_csvs(self):
        with tempfile.TemporaryDirectory() as td:
            scan = os.path.join(td, "scan_20260501_090000.csv")
            _write_csv(scan, [_row("10.0.0.1", "22")])
            with open(os.path.join(td, "00_보고요약.csv"), "w", encoding="utf-8") as f:
                f.write("섹션,항목,값\n보고 기준,현재 스캔 시점,20260501_090000\n")
            with open(os.path.join(td, "02_시간축히트맵.csv"), "w", encoding="utf-8") as f:
                f.write("자산키,IP,포트\n10.0.0.1|tcp|22,10.0.0.1,22\n")
            files = rg.collect_csv_files(td)
            self.assertEqual([os.path.basename(path) for path, _label in files], ["scan_20260501_090000.csv"])

    def test_header_whitespace_is_accepted_for_required_columns_and_rows(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "scan_20260501_090000.csv")
            header = _HEADER_24.replace("IP,호스트", " IP ,호스트").replace("프로토콜", " 프로토콜 ").replace("포트,표준포트", " 포트 ,표준포트").replace("포트상태", " 포트상태 ")
            _write_csv(csv_path, [_row("10.0.0.1", "22")], header=header)
            rows, _enc, headers = rg._read_csv_rows_with_headers(csv_path)
            rg._validate_required_headers(headers, csv_path)
            self.assertEqual(rg._key_for_row(rows[0]), "10.0.0.1:22/tcp")

    def test_report_summary_focuses_on_cumulative_and_current_scan_not_previous_baseline(self):
        snapshots = [
            ("week1", [{"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"}]),
            ("week2", [
                {"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"},
                {"IP": "10.0.0.2", "프로토콜": "tcp", "포트": "80", "포트상태": "open", "확인서비스(short)": "http"},
            ]),
        ]
        summary = rg._build_sheet_summary_final(snapshots, "/tmp/input")
        summary_text = "\n".join("|".join(row) for row in summary["rows"])
        self.assertIn("지금까지 스캔 통합", summary_text)
        self.assertIn("누적 관측 포트 수", summary_text)
        self.assertIn("이번 스캔", summary_text)
        self.assertIn("이번 스캔 open 포트 수", summary_text)
        self.assertNotIn("비교 기준 시점", summary_text)
        self.assertNotIn("신규 Open", summary_text)
        self.assertNotIn("변경|", summary_text)

    def test_duplicate_port_rows_are_reported_in_summary(self):
        snapshots = [
            ("20260501_090000", [
                {"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"},
                {"IP": "10.0.0.1", "프로토콜": "tcp", "포트": "22", "포트상태": "open", "확인서비스(short)": "ssh"},
            ])
        ]
        summary = rg._build_sheet_summary_final(snapshots, "/tmp/input")
        summary_text = "\n".join("|".join(row) for row in summary["rows"])
        self.assertIn("중복 포트 행", summary_text)
        self.assertIn("1", summary_text)


if __name__ == "__main__":
    unittest.main()
