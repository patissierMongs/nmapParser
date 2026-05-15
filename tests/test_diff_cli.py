import csv
import io
import os
import tempfile
import unittest
import glob
from unittest import mock

import nmapParser as np


class DiffEngineTests(unittest.TestCase):
    def test_exposure_guide_has_minimum_services(self):
        required = [
            "chargen", "ftp", "ssh", "telnet", "smtp", "dns", "tftp",
            "http", "https", "rpcbind", "ntp", "microsoft-ds", "snmp",
            "cldap", "rdp", "vnc", "ajp13", "http-proxy", "echo",
            "ipsec-nat-t", "syslog", "sip", "webpush", "ipcserver", "cadlock2",
            "914c-g", "rcp", "rlogin", "postgresql", "mysql", "mongodb", "redis",
        ]
        missing = [k for k in required if k not in np.SERVICE_EXPOSURE_GUIDE]
        self.assertFalse(missing, f"missing guide keys: {missing}")

    def test_digest_normalization(self):
        a = np._digest_for_diff(" SSH  ", "OpenSSH   9.6", "A\nB")
        b = np._digest_for_diff("ssh", "openssh 9.6", "a b")
        self.assertEqual(a, b)

    def test_parse_csv_rows_for_diff(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "x.csv")
            with open(p, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.6,abc\n")
            rows = np.parse_csv_rows_for_diff(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "10.0.0.1")
            self.assertEqual(rows[0]["proto"], "tcp")
            self.assertEqual(rows[0]["port"], "22")

    def test_parse_csv_rows_for_diff_accepts_cp949(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "cp949.csv")
            with open(p, "w", encoding="cp949", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.6,한글\n")
            rows = np.parse_csv_rows_for_diff(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "10.0.0.1")
            self.assertEqual(rows[0]["service"], "ssh")

    def test_run_cli_diff_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.6,x\n")
                f.write("10.0.0.1,80,tcp,open,http,nginx,\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.7,x\n")
                f.write("10.0.0.1,443,tcp,open,https,nginx,\n")

            class Args:
                pass
            args = Args()
            args.diff = True
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True

            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)
            names = os.listdir(td)
            self.assertTrue(any(n.startswith("diff_") and n.endswith(".csv") for n in names))
            self.assertTrue(any(n.startswith("summary_") and n.endswith(".csv") for n in names))
            self.assertTrue(any(n.startswith("snapshot_") and n.endswith(".csv") for n in names))

    def test_parse_xml_rows_for_diff(self):
        with tempfile.TemporaryDirectory() as td:
            xml_path = os.path.join(td, "sample.xml")
            xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
        <script id="ssh-hostkey" output="rsa key"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)
            rows = np.parse_xml_rows_for_diff(xml_path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "10.0.0.2")
            self.assertEqual(rows[0]["proto"], "tcp")
            self.assertEqual(rows[0]["port"], "22")
            self.assertEqual(rows[0]["state"], "open")
            self.assertEqual(rows[0]["service"], "ssh")

    def test_xml_and_generated_csv_diff_digest_match_for_script_output(self):
        with tempfile.TemporaryDirectory() as td:
            xml_path = os.path.join(td, "sample.xml")
            csv_path = os.path.join(td, "sample.csv")
            xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" method="probed" product="nginx"/>
        <script id="http-title" output="Portal"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)
            np.convert_xml_to_csv_standalone(xml_path, csv_path)
            self.assertEqual(np.parse_xml_rows_for_diff(xml_path)[0]["digest"], np.parse_csv_rows_for_diff(csv_path)[0]["digest"])

    def test_xml_and_generated_csv_diff_service_match_for_table_method(self):
        with tempfile.TemporaryDirectory() as td:
            xml_path = os.path.join(td, "sample.xml")
            csv_path = os.path.join(td, "sample.csv")
            xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" method="table"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)
            np.convert_xml_to_csv_standalone(xml_path, csv_path)
            self.assertEqual(np.parse_xml_rows_for_diff(xml_path)[0]["service"], np.parse_csv_rows_for_diff(csv_path)[0]["service"])

    def test_parse_nmap_xml_resilient_with_truncated_tail(self):
        with tempfile.TemporaryDirectory() as td:
            xml_path = os.path.join(td, "broken.xml")
            # </nmaprun> 이 없는 절전/중단 상황 유사 데이터
            xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/></port>
    </ports>
  </host>"""
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml)
            root = np.parse_nmap_xml_resilient(xml_path)
            self.assertEqual(root.tag, "nmaprun")
            hosts = root.findall("host")
            self.assertEqual(len(hosts), 1)

    def test_only_changes_filters_unchanged_rows(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.6,x\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write("IP,PORT,프로토콜,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n")
                f.write("10.0.0.1,22,tcp,open,ssh,OpenSSH 9.6,x\n")

            class Args:
                pass
            args = Args()
            args.diff = True
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True
            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)

            diff_files = sorted(glob.glob(os.path.join(td, "diff_*.csv")))
            self.assertTrue(diff_files)
            with open(diff_files[-1], "r", encoding="utf-8-sig") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            # 헤더만 남아야 함 (UNCHANGED는 필터링)
            self.assertEqual(len(lines), 1)

    def test_parse_csv_rows_for_diff_korean_23col(self):
        """도구가 실제로 출력하는 23컬럼 한국어 CSV 헤더에서 정상 파싱되는지 검증.
        v0.4 회귀 방지 — port 컬럼이 '포트' (한국어) 인 케이스.
        """
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "korean.csv")
            with open(p, "w", encoding="utf-8-sig", newline="") as f:
                f.write(
                    "IP,호스트,OS,프로토콜,포트,표준포트,포트상태,추측서비스,확인서비스(short),"
                    "식별,분류,용도,위험도,암호화,인증,노출위험,공격표면,출처,"
                    "상세(제품/버전),비고,NSE스크립트명,스크립트출력,점검메모\n"
                )
                f.write(
                    "10.0.0.1,host1,Linux,tcp,22,ssh,open,ssh,ssh,"
                    "확인,원격접속,관리,중,SSH,비밀번호,약한비번,브루트포스,KISA U-01,"
                    "OpenSSH 9.6,,,," "\n"
                )
                f.write(
                    "10.0.0.1,host1,Linux,tcp,80,http,open,http,http,"
                    "확인,웹,사용자,중,없음,없음,평문,XSS,KISA W-13,"
                    "nginx 1.24,,,," "\n"
                )
            rows = np.parse_csv_rows_for_diff(p)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["ip"], "10.0.0.1")
            self.assertEqual(rows[0]["proto"], "tcp")
            self.assertEqual(rows[0]["port"], "22")
            self.assertEqual(rows[0]["state"], "open")
            self.assertEqual(rows[0]["service"], "ssh")
            self.assertIn("OpenSSH", rows[0]["detail"])
            ports = sorted(r["port"] for r in rows)
            self.assertEqual(ports, ["22", "80"])

    def test_run_cli_diff_korean_23col(self):
        """23컬럼 한국어 CSV 두 개로 --diff 실행 시 결과 비어있지 않음."""
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = (
                "IP,호스트,OS,프로토콜,포트,표준포트,포트상태,추측서비스,확인서비스(short),"
                "식별,분류,용도,위험도,암호화,인증,노출위험,공격표면,출처,"
                "상세(제품/버전),비고,NSE스크립트명,스크립트출력,점검메모\n"
            )
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,h,Linux,tcp,22,ssh,open,ssh,ssh,확,원격,관리,중,SSH,비번,x,x,KISA,OpenSSH 9.6,,,,,\n")
                f.write("10.0.0.1,h,Linux,tcp,80,http,open,http,http,확,웹,사용자,중,X,X,X,X,KISA,nginx 1.24,,,,,\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,h,Linux,tcp,22,ssh,open,ssh,ssh,확,원격,관리,중,SSH,비번,x,x,KISA,OpenSSH 9.7,,,,,\n")
                f.write("10.0.0.1,h,Linux,tcp,443,https,open,https,https,확,웹,사용자,중,TLS,X,X,X,KISA,nginx 1.24,,,,,\n")

            class Args:
                pass
            args = Args()
            args.diff = True
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True
            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)

            diff_files = sorted(glob.glob(os.path.join(td, "diff_*.csv")))
            self.assertTrue(diff_files)
            with open(diff_files[-1], "r", encoding="utf-8-sig") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            # 헤더 + 데이터 행 (CHANGED + NEW_OPEN + CLOSED 3행, only_changes=True 라 UNCHANGED 빠짐)
            self.assertGreater(len(lines), 1, "diff 결과가 헤더만 — Korean 컬럼 파싱 실패 의심")

    def test_diff_xlsx_with_colors(self):
        """--out-format xlsx 또는 both 면 색칠된 xlsx 가 같이 생성되는지 검증."""
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = "IP,프로토콜,포트,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n"
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,\n")
                f.write("10.0.0.1,tcp,80,open,http,nginx 1.24,\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.7,\n")  # CHANGED
                f.write("10.0.0.1,tcp,443,open,https,nginx 1.24,\n")  # NEW_OPEN
                # 80 → 빠짐 (CLOSED)

            class Args:
                pass
            args = Args()
            args.diff = True
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = False
            args.out_format = "both"

            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)

            xlsx_files = glob.glob(os.path.join(td, "diff_*.xlsx"))
            self.assertEqual(len(xlsx_files), 1, "diff xlsx 파일이 생성되지 않음")
            xlsx_path = xlsx_files[0]

            with zipfile.ZipFile(xlsx_path) as z:
                names = z.namelist()
                # 3개 시트 (Diff/Summary/Snapshot)
                sheet_files = [n for n in names if n.startswith("xl/worksheets/sheet")]
                self.assertEqual(len(sheet_files), 3)
                # 색 확인 — styles.xml 안에 NEW_OPEN red, CHANGED yellow 들어 있어야
                styles = z.read("xl/styles.xml").decode("utf-8")
                self.assertIn("FFFFCDD2", styles)  # NEW_OPEN red
                self.assertIn("FFFFF59D", styles)  # CHANGED yellow
                self.assertIn("FFE1BEE7", styles)  # CLOSED 자주
                # Diff 시트 (sheet1) 안에 색 인덱스 적용된 셀 존재
                diff_xml = z.read("xl/worksheets/sheet1.xml").decode("utf-8")
                self.assertTrue(
                    's="2"' in diff_xml or 's="4"' in diff_xml or 's="6"' in diff_xml,
                    "Diff 시트에 NEW_OPEN/CLOSED/CHANGED 색이 적용되지 않음"
                )

    def test_diff_xlsx_only_format(self):
        """--out-format xlsx 면 CSV 는 안 만들고 xlsx 만."""
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = "IP,프로토콜,포트,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n"
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.7,\n")

            class Args:
                pass
            args = Args()
            args.diff = True
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = False
            args.out_format = "xlsx"

            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)
            self.assertEqual(len(glob.glob(os.path.join(td, "diff_*.csv"))), 0)
            self.assertEqual(len(glob.glob(os.path.join(td, "diff_*.xlsx"))), 1)

    def test_diff_raises_on_missing_file(self):
        class Args:
            pass
        args = Args()
        args.diff = True
        args.base = "/nonexistent/base.csv"
        args.curr = "/nonexistent/curr.csv"
        args.out = tempfile.gettempdir()
        args.only_changes = True
        with self.assertRaises(OSError):
            np.run_cli_diff(args)

    def test_main_diff_missing_file_returns_1(self):
        with mock.patch("sys.argv", ["nmapParser.py", "--diff", "--base", "/no/base.csv", "--curr", "/no/curr.csv"]):
            rc = np.main()
        self.assertEqual(rc, 1)

    def test_run_cli_diff_prints_summary_counts(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = "IP,프로토콜,포트,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n"
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,\n")
                f.write("10.0.0.1,tcp,80,open,http,nginx,\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.7,\n")
                f.write("10.0.0.1,tcp,443,open,https,nginx,\n")

            class Args:
                pass
            args = Args()
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True
            args.out_format = "csv"
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("[diff] SUMMARY:", out)
            self.assertIn("NEW_OPEN=1", out)
            self.assertIn("CLOSED=1", out)
            self.assertIn("CHANGED=1", out)

    def test_run_cli_diff_invalid_out_format_raises_value_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = "IP,프로토콜,포트,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n"
            for p in (base, curr):
                with open(p, "w", encoding="utf-8-sig", newline="") as f:
                    f.write(header)
                    f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,\n")
            class Args:
                pass
            args = Args()
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True
            args.out_format = "bogus"
            with self.assertRaises(ValueError):
                np.run_cli_diff(args)

    def test_diff_changed_fields_labels_digest_as_nse_or_script(self):
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "base.csv")
            curr = os.path.join(td, "curr.csv")
            header = "IP,프로토콜,포트,포트상태,확인서비스(short),상세(제품/버전),스크립트출력\n"
            with open(base, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,key-a\n")
            with open(curr, "w", encoding="utf-8-sig", newline="") as f:
                f.write(header)
                f.write("10.0.0.1,tcp,22,open,ssh,OpenSSH 9.6,key-b\n")
            class Args:
                pass
            args = Args()
            args.base = base
            args.curr = curr
            args.out = td
            args.only_changes = True
            args.out_format = "csv"
            np.run_cli_diff(args)
            diff_files = sorted(glob.glob(os.path.join(td, "diff_*.csv")))
            with open(diff_files[-1], "r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["change_type"], "CHANGED")
            self.assertEqual(rows[0]["changed_fields"], "nse_or_script")


if __name__ == "__main__":
    unittest.main()
