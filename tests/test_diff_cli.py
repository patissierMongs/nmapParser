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
            args.asset = "HQ"
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
            args.asset = "HQ"
            args.only_changes = True
            rc = np.run_cli_diff(args)
            self.assertEqual(rc, 0)

            diff_files = sorted(glob.glob(os.path.join(td, "diff_*.csv")))
            self.assertTrue(diff_files)
            with open(diff_files[-1], "r", encoding="utf-8-sig") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            # 헤더만 남아야 함 (UNCHANGED는 필터링)
            self.assertEqual(len(lines), 1)

    def test_diff_raises_on_missing_file(self):
        class Args:
            pass
        args = Args()
        args.diff = True
        args.base = "/nonexistent/base.csv"
        args.curr = "/nonexistent/curr.csv"
        args.out = tempfile.gettempdir()
        args.asset = "HQ"
        args.only_changes = True
        with self.assertRaises(OSError):
            np.run_cli_diff(args)

    def test_main_diff_missing_file_returns_1(self):
        with mock.patch("sys.argv", ["nmapParser.py", "--diff", "--base", "/no/base.csv", "--curr", "/no/curr.csv"]):
            rc = np.main()
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
