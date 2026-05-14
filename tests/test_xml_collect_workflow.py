# -*- coding: utf-8 -*-
"""기존 XML recursive 취합/CSV 변환 workflow 테스트."""

import os
import tempfile
import unittest

import nmapParser as np


def _write_xml(path, ip="10.0.0.1", port="80"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f'''<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>
''')


class XmlCollectWorkflowTest(unittest.TestCase):
    def test_collect_xml_candidates_is_recursive_excludes_managed_dirs_and_dedups(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "workspace")
            scans = os.path.join(src, "old", "nested")
            collected = os.path.join(src, "collected", "latest")
            reports = os.path.join(src, "reports")
            legacy = os.path.join(src, "_collected_20260101_000000")
            dst = os.path.join(src, "collected", "20260514_150000")
            for d in (scans, collected, reports, legacy, dst):
                os.makedirs(d, exist_ok=True)
            _write_xml(os.path.join(scans, "scan.xml"), "10.0.0.1", "80")
            _write_xml(os.path.join(scans, "dup.xml"), "10.0.0.1", "80")
            _write_xml(os.path.join(collected, "already.xml"), "10.0.0.2", "443")
            _write_xml(os.path.join(reports, "report.xml"), "10.0.0.3", "22")
            _write_xml(os.path.join(legacy, "old.xml"), "10.0.0.4", "25")
            _write_xml(os.path.join(dst, "dst.xml"), "10.0.0.5", "110")

            paths, skipped = np.collect_xml_candidates(
                src, dst,
                exclude_dirs=[np.get_collected_dir(src), np.get_reports_dir(src)],
            )

            self.assertEqual(len(paths), 1)
            self.assertIn(paths[0].name, ("scan.xml", "dup.xml"))
            self.assertEqual(skipped, 1)

    def test_convert_xml_candidates_to_csv_bundle_writes_csv_and_copies_xml_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "src")
            dst = os.path.join(td, "collected", "20260514_150000")
            xml1 = os.path.join(src, "a", "scan.xml")
            xml2 = os.path.join(src, "b", "scan.xml")
            _write_xml(xml1, "10.0.0.1", "80")
            _write_xml(xml2, "10.0.0.2", "443")

            result = np.convert_xml_candidates_to_csv_bundle([xml1, xml2], dst)

            self.assertEqual(result["ok"], 2)
            self.assertEqual(result["failed"], [])
            files = sorted(os.listdir(dst))
            self.assertIn("scan.csv", files)
            self.assertIn("scan.xml", files)
            self.assertIn("scan_2.csv", files)
            self.assertIn("scan_2.xml", files)
            with open(os.path.join(dst, "scan.csv"), encoding="utf-8-sig") as f:
                self.assertIn("10.0.0.1", f.read())
            with open(os.path.join(dst, "scan_2.csv"), encoding="utf-8-sig") as f:
                self.assertIn("10.0.0.2", f.read())


if __name__ == "__main__":
    unittest.main()
