# -*- coding: utf-8 -*-
"""명령 조립 보조 로직 회귀 테스트."""

import unittest

import nmapParser as np


class CommandBuildingTests(unittest.TestCase):
    def test_override_target_detection_treats_sn_target_as_target(self):
        self.assertTrue(np.override_tokens_have_target(["-sn", "192.168.1.0/24"]))

    def test_override_target_detection_ignores_option_arguments(self):
        self.assertFalse(np.override_tokens_have_target(["-p", "22", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["--script", "ssl-cert,http-title"]))
        self.assertFalse(np.override_tokens_have_target(["-T", "4", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["-oA", "scan_output", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["-S", "192.0.2.10", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["--top-ports", "100", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["--min-rate", "1000", "-sV"]))
        self.assertFalse(np.override_tokens_have_target(["--dns-servers", "8.8.8.8", "-sV"]))

    def test_sanitize_output_args_removes_attached_output_options(self):
        app = np.NmapParserApp.__new__(np.NmapParserApp)
        self.assertEqual(app.sanitize_output_args(["-sV", "-oXscan.xml", "-oN", "scan.nmap", "-Pn"]), ["-sV", "-Pn"])

    def test_script_option_row_keeps_additional_tokens(self):
        app = np.NmapParserApp.__new__(np.NmapParserApp)
        extra, scripts = app.parse_option_rows_to_tokens([
            {"option": "--script ssl-cert --script-args tls.servername=example.com", "lineno": 2}
        ])
        self.assertEqual(scripts, ["ssl-cert"])
        self.assertEqual(extra, ["--script-args", "tls.servername=example.com"])

    def test_override_target_detection_accepts_file_and_hostname_targets(self):
        self.assertTrue(np.override_tokens_have_target(["-iL", "targets.txt"]))
        self.assertTrue(np.override_tokens_have_target(["--script", "ssl-cert", "example.com"]))


if __name__ == "__main__":
    unittest.main()
