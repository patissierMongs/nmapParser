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

    def test_override_target_detection_accepts_file_and_hostname_targets(self):
        self.assertTrue(np.override_tokens_have_target(["-iL", "targets.txt"]))
        self.assertTrue(np.override_tokens_have_target(["--script", "ssl-cert", "example.com"]))


if __name__ == "__main__":
    unittest.main()
