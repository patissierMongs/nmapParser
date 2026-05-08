# -*- coding: utf-8 -*-
"""nse_extract 단위 테스트.

각 NSE 스크립트별 sample output 으로 핵심 필드가 정상 추출되는지 검증.
실제 nmap 출력 형태 (multiline, 들여쓰기, key: value) 를 흉내내서 회귀 방지.
"""

import unittest

import nse_extract as ne


class NseExtractTests(unittest.TestCase):
    # ---------------- ssl-cert
    def test_ssl_cert_basic(self):
        out = """Subject: commonName=www.example.com/organizationName=Example Inc.
Subject Alternative Name: DNS:www.example.com, DNS:example.com
Issuer: commonName=DigiCert TLS Hybrid ECC SHA384 2020 CA1
Public Key type: ec
Public Key bits: 256
Not valid before: 2025-01-15T00:00:00
Not valid after:  2026-02-13T23:59:59
"""
        f = ne.extract_nse_fields("ssl-cert", out)
        self.assertEqual(f["TLS_CN"], "www.example.com")
        self.assertIn("example.com", f["TLS_SAN"])
        self.assertEqual(f["TLS_Issuer"], "DigiCert TLS Hybrid ECC SHA384 2020 CA1")
        self.assertEqual(f["TLS_NotAfter"].strip(), "2026-02-13T23:59:59")
        self.assertEqual(f["TLS_KeyBits"], "256")
        self.assertEqual(f["TLS_SelfSigned"], "N")

    def test_ssl_cert_self_signed(self):
        out = """Subject: commonName=internal-host
Issuer: commonName=internal-host
Not valid after: 2027-01-01T00:00:00
"""
        f = ne.extract_nse_fields("ssl-cert", out)
        self.assertEqual(f["TLS_SelfSigned"], "Y")

    # ---------------- http-server-header
    def test_http_server_header(self):
        f = ne.extract_nse_fields("http-server-header", "Apache/2.4.58 (Ubuntu)")
        self.assertEqual(f["HTTP_Server"], "Apache/2.4.58 (Ubuntu)")

    # ---------------- http-title
    def test_http_title(self):
        f = ne.extract_nse_fields("http-title", "Welcome to nginx!\n")
        self.assertEqual(f["HTTP_Title"], "Welcome to nginx!")

    def test_http_title_no_title(self):
        f = ne.extract_nse_fields("http-title", "Site doesn't have a title (text/html).")
        self.assertNotIn("HTTP_Title", f)

    # ---------------- ssh-hostkey
    def test_ssh_hostkey(self):
        out = """  3072 SHA256:abcDEFghi/jklMNO+PQRstuVWX0123456789abcdefg (RSA)
  256 SHA256:zyxWVU/tsrQPONmlkjihGFEDCBA9876543210ZYXWVut (ED25519)
"""
        f = ne.extract_nse_fields("ssh-hostkey", out)
        self.assertIn("rsa", f["SSH_KeyTypes"])
        self.assertIn("ed25519", f["SSH_KeyTypes"])
        self.assertTrue(f.get("SSH_FP_SHA256", "").startswith("SHA256:"))

    # ---------------- smb-os-discovery
    def test_smb_os_discovery(self):
        out = """OS: Windows 10 Pro 19045 (Windows 10 Pro 6.3)
Computer name: WINHOST01
NetBIOS computer name: WINHOST01
Domain name: corp.example.com
FQDN: WINHOST01.corp.example.com
"""
        f = ne.extract_nse_fields("smb-os-discovery", out)
        self.assertIn("Windows", f["SMB_OS"])
        self.assertEqual(f["SMB_Computer"], "WINHOST01")
        self.assertEqual(f["SMB_Domain"], "corp.example.com")
        self.assertEqual(f["SMB_FQDN"], "WINHOST01.corp.example.com")

    # ---------------- smb-protocols
    def test_smb_protocols_v1(self):
        out = """  dialects:
    NT LM 0.12
    2.0.2
    2.1
"""
        f = ne.extract_nse_fields("smb-protocols", out)
        self.assertEqual(f["SMB_HasV1"], "Y")
        self.assertIn("2.1", f["SMB_Dialects"])

    def test_smb_protocols_no_v1(self):
        out = """  dialects:
    2.0.2
    2.1
    3.0
    3.0.2
    3.1.1
"""
        f = ne.extract_nse_fields("smb-protocols", out)
        self.assertEqual(f["SMB_HasV1"], "N")

    # ---------------- rdp-ntlm-info
    def test_rdp_ntlm(self):
        out = """Target_Name: CORP
NetBIOS_Domain_Name: CORP
NetBIOS_Computer_Name: WINHOST01
DNS_Domain_Name: corp.example.com
DNS_Computer_Name: WINHOST01.corp.example.com
DNS_Tree_Name: corp.example.com
Product_Version: 10.0.19045
"""
        f = ne.extract_nse_fields("rdp-ntlm-info", out)
        self.assertEqual(f["NTLM_Domain"], "corp.example.com")
        self.assertEqual(f["NTLM_Computer"], "WINHOST01.corp.example.com")
        self.assertEqual(f["NTLM_OS_Build"], "10.0.19045")

    # ---------------- nbstat
    def test_nbstat(self):
        out = """NetBIOS name: WINHOST01, NetBIOS user: <unknown>, NetBIOS MAC: 00:11:22:33:44:55 (Vendor)"""
        f = ne.extract_nse_fields("nbstat", out)
        self.assertEqual(f["NetBIOS_Computer"], "WINHOST01")
        self.assertEqual(f["NetBIOS_MAC"], "00:11:22:33:44:55")
        self.assertNotIn("NetBIOS_User", f)

    # ---------------- snmp-info
    def test_snmp_info(self):
        out = """sysDescr.0 = Linux router 5.4.0-generic"""
        f = ne.extract_nse_fields("snmp-info", out)
        self.assertIn("Linux", f["SNMP_sysDescr"])

    # ---------------- ike-version
    def test_ike_version(self):
        f = ne.extract_nse_fields("ike-version", "Detected IKEv2 endpoint")
        self.assertEqual(f["IKE_Version"], "v2")
        f = ne.extract_nse_fields("ike-version", "Aggressive mode handshake observed")
        self.assertEqual(f["IKE_Version"], "v1")

    # ---------------- ms-sql-info
    def test_ms_sql_info(self):
        out = """Version:
  name: Microsoft SQL Server 2019
  number: 15.0.4123.1
Instance name: MSSQLSERVER
"""
        f = ne.extract_nse_fields("ms-sql-info", out)
        self.assertIn("Microsoft", f["MSSQL_Version"])
        self.assertEqual(f["MSSQL_Instance"], "MSSQLSERVER")

    # ---------------- API: extract_all_nse + format_nse_summary
    def test_extract_all_merge(self):
        nse = [
            ("http-server-header", "nginx/1.24.0"),
            ("http-title", "Welcome"),
            ("ssl-cert", "Subject: commonName=foo\nIssuer: commonName=bar\n"),
        ]
        merged = ne.extract_all_nse(nse)
        self.assertEqual(merged["HTTP_Server"], "nginx/1.24.0")
        self.assertEqual(merged["HTTP_Title"], "Welcome")
        self.assertEqual(merged["TLS_CN"], "foo")

    def test_format_nse_summary_empty(self):
        self.assertEqual(ne.format_nse_summary({}), "")
        self.assertEqual(ne.format_nse_summary(None), "")

    def test_format_nse_summary_kv(self):
        s = ne.format_nse_summary({"TLS_CN": "foo", "HTTP_Server": "nginx"})
        self.assertIn("TLS_CN=foo", s)
        self.assertIn("HTTP_Server=nginx", s)
        self.assertIn(";", s)

    def test_unknown_script_returns_empty(self):
        self.assertEqual(ne.extract_nse_fields("non-existent-script", "abc"), {})

    def test_empty_output_safe(self):
        self.assertEqual(ne.extract_nse_fields("ssl-cert", ""), {})
        self.assertEqual(ne.extract_nse_fields("", "abc"), {})


if __name__ == "__main__":
    unittest.main()
