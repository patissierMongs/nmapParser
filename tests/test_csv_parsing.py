# -*- coding: utf-8 -*-
"""실제 nmap XML 케이스에서 발견된 NSE 파싱 / CSV 컬럼 매핑 결함 회귀 방지.

각 테스트는 v0.4.1 까지 잘못 동작했던 케이스를 reproduce 한 다음
v0.4.2 fix 가 정상 처리하는지 검증.
"""

import csv
import os
import tempfile
import unittest

import nmapParser as np


def _write_xml(path, body):
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            '<?xml version="1.0"?>\n<nmaprun scanner="nmap">\n'
            + body
            + '\n</nmaprun>'
        )


class CsvParsingRegressionTests(unittest.TestCase):
    def _convert(self, xml_body):
        td = tempfile.mkdtemp()
        xml_path = os.path.join(td, "scan.xml")
        csv_path = os.path.join(td, "scan.csv")
        _write_xml(xml_path, xml_body)
        np.convert_xml_to_csv_standalone(xml_path, csv_path)
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            rdr = csv.reader(f)
            headers = next(rdr)
            rows = [dict(zip(headers, r)) for r in rdr]
        return rows

    # ---------- Bug C: probed-honest lookup (no leak from guessed)
    def test_lookup_probed_honest_no_guessed_leak(self):
        """probed=nagios-nsca, port=5432 (guessed postgresql) — categories 에 nagios-nsca
        가 없으므로 분류/위험도/노출위험은 빈 칸 또는 미분류. postgresql 데이터가
        leak 되면 안 됨. v0.4.1 까지 postgresql 의 '위험도 상 / scram-sha-256 미적용...'
        이 nagios-nsca 행에 붙던 버그.
        """
        body = '''<host><address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="5432"><state state="open"/>
<service name="nagios-nsca" product="Nagios NSCA" version="9.6.0 or later" method="probed"/>
</port></ports></host>'''
        rows = self._convert(body)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["확인서비스(short)"], "nagios-nsca")
        self.assertEqual(r["분류"], "미분류",
            "probed=nagios-nsca 인데 guessed=postgresql 의 분류가 leak 됨 (Bug C)")
        self.assertEqual(r["위험도"], "")
        self.assertNotIn("scram-sha-256", r.get("노출위험", ""),
            "postgresql 노출위험 텍스트가 nagios-nsca 행으로 leak 됨 (Bug C)")

    # ---------- Bug D: HTTPS auto-promotion (port 443 + tls scripts)
    def test_https_auto_promotion_port_443(self):
        """port 443 + service.name=http (TLS inner 식별 케이스). ssl-cert/ssl-enum-ciphers
        NSE 도 있으면 lookup 키를 'https' 로 승격해 암호화 컬럼을 TLS 로 표시해야.
        v0.4.1 까지 http 키 매칭으로 '암호화=평문' 으로 잘못 표시.
        """
        body = '''<host><address addr="10.0.0.2" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="http" product="nginx" version="1.27.5" method="probed"/>
<script id="ssl-cert" output="Subject: commonName=test"/>
<script id="ssl-enum-ciphers" output="TLSv1.2"/>
</port></ports></host>'''
        rows = self._convert(body)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertNotEqual(r["암호화"], "평문",
            "port 443 + ssl-cert 인데 '평문' 으로 분류됨 (Bug D)")
        # https 카테고리는 보통 웹 + TLS 관련 표현 포함
        self.assertIn("TLS", r["노출위험"] + r["암호화"],
            "HTTPS 자동 승격이 안돼 TLS 관련 텍스트가 노출위험·암호화 컬럼에 없음 (Bug D)")

    def test_http_port_80_remains_plain(self):
        """포트 80 (TLS 흔적 없음) 은 정상 http 그대로 — 잘못된 승격 회귀 방지."""
        body = '''<host><address addr="10.0.0.3" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache" version="2.4" method="probed"/>
</port></ports></host>'''
        rows = self._convert(body)
        self.assertEqual(rows[0]["암호화"], "평문")

    # ---------- Bug E: HTML entity decode
    def test_html_entity_decoded_in_nse_output(self):
        """nmap XML 의 <script output="..."> 안에 numeric character reference
        (&#8211; 등) 가 그대로 들어가는 경우. v0.4.1 까지 디코드 안 돼서
        '&#8211;' 가 CSV 에 그대로 들어가던 케이스 (Blocky HTB http-title).
        """
        body = '''<host><address addr="10.0.0.4" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache" method="probed"/>
<script id="http-title" output="BlockyCraft &amp;#8211; Under Construction!"/>
</port></ports></host>'''
        rows = self._convert(body)
        r = rows[0]
        # &#8211; (en-dash) 가 실제 문자 '–' 로 디코드돼야 함
        joined = r["스크립트출력"] + r["NSE추출"] + r["비고"]
        self.assertNotIn("&#8211;", joined,
            "HTML entity (&#8211;) 가 디코드 안 되고 CSV 에 그대로 들어감 (Bug E)")

    # ---------- Bug F: remarks ≠ detail (no duplicate)
    def test_remarks_does_not_duplicate_detail(self):
        """NSE 없을 때 비고 컬럼이 detail 그대로 복사되던 버그.
        비고는 NSE 요약 전용 — NSE 없으면 빈 칸이어야 함.
        """
        body = '''<host><address addr="10.0.0.5" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="10.2" method="probed"/>
</port></ports></host>'''
        rows = self._convert(body)
        r = rows[0]
        self.assertIn("OpenSSH", r["상세(제품/버전)"])
        self.assertEqual(r["비고"], "",
            "NSE 없는 행의 비고가 detail 을 중복함 (Bug F)")

    def test_remarks_has_nse_key_only(self):
        """NSE 있을 때 비고에는 NSE key-line 만 (detail 중복 없이)."""
        body = '''<host><address addr="10.0.0.6" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="nginx" version="1.27" method="probed"/>
<script id="http-title" output="Hello"/>
</port></ports></host>'''
        rows = self._convert(body)
        r = rows[0]
        # 비고에 NSE 핵심 (title) 은 있어도 detail (nginx 1.27) 은 중복 X
        self.assertIn("Hello", r["비고"] + r["NSE추출"])
        # 비고가 detail 그대로 시작하면 중복 — 회귀 신호
        self.assertFalse(r["비고"].startswith("nginx 1.27"),
            "비고가 detail 로 시작 — 중복 (Bug F regression)")


if __name__ == "__main__":
    unittest.main()
