# -*- coding: utf-8 -*-
"""NSE 스크립트 출력 → 핵심 필드 dict 추출.

지원 19개 (사용자 phase1 명령 기준):
  ssl-cert / ssl-enum-ciphers / tls-alpn /
  http-headers / http-server-header / http-title /
  ssh-hostkey /
  smb-os-discovery / smb-protocols / nbstat /
  rdp-ntlm-info /
  ms-sql-info / oracle-tns-version /
  snmp-info / ike-version / sip-methods / ntp-info /
  rpcinfo / fingerprint-strings

리턴: {"필드명": "값", ...}. 못 찾으면 빈 dict.
"""

import re


_RE_CN = re.compile(r"commonName=([^/\n,]+)", re.IGNORECASE)
_RE_SAN = re.compile(r"Subject Alternative Name:\s*([^\n]+)", re.IGNORECASE)
_RE_ISSUER_CN = re.compile(r"Issuer:[^\n]*?commonName=([^/\n,]+)", re.IGNORECASE)
_RE_NOT_BEFORE = re.compile(r"Not valid before:\s*([^\n]+)", re.IGNORECASE)
_RE_NOT_AFTER = re.compile(r"Not valid after:\s*([^\n]+)", re.IGNORECASE)
_RE_KEY_BITS = re.compile(r"Public Key bits:\s*(\d+)", re.IGNORECASE)


def _extract_ssl_cert(out):
    fields = {}
    m = _RE_CN.search(out)
    if m:
        fields["TLS_CN"] = m.group(1).strip()
    m = _RE_SAN.search(out)
    if m:
        san = m.group(1).strip()
        # "DNS:foo.com, DNS:bar.com" → "foo.com; bar.com"
        san = re.sub(r"DNS:", "", san)
        san = ";".join(p.strip() for p in re.split(r"[,]", san) if p.strip())
        fields["TLS_SAN"] = san
    m = _RE_ISSUER_CN.search(out)
    if m:
        fields["TLS_Issuer"] = m.group(1).strip()
    m = _RE_NOT_BEFORE.search(out)
    if m:
        fields["TLS_NotBefore"] = m.group(1).strip()
    m = _RE_NOT_AFTER.search(out)
    if m:
        fields["TLS_NotAfter"] = m.group(1).strip()
    m = _RE_KEY_BITS.search(out)
    if m:
        fields["TLS_KeyBits"] = m.group(1).strip()
    # Self-signed: Subject CN == Issuer CN
    cn = fields.get("TLS_CN", "")
    issuer = fields.get("TLS_Issuer", "")
    if cn and issuer:
        fields["TLS_SelfSigned"] = "Y" if cn == issuer else "N"
    return fields


def _extract_ssl_enum_ciphers(out):
    fields = {}
    versions = []
    for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        if re.search(rf"{re.escape(v)}:", out):
            versions.append(v)
    if versions:
        fields["TLS_Versions"] = ",".join(versions)
    # 가장 약한 grade — least letter
    grades = re.findall(r"least strength:\s*([A-F])", out)
    if grades:
        # 알파벳상 가장 큰 글자 = 가장 약함
        fields["TLS_Strength"] = max(grades)
    return fields


def _extract_tls_alpn(out):
    fields = {}
    # tls-alpn output 예: "  h2\n  http/1.1\n"
    protos = []
    for m in re.finditer(r"^\s+([a-zA-Z0-9.\-/]+)\s*$", out, re.MULTILINE):
        v = m.group(1).strip()
        if v and v not in protos:
            protos.append(v)
    if protos:
        fields["TLS_ALPN"] = ",".join(protos)
    return fields


def _extract_http_server(out):
    fields = {}
    m = re.search(r"Server:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["HTTP_Server"] = m.group(1).strip()
    m = re.search(r"X-Powered-By:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["HTTP_Powered"] = m.group(1).strip()
    return fields


def _extract_http_server_header(out):
    fields = {}
    # http-server-header 의 output 은 보통 "Apache/2.4.58" 한 줄
    line = (out or "").strip().splitlines()
    if line:
        first = line[0].strip()
        if first and not first.lower().startswith("error"):
            fields["HTTP_Server"] = first
    return fields


def _extract_http_title(out):
    fields = {}
    line = (out or "").strip().splitlines()
    if line:
        title = line[0].strip()
        if title and "doesn't have a title" not in title.lower():
            if len(title) > 80:
                title = title[:77] + "..."
            fields["HTTP_Title"] = title
    return fields


def _extract_ssh_hostkey(out):
    """SSH host key 핑거프린트 추출.
    nmap 출력에 따라 SHA256 형태 (`SHA256:base64`) 또는 MD5 형태
    (`xx:xx:...` hex pairs) 둘 다 나옴. 결과 키를 라벨로 정확히 구분:
      - SHA256:접두사 있으면 SSH_FP_SHA256
      - hex colon-pairs 면 SSH_FP_MD5 (전통적 MD5 fingerprint)
    """
    fields = {}
    types = []
    sha256_fp = ""
    md5_fp = ""
    for m in re.finditer(r"\d+\s+(SHA256:\S+|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5,})\s*\(([A-Za-z0-9_\-]+)\)", out):
        fp = m.group(1)
        kt = m.group(2)
        if kt and kt.lower() not in [t.lower() for t in types]:
            types.append(kt.lower())
        if fp.startswith("SHA256:") and not sha256_fp:
            sha256_fp = fp
        elif ":" in fp and not fp.startswith("SHA256:") and not md5_fp:
            md5_fp = fp
    if types:
        fields["SSH_KeyTypes"] = ",".join(types)
    if sha256_fp:
        fields["SSH_FP_SHA256"] = sha256_fp
    if md5_fp:
        fields["SSH_FP_MD5"] = md5_fp
    return fields


def _extract_smb_os_discovery(out):
    fields = {}
    m = re.search(r"OS:\s*([^\n]+?)(?:\s*\(.*?\))?$", out, re.MULTILINE | re.IGNORECASE)
    if m:
        fields["SMB_OS"] = m.group(1).strip()
    m = re.search(r"Computer name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["SMB_Computer"] = m.group(1).strip()
    m = re.search(r"Domain name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["SMB_Domain"] = m.group(1).strip()
    m = re.search(r"FQDN:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["SMB_FQDN"] = m.group(1).strip()
    m = re.search(r"Workgroup:\s*([^\n]+)", out, re.IGNORECASE)
    if m and "SMB_Domain" not in fields:
        fields["SMB_Domain"] = m.group(1).strip()
    return fields


def _extract_smb_protocols(out):
    fields = {}
    dialects = []
    for m in re.finditer(r"^\s+([0-9.]+|NT LM 0\.12)\s*$", out, re.MULTILINE):
        d = m.group(1).strip()
        if d and d not in dialects:
            dialects.append(d)
    if dialects:
        fields["SMB_Dialects"] = ",".join(dialects)
    # SMB1 활성
    has_v1 = bool(re.search(r"NT LM 0\.12|SMBv1|SMB1", out, re.IGNORECASE))
    fields["SMB_HasV1"] = "Y" if has_v1 else "N"
    return fields


def _extract_nbstat(out):
    fields = {}
    m = re.search(r"NetBIOS name:\s*([^\s,]+)", out, re.IGNORECASE)
    if m:
        fields["NetBIOS_Computer"] = m.group(1).strip()
    m = re.search(r"NetBIOS user:\s*([^\s,]+)", out, re.IGNORECASE)
    if m and m.group(1).strip() != "<unknown>":
        fields["NetBIOS_User"] = m.group(1).strip()
    m = re.search(r"NetBIOS MAC:\s*([0-9a-fA-F:]+)", out, re.IGNORECASE)
    if m:
        fields["NetBIOS_MAC"] = m.group(1).strip()
    return fields


def _extract_rdp_ntlm(out):
    fields = {}
    m = re.search(r"DNS_Domain_Name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["NTLM_Domain"] = m.group(1).strip()
    m = re.search(r"DNS_Computer_Name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["NTLM_Computer"] = m.group(1).strip()
    m = re.search(r"Product_Version:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["NTLM_OS_Build"] = m.group(1).strip()
    m = re.search(r"NetBIOS_Computer_Name:\s*([^\n]+)", out, re.IGNORECASE)
    if m and "NTLM_Computer" not in fields:
        fields["NTLM_Computer"] = m.group(1).strip()
    return fields


def _extract_ms_sql_info(out):
    fields = {}
    m = re.search(r"Version:\s*\n\s*name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["MSSQL_Version"] = m.group(1).strip()
    else:
        m = re.search(r"Version:\s*([^\n]+)", out, re.IGNORECASE)
        if m:
            fields["MSSQL_Version"] = m.group(1).strip()
    m = re.search(r"Instance name:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["MSSQL_Instance"] = m.group(1).strip()
    return fields


def _extract_oracle_tns(out):
    fields = {}
    m = re.search(r"Version:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["Oracle_Version"] = m.group(1).strip()
    return fields


def _extract_snmp_info(out):
    fields = {}
    m = re.search(r"sysDescr\.\d+\s*=\s*([^\n]+)|sysDescr:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["SNMP_sysDescr"] = (m.group(1) or m.group(2)).strip()
    m = re.search(r"community:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["SNMP_Community"] = m.group(1).strip()
    return fields


def _extract_ike_version(out):
    fields = {}
    if re.search(r"IKEv2", out):
        fields["IKE_Version"] = "v2"
    elif re.search(r"IKEv1|aggressive", out, re.IGNORECASE):
        fields["IKE_Version"] = "v1"
    return fields


def _extract_sip_methods(out):
    fields = {}
    m = re.search(r"Methods?:?\s*([A-Z, ]+)", out, re.IGNORECASE)
    if m:
        methods = re.split(r"[,\s]+", m.group(1).strip())
        methods = [x for x in methods if x]
        if methods:
            fields["SIP_Methods"] = ",".join(methods)
    return fields


def _extract_ntp_info(out):
    fields = {}
    m = re.search(r"stratum:\s*(\d+)|stratum=(\d+)", out, re.IGNORECASE)
    if m:
        fields["NTP_Stratum"] = (m.group(1) or m.group(2)).strip()
    m = re.search(r"reference id:\s*([^\n]+)|refid:\s*([^\n]+)", out, re.IGNORECASE)
    if m:
        fields["NTP_RefId"] = (m.group(1) or m.group(2)).strip()
    return fields


def _extract_rpcinfo(out):
    fields = {}
    progs = []
    for m in re.finditer(r"(\d+)\s+(\d+)\s+(?:tcp|udp)\s+\d+\s+(\S+)", out):
        prog = m.group(3)
        ver = m.group(2)
        token = f"{prog}={ver}"
        if token not in progs:
            progs.append(token)
        if len(progs) >= 5:
            break
    if progs:
        fields["RPC_Programs"] = ",".join(progs)
    return fields


def _extract_fingerprint_strings(out):
    """nmap 의 fingerprint-strings 출력에서 의미있는 첫 응답 라인 추출.

    nmap 출력 형태:
        |  FourOhFourRequest, GetRequest, OfficeScan, ...:
        |    HTTP/1.0 200 OK
        |    Content-Type: text/plain
        |    ...

    첫 줄은 nmap 의 probe **이름** 들 (콤마 + 콜론 끝). 우리가 원하는 건 그 다음
    들여쓰기된 실제 응답 바이트. 이전 구현이 첫 비어있지 않은 라인을 무조건
    Raw_FirstLine 으로 잡아서 probe name 리스트를 결과로 보여주는 버그가 있었음.

    이번 구현은:
      1) `<probe-names>:` 헤더 라인 skip (콜론으로 끝나는 한 줄)
      2) 그 다음 줄 (들여쓰기 더 깊은 raw 응답) 캡쳐
      3) 못 찾으면 빈 dict (fingerprint-strings 가 떴다는 자체가 nmap 의 식별
         실패 신호 — 굳이 leak 시키지 않음)
    """
    fields = {}
    lines = (out or "").splitlines()
    saw_probe_header = False
    for raw in lines:
        s = raw.strip().lstrip("|_ ").strip()
        if not s:
            continue
        # 첫 줄: probe 이름들 + ':' 로 끝남 — skip 하고 다음 줄을 캡쳐 대상으로.
        if not saw_probe_header and s.endswith(":") and "," in s:
            saw_probe_header = True
            continue
        # 한 줄에 probe 이름이 콤마 여러 개 + 콜론 끝 형태면 skip
        if s.endswith(":") and len(s.split(",")) >= 2:
            continue
        if s.lower().startswith(("fingerprint-strings", "if you know")):
            continue
        # 너무 짧으면 의미 없음
        if len(s) < 4:
            continue
        if len(s) > 80:
            s = s[:77] + "..."
        fields["Raw_FirstLine"] = s
        break
    return fields


# Script-id → extractor 함수 매핑
_EXTRACTORS = {
    "ssl-cert": _extract_ssl_cert,
    "ssl-enum-ciphers": _extract_ssl_enum_ciphers,
    "tls-alpn": _extract_tls_alpn,
    "http-headers": _extract_http_server,
    "http-server-header": _extract_http_server_header,
    "http-title": _extract_http_title,
    "ssh-hostkey": _extract_ssh_hostkey,
    "smb-os-discovery": _extract_smb_os_discovery,
    "smb-protocols": _extract_smb_protocols,
    "nbstat": _extract_nbstat,
    "rdp-ntlm-info": _extract_rdp_ntlm,
    "ms-sql-info": _extract_ms_sql_info,
    "oracle-tns-version": _extract_oracle_tns,
    "snmp-info": _extract_snmp_info,
    "ike-version": _extract_ike_version,
    "sip-methods": _extract_sip_methods,
    "ntp-info": _extract_ntp_info,
    "rpcinfo": _extract_rpcinfo,
    "fingerprint-strings": _extract_fingerprint_strings,
}


def extract_nse_fields(script_id, output):
    """단일 NSE 스크립트 출력에서 핵심 필드 추출. 못 찾으면 빈 dict."""
    if not output or not script_id:
        return {}
    fn = _EXTRACTORS.get(script_id.lower())
    if fn is None:
        return {}
    try:
        return fn(output) or {}
    except Exception:
        return {}


def extract_all_nse(nse_data):
    """[(script_id, output), ...] → 모든 추출 필드를 합친 단일 dict.
    같은 키 중복 시 첫 값 유지 (예: http-server-header 가 우선)."""
    merged = {}
    for sid, out in (nse_data or []):
        if not sid:
            continue
        fields = extract_nse_fields(sid, out)
        for k, v in fields.items():
            if k not in merged and v:
                merged[k] = v
    return merged


def format_nse_summary(merged):
    """추출 dict → 한 줄 'key=value; key=value' 포맷 (CSV 한 셀용)."""
    if not merged:
        return ""
    return "; ".join(f"{k}={v}" for k, v in merged.items())
