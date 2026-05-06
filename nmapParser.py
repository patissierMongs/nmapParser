#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nmapParser - 비기술 사용자용 nmap GUI (Windows, Python 표준 라이브러리만 사용).

옵션 관리:
  * `options.xlsx` 파일을 같은 폴더에 두면 그 행들이 GUI 체크박스로 자동 생성됨.
  * 컬럼: 스캔 옵션(라벨), 옵션(nmap 인자), 활성화(0/1).
  * 옵션 컬럼이 `--script` 로 시작하면 NSE 그룹 패널에, 아니면 기본 스캔 옵션 패널에 배치.
  * Excel 에서 행을 추가/제거/편집한 뒤 GUI 의 "옵션 다시 불러오기" 버튼으로 즉시 반영.
  * 파일이 없으면 기본 옵션 셋으로 자동 생성됨.
  * 구버전 `options.csv` 가 있고 `options.xlsx` 가 없으면 자동 마이그레이션 (`options.csv.bak` 으로 백업).
  * **모든 셀이 inline string** 으로 저장돼 `-Pn`, `--version-all` 같은 값도 Excel 에서 수식 해석 안 됨.

핵심 CSV 변환 로직 (이전과 동일):
  * "추측서비스(table)" = nmap-services 파일 룩업 (-sV 미사용시 nmap 의 "기본 추측"과 동급).
  * "확인서비스(probed)" = XML <service>:
       method == "probed" -> name + product + version
       method == "table"  -> name 뒤에 ? (예: 'snapenetio?') = probe 실패
       <service> 요소 없음 -> 빈 문자열
"""

import os
import re
import sys
import csv
import shlex
import ipaddress
import queue
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# 동봉된 xlsx 헬퍼 (stdlib only)
import xlsx_io


# ============================================================ defaults / loaders

OPTIONS_XLSX_NAME = "options.xlsx"
OPTIONS_CSV_NAME = "options.csv"  # 구버전 호환 (자동 마이그레이션 후 .bak 으로 이동)

# (라벨, 옵션, 활성화, 그룹, 상세설명) — options.xlsx 가 없으면 이 셋으로 새로 만들어짐.
# 그룹 == "" → 독립 체크박스. 그룹 != "" → 같은 그룹끼리 라디오 (택 1).
# 상세설명 비어 있으면 툴팁 안 뜸. 채워져 있으면 hover 시 노란 툴팁 표시.
DEFAULT_OPTIONS = [
    ("응답 없는 호스트도 강제로 스캔", "-Pn", "1", "",
     "ICMP/ARP 호스트 디스커버리를 건너뜀. ICMP 차단 호스트 누락 방지. 죽은 IP까지 풀 포트 스윕하므로 시간이 약간 증가하지만 누락은 0."),
    ("DNS 역조회 안 함", "-n", "1", "",
     "PTR 역조회 시도하지 않음. 호스트가 많을수록 시간 단축 효과 큼. 결과에 호스트명이 안 들어가는 단점."),

    # ---- TCP 스캔 타입 (라디오 - 항상 택 1)
    ("SYN", "-sS", "0", "TCP 스캔 타입",
     "Half-open TCP SYN 스캔 (-sS). raw socket 권한(=관리자) 필요. 타겟에 완전한 TCP 연결을 안 만들어 stealth, 빠름. 권한 없으면 nmap이 자동으로 -sT 로 폴백."),
    ("Connect", "-sT", "1", "TCP 스캔 타입",
     "정상 TCP 3-way handshake 완성 (-sT). 일반 사용자 권한으로 가능. 타겟 로그에 connect 흔적이 더 남고 -sS 보다 약간 느림."),
    ("Null", "-sN", "0", "TCP 스캔 타입",
     "TCP 헤더 모든 플래그를 0 으로 보냄 (-sN). RFC 따르는 호스트는 closed 포트에서 RST. 일부 stateless 방화벽 우회. Windows 는 응답 안 해 신뢰성 낮음."),
    ("FIN", "-sF", "0", "TCP 스캔 타입",
     "FIN 플래그만 set 한 패킷 (-sF). closed 포트는 RST, 열린/필터링은 무응답. -sN 과 비슷한 stateless 방화벽 우회 의도."),
    ("Xmas", "-sX", "0", "TCP 스캔 타입",
     "FIN+PSH+URG 동시 set (-sX, 크리스마스 트리). closed 포트는 RST. 일부 IDS/방화벽이 SYN 만 추적할 때 우회."),
    ("ACK", "-sA", "0", "TCP 스캔 타입",
     "ACK 패킷만 보냄 (-sA). open/closed 구분 못 하지만 filtered vs unfiltered 구분 가능. 방화벽 stateful 여부와 룰셋 분석용."),

    # ---- 타이밍 / 속도 (라디오 - 항상 택 1)
    ("T0", "-T0", "0", "속도",
     "Paranoid (-T0). 5분 간격 probe. IDS/IPS 회피용. 65535 포트 스캔 시 며칠 걸림."),
    ("T1", "-T1", "0", "속도",
     "Sneaky (-T1). 15초 간격. IDS 회피용. 일반 점검용으론 너무 느림."),
    ("T2", "-T2", "0", "속도",
     "Polite (-T2). 부하 줄여 타겟에 부담 적음. 호스트가 약하거나 네트워크가 좁을 때."),
    ("T3", "-T3", "0", "속도",
     "Normal (-T3). nmap 기본값. 명시 안 하면 이 속도."),
    ("T4", "-T4", "1", "속도",
     "Aggressive (-T4, 권장). 빠른 LAN/안정적인 회선에서 권장. 일반적인 점검의 표준."),
    ("T5", "-T5", "0", "속도",
     "Insane (-T5). 최고 속도. 패킷 손실/오탐 가능. 정확도보다 시간 절약이 우선일 때만."),

    # ---- 비그룹 옵션
    ("UDP 주요 포트 스캔",
     "-sU -p U:7,53,67,68,69,123,135,137,138,139,161,162,500,514,520,1900,4500,5060,5353,11211", "0", "",
     "UDP 스캔 + 자주 쓰이는 22 포트만. UDP 는 RST 응답이 없어 매우 느림. 포트를 좁힐수록 시간 단축. SNMP, NetBIOS, IKE, SIP 등 식별."),
    ("TCP 모든 포트 (1-65535)", "-p T:1-65535", "0", "",
     "TCP 65535 포트 전부 SYN 보냄. T4 기준 호스트당 5~15분. 전수 점검용. 시간 많이 걸려 일반 점검에선 자주 쓰는 포트만 권장."),
    ("서비스 버전 식별", "-sV", "1", "",
     "open 포트마다 추가 probe 보내 서비스 이름/제품/버전 식별. -sV 안 쓰면 nmap-services 룩업만 — 부정확."),
    ("버전 식별 강도 최대", "--version-all", "1", "",
     "-sV 의 모든 probe 시도 (intensity 9). 식별률 최대화. 시간 30~60% 증가하지만 unknown 포트 대폭 감소."),
    ("재시도 2회", "--max-retries 2", "1", "",
     "응답 없을 때 최대 2회 재전송. 기본 10 에서 줄여 빠르게. WAN 같이 패킷 손실 큰 환경엔 더 늘려야."),
    ("open 포트만 출력", "--open", "1", "",
     "결과에 open 포트만. closed/filtered 출력 안 함. 결과 파일 작아지고 가독성 좋아짐."),
    ("이유 표기", "--reason", "1", "",
     "각 포트의 상태 판정 근거 표시 (syn-ack / no-response / reset 등). 디버깅과 결과 검증에 유용."),
    ("RST 제한 우회", "--defeat-rst-ratelimit", "0", "",
     "Linux tcp_challenge_ack_limit 같은 RST throttle 우회. closed 포트가 timeout 으로 filtered 오인되는 것 방지. 정확도 보호."),
    ("호스트그룹 64", "--min-hostgroup 64", "0", "",
     "한 번에 64개 호스트를 병렬로 스캔. /24 같은 큰 대역 스캔 시 처리량 증가. 메모리/대역폭 더 사용."),
    ("동시 처리 100", "--max-parallelism 100", "0", "",
     "동시 in-flight probe 100개까지. 빠른 네트워크에서 처리량 증가. 너무 높으면 IDS 트리거/패킷 손실."),
    ("Aggressive 모드 (-A)", "-A", "0", "",
     "공격적 옵션 묶음 (-O OS 식별 + -sV + -sC default NSE + --traceroute). 매우 빠르게 정보 모음. 대신 흔적 많아 stealth 불가."),
    ("진행 stats 1분마다 출력 (--stats-every 1m)", "--stats-every 1m", "1", "",
     "1분마다 nmap 이 진행률 stats 라인을 stdout 에 강제로 씀. GUI 로그창이 buffer 때문에 한참 비어 보이는 문제 방지. 끄지 않는 것 권장."),

    # ---- NSE (옵션이 --script 로 시작하면 NSE 패널로 자동 분류)
    ("HTTP 식별", "--script http-headers,http-server-header,http-title", "0", "",
     "HTTP 응답 헤더, 서버 헤더, 페이지 타이틀 추출. 웹 서버 종류와 페이지 정보 빠르게 파악."),
    ("TLS 인증서 식별 (CN/SAN/Issuer)", "--script ssl-cert", "0", "",
     "TLS 인증서의 CN, SAN(Subject Alternative Name), Issuer, Validity 추출. 점검에서 가장 큰 정보 노출 NSE 중 하나 — 인증서가 내부 호스트명을 노출시킴."),
    ("TLS cipher / ALPN 식별", "--script ssl-enum-ciphers,tls-alpn", "0", "",
     "지원 TLS 버전, cipher suite, ALPN 프로토콜 (h2/http/1.1). 약한 cipher 사용 여부 확인용."),
    ("SSH 호스트키", "--script ssh-hostkey", "0", "",
     "SSH 호스트 키 fingerprint (RSA/ECDSA/ED25519) 추출. 호스트 식별 + 키 재사용 탐지."),
    ("SMB 식별", "--script nbstat,smb-os-discovery,smb-protocols,smb-security-mode", "0", "",
     "Windows OS 버전, 도메인, NetBIOS 이름, SMB 버전, 보안 모드 (signing 강제 여부). AD 환경 점검 필수."),
    ("DBMS 식별", "--script ms-sql-info,mysql-info,oracle-tns-version,mongodb-info,redis-info", "0", "",
     "MS-SQL/MySQL/Oracle/MongoDB/Redis 버전과 일부 설정. 인증 안 된 DB 노출 여부도 식별."),
    ("RDP/VNC/AJP 식별", "--script rdp-ntlm-info,rdp-enum-encryption,vnc-info,ajp-headers", "0", "",
     "RDP NTLM 정보 (호스트명/도메인), RDP 암호화 모드, VNC 인증, AJP 헤더. 원격 접속 서비스 점검."),
    ("UDP 응용 식별 (SNMP/IKE/SIP/NTP)", "--script snmp-info,ike-version,sip-methods,ntp-info", "0", "",
     "SNMP community / OID 정보, IKE/IPSec 버전, SIP 지원 method, NTP 서버 정보. UDP 스캔과 함께 써야 의미."),
    ("RPC 정보", "--script rpcinfo", "0", "",
     "Sun RPC (portmapper) 서비스 매핑. NFS, NIS 등 RPC 기반 서비스 식별."),
    ("LDAP/AD 식별", "--script ldap-rootdse", "0", "",
     "LDAP root DSE 정보 추출. AD/LDAP 서버 도메인, naming context, 지원 컨트롤 등."),
    ("raw 응답 캡처 (식별 실패 포트)", "--script fingerprint-strings,banner", "0", "",
     "식별 실패한 포트의 원본 응답 바이트 캡쳐. unknown 서비스를 수동 분석할 때 필수. 결과 파일 커짐."),
]


def write_default_options_xlsx(path):
    """options.xlsx 가 없을 때 기본값으로 새 파일 작성 (모든 셀 shared string)."""
    rows = [["스캔 옵션", "옵션", "활성화", "그룹", "상세설명"]]
    for label, option, enabled, group, desc in DEFAULT_OPTIONS:
        rows.append([label, option, enabled, group, desc])
    # 컬럼 폭
    col_widths = [38, 64, 10, 18, 80]
    xlsx_io.write_xlsx(path, rows, col_widths=col_widths)


def load_options_xlsx(path):
    """
    options.xlsx 파싱.
    리턴: (rows, errors)
       rows = [{"label": str, "option": str, "enabled": bool, "lineno": int}, ...]
       errors = ["사람이 읽는 한글 오류 메시지", ...]
    """
    rows = []
    errors = []
    seen_options = set()
    try:
        all_rows = xlsx_io.read_xlsx(path)
    except (OSError, ET_ParseError, KeyError) as e:
        return [], [f"options.xlsx 를 읽을 수 없음: {e}"]
    except Exception as e:
        return [], [f"options.xlsx 파싱 오류: {e}"]

    if not all_rows:
        return [], ["options.xlsx 가 비어 있습니다."]

    header = all_rows[0]
    if not header or len(header) < 3:
        return [], [f"options.xlsx 의 헤더가 잘못되었습니다 (3개 이상 컬럼 필요): {header}"]
    normalized = [(c or "").strip() for c in header]
    required = ["스캔 옵션", "옵션", "활성화"]
    for idx, req in enumerate(required):
        if len(normalized) <= idx or normalized[idx] != req:
            return [], [f"options.xlsx 헤더 불일치: {idx+1}번째 컬럼은 '{req}' 이어야 합니다. (현재: '{normalized[idx] if len(normalized)>idx else ''}')"]

    for i, row in enumerate(all_rows[1:], start=2):
        if not row or all(not (c or "").strip() for c in row):
            continue
        if len(row) < 3:
            errors.append(f"{i}번째 행: 컬럼 부족 (3개 이상 필요) — {row}")
            continue
        label = (row[0] or "").strip()
        option = (row[1] or "").strip()
        enabled_raw = (row[2] or "").strip()
        # 그룹 컬럼은 선택적 (4번째 컬럼)
        group = (row[3] or "").strip() if len(row) >= 4 else ""
        # 상세설명도 선택적 (5번째 컬럼) — strip 안 함, 줄바꿈 보존
        desc = (row[4] or "") if len(row) >= 5 else ""
        if not label:
            errors.append(f"{i}번째 행: '스캔 옵션' 라벨이 비어 있음 — {row}")
            continue
        if len(label) > 120:
            errors.append(f"{i}번째 행: '스캔 옵션' 라벨이 너무 깁니다 (최대 120자) — '{label[:40]}...'")
            continue
        if not option:
            errors.append(f"{i}번째 행: '옵션' 컬럼이 비어 있음 — '{label}'")
            continue
        if len(option) > 512:
            errors.append(f"{i}번째 행: '옵션' 값이 너무 깁니다 (최대 512자) — '{label}'")
            continue
        if enabled_raw not in ("0", "1"):
            errors.append(f"{i}번째 행: '활성화' 값이 0/1 이 아님 — '{enabled_raw}' (행: {row})")
            continue
        if option in seen_options:
            errors.append(f"{i}번째 행: 중복된 옵션 — '{option}' (이전 행에 이미 있음)")
            continue
        seen_options.add(option)
        rows.append({
            "label": label,
            "option": option,
            "enabled": enabled_raw == "1",
            "group": group,
            "desc": desc,
            "lineno": i,
        })
    return rows, errors


def migrate_csv_to_xlsx(csv_path, xlsx_path):
    """구버전 options.csv (3컬럼) 가 있고 xlsx 가 없을 때 마이그레이션.
    성공 시 csv 는 .bak 으로 이동. 그룹/상세설명 컬럼은 빈 문자열로 채움.
    리턴: (success: bool, message: str)"""
    rows = [["스캔 옵션", "옵션", "활성화", "그룹", "상세설명"]]
    try:
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)  # 첫 줄(헤더) 버림
            for row in reader:
                if not row or all(not (c or "").strip() for c in row):
                    continue
                row = [(c or "").strip() for c in row]
                while len(row) < 5:
                    row.append("")
                rows.append(row[:5])
    except OSError as e:
        return False, f"options.csv 읽기 실패: {e}"
    try:
        xlsx_io.write_xlsx(xlsx_path, rows, col_widths=[38, 64, 10, 18, 80])
    except OSError as e:
        return False, f"options.xlsx 쓰기 실패: {e}"
    # 백업 이동
    try:
        bak = csv_path + ".bak"
        if os.path.exists(bak):
            os.remove(bak)
        os.rename(csv_path, bak)
        return True, f"options.csv 를 options.xlsx 로 변환했습니다.\n원본은 {os.path.basename(bak)} 으로 백업되었습니다."
    except OSError:
        return True, "options.xlsx 로 변환 완료. (원본 csv 는 백업하지 못함)"


# ET_ParseError 동의어 (위 try/except 가독성)
ET_ParseError = ET.ParseError


# ============================================================ nmap helpers

def find_nmap_exe():
    """기본 위치 -> 동봉 폴더 순으로 nmap.exe 탐색."""
    here = _app_dir()
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.join(here, "nmap.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def parse_nmap_services(nmap_exe_path):
    """
    nmap 설치 폴더의 nmap-services 파일을 파싱.
    포맷: <name> <port>/<proto> <frequency> [aliases...]
    같은 (port, proto) 에 여러 엔트리가 있으면 frequency 가장 높은 이름을 채택.
    리턴: {(port_int, proto_str): name_str}
    """
    if not nmap_exe_path:
        return {}
    nmap_dir = os.path.dirname(nmap_exe_path)
    services_file = os.path.join(nmap_dir, "nmap-services")
    if not os.path.isfile(services_file):
        return {}
    table = {}  # (port, proto) -> (name, freq)
    try:
        with open(services_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                port_proto = parts[1]
                if "/" not in port_proto:
                    continue
                port_str, proto = port_proto.split("/", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                freq = 0.0
                if len(parts) >= 3:
                    try:
                        freq = float(parts[2])
                    except ValueError:
                        freq = 0.0
                key = (port, proto)
                if key not in table or freq > table[key][1]:
                    table[key] = (name, freq)
    except OSError:
        return {}
    return {k: v[0] for k, v in table.items()}


def _quote_win(s):
    """Windows cmd 스타일 인용 (공백/특수문자 포함 시)."""
    if s and not re.search(r"[\s\"<>|&^]", s):
        return s
    return '"' + s.replace('"', '\\"') + '"'


@dataclass
class ValidationIssue:
    code: str
    field: str
    message: str
    hint: str = ""


@dataclass
class ValidationResult:
    valid_items: list = field(default_factory=list)
    invalid_items: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    issues: list = field(default_factory=list)

    @property
    def ok(self):
        return not self.invalid_items and not self.issues


def format_user_error(title, cause, action, details=None):
    msg = f"원인: {cause}\n해결: {action}"
    if details:
        msg += f"\n상세:\n{details}"
    return title, msg


OPTION_CONFLICT_PREFIXES = [
    ("-sS", "-sT"),
    ("-sS", "-sN"),
    ("-sS", "-sF"),
    ("-sS", "-sX"),
    ("-sS", "-sA"),
    ("-sT", "-sN"),
    ("-sT", "-sF"),
    ("-sT", "-sX"),
    ("-sT", "-sA"),
    ("-sN", "-sF"),
    ("-sN", "-sX"),
    ("-sN", "-sA"),
    ("-sF", "-sX"),
    ("-sF", "-sA"),
    ("-sX", "-sA"),
]


def _app_dir():
    """앱 베이스 폴더.
    - 일반 Python 실행 시: 이 .py 파일이 있는 폴더
    - PyInstaller onefile (.exe) 실행 시: .exe 가 있는 폴더 (sys.executable)
      (`__file__` 은 임시 _MEI 폴더를 가리켜 options.xlsx 가 사라지므로 우회)
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


# ============================================================ tooltip

class Tooltip:
    """위젯에 마우스 호버 시 노란 박스 툴팁 표시. 빈 텍스트면 아예 바인딩 안 함."""
    def __init__(self, widget, text, delay=250, wraplength=420):
        self.widget = widget
        self.text = (text or "").strip()
        self.delay = delay
        self.wraplength = wraplength
        self.tip = None
        self.after_id = None
        if not self.text:
            return
        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")

    def _on_enter(self, _e=None):
        self._cancel_after()
        self.after_id = self.widget.after(self.delay, self._show)

    def _on_leave(self, _e=None):
        self._cancel_after()
        self._hide()

    def _cancel_after(self):
        if self.after_id:
            try:
                self.widget.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None

    def _show(self):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 24
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        try:
            self.tip.wm_overrideredirect(True)
        except Exception:
            pass
        self.tip.wm_geometry(f"+{x}+{y}")
        # 약간 그림자 느낌의 테두리
        outer = tk.Frame(self.tip, bg="#a0a000")
        outer.pack()
        label = tk.Label(
            outer, text=self.text,
            bg="#fffbcc", fg="#222",
            relief="flat", justify="left",
            wraplength=self.wraplength,
            font=("Segoe UI", 9), padx=8, pady=5,
        )
        label.pack(padx=1, pady=1)

    def _hide(self):
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None


# ============================================================ main app

class NmapParserApp:
    def __init__(self, root):
        self.root = root
        root.title("nmapParser - nmap GUI (한글)")
        # 산업 표준 데스크톱 productivity 툴 가이드라인 — 1280x860 기본 (3:2 비율).
        # 화면 작으면 축소(비율 유지), 크면 MAX 까지만.
        TARGET_W, TARGET_H = 1280, 760
        MIN_W, MIN_H = 1000, 660
        MAX_W, MAX_H = 1400, 860
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()

        window_w = max(MIN_W, min(TARGET_W, sw - 100))
        window_h = max(MIN_H, min(TARGET_H, sh - 100))
        # 화면이 매우 좁으면 폭 기준으로 비율 유지 축소
        if sw - 100 < TARGET_W:
            scale = (sw - 100) / TARGET_W
            window_h = max(MIN_H, int(TARGET_H * scale))

        root.geometry(f"{window_w}x{window_h}")
        root.minsize(MIN_W, MIN_H)

        # 1280px 기준 panel 폭 ~620px → 한 cell 200~220px → 3 col 적정
        self.panel_cols = 3

        here = _app_dir()
        self.options_xlsx_path = os.path.join(here, OPTIONS_XLSX_NAME)
        self.options_csv_path = os.path.join(here, OPTIONS_CSV_NAME)  # 구버전 호환
        self.option_rows = []     # 옵션 파일에서 읽은 행
        self.option_vars = []     # [{"kind", "var", "row", "group"}, ...]
        self.group_vars = {}      # group_name -> StringVar

        self.nmap_exe = find_nmap_exe()
        self.services_table = parse_nmap_services(self.nmap_exe) if self.nmap_exe else {}

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_folder = tk.StringVar(value=os.path.join(here, ts))

        self.scan_thread = None
        self.proc = None
        self.output_prefix = None
        self._log_file = None         # 전체 로그 파일 핸들 (.log)
        self._log_file_path = None    # 마지막 .log 경로 (스캔 끝나도 보존 — '전체 로그 보기' 용)
        self._log_lines_since_trim = 0
        self._log_max_lines = 275  # 화면에 표시할 최대 줄 수 (rolling buffer)
        self._log_queue = queue.Queue()
        self._log_pump_after_id = None
        self._log_pump_interval_ms = 120
        self._log_batch_limit = 120

        self._build_static_ui()
        self._reload_options(initial=True)
        self._refresh_nmap_button()

    def _make_scrollable_panel(self, parent, title):
        """LabelFrame + 내부 Canvas + Scrollbar + Inner Frame 구조 생성.
        리턴: (outer_frame_to_pack, inner_frame_to_use_as_parent)"""
        outer = tk.LabelFrame(parent, text=title)
        canvas = tk.Canvas(outer, borderwidth=0, highlightthickness=0)
        vbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)
        vbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_config(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_inner_config)

        def _on_canvas_config(e):
            # 내부 frame 폭을 canvas 폭과 동기화 (가로 스크롤 안 생기게)
            canvas.itemconfigure(win_id, width=e.width)
        canvas.bind("<Configure>", _on_canvas_config)

        # 마우스 휠 — 콘텐츠가 canvas 보다 길 때만 스크롤 (짧으면 skip)
        def _on_wheel(e):
            try:
                bbox = canvas.bbox("all")
                if bbox is None:
                    return
                content_h = bbox[3] - bbox[1]
                canvas_h = canvas.winfo_height()
                if content_h <= canvas_h:
                    return  # 콘텐츠가 화면에 다 들어옴 — 스크롤 불필요
                canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
            except Exception:
                pass
        def _bind_wheel(_e=None):
            canvas.bind_all("<MouseWheel>", _on_wheel)
        def _unbind_wheel(_e=None):
            canvas.unbind_all("<MouseWheel>")
        canvas.bind("<Enter>", _bind_wheel)
        canvas.bind("<Leave>", _unbind_wheel)
        inner.bind("<Enter>", _bind_wheel)
        inner.bind("<Leave>", _unbind_wheel)

        return outer, inner

    # ----------------------------- 정적 UI (옵션 패널 외 모든 것)
    def _build_static_ui(self):
        # 0. nmap 탐지
        top = tk.Frame(self.root)
        top.pack(fill="x", padx=8, pady=(8, 4))
        self.nmap_button = tk.Button(top, text="", command=self._select_nmap_exe,
                                     anchor="w", font=("Segoe UI", 9, "bold"),
                                     padx=8, pady=4)
        self.nmap_button.pack(fill="x")

        # 출력 폴더
        out = tk.Frame(self.root)
        out.pack(fill="x", padx=8, pady=2)
        tk.Label(out, text="출력 폴더:").pack(side="left")
        tk.Entry(out, textvariable=self.output_folder).pack(side="left", fill="x", expand=True, padx=4)
        tk.Button(out, text="출력 폴더 변경", command=self._choose_output_folder).pack(side="left", padx=2)
        tk.Button(out, text="폴더 열기", command=self._open_output_folder).pack(side="left", padx=2)

        # 1. 타겟 — 텍스트박스 (height=2) + 우측 버튼 vertical stack
        tgt_frame = tk.LabelFrame(self.root,
            text="타겟 (여러 줄/공백 구분 — IP, CIDR, 호스트명)")
        tgt_frame.pack(fill="x", padx=8, pady=4)
        tgt_inner = tk.Frame(tgt_frame)
        tgt_inner.pack(fill="x", padx=4, pady=4)
        self.targets_text = scrolledtext.ScrolledText(tgt_inner, height=2, font=("Consolas", 10))
        self.targets_text.pack(side="left", fill="both", expand=True)
        tgt_btns = tk.Frame(tgt_inner)
        tgt_btns.pack(side="right", padx=(6, 0), fill="y")
        tk.Button(tgt_btns, text="📁 파일에서 불러오기",
                  command=self._load_targets_file).pack(fill="x", pady=1)
        tk.Button(tgt_btns, text="🗑 비우기",
                  command=lambda: self.targets_text.delete("1.0", "end")).pack(fill="x", pady=1)

        # 2. 옵션/로그 PanedWindow — 옵션 (상단) / 컨트롤+로그 (하단)
        # PanedWindow 안에 paned 의 panes 만 add 가능. 컨트롤 줄들은 PanedWindow 밖에 둬도 되지만
        # 사용자 워크플로 (옵션 → 컨트롤 → 로그) 자연스럽게 하려면 컨트롤은 paned 밖에 배치.
        self.paned = tk.PanedWindow(self.root, orient="vertical",
                                    sashrelief="raised", sashwidth=6, bg="#cccccc")
        # paned 는 _build_static_ui 끝부분에서 pack — 컨트롤들을 먼저 paned 위에 배치하기 위해.

        # ---- 상단 pane: 옵션 (좌: 기본, 우: NSE) — 둘 다 scrollable.
        # height=320 — 옵션 panel 이 화면의 큰 비중 차지하게.
        mid = tk.Frame(self.paned)
        self.paned.add(mid, minsize=200, stretch="always", height=320)

        opts_outer, self.opts_frame = self._make_scrollable_panel(
            mid, "기본 스캔 옵션 (options.xlsx 기반)")
        opts_outer.pack(side="left", fill="both", expand=True, padx=(0, 4))

        nse_outer, self.nse_frame = self._make_scrollable_panel(
            mid, "NSE 식별 스크립트 (options.xlsx 의 --script 행)")
        nse_outer.pack(side="left", fill="both", expand=True, padx=(4, 0))

        # paned.pack 은 함수 끝에서 (모든 bottom 위젯 packed 후 잉여 공간 차지하게).

        # 4. 옵션 관리 버튼 줄
        opt_mgr = tk.Frame(self.root)
        tk.Button(opt_mgr, text="옵션 다시 불러오기", command=lambda: self._reload_options(initial=False),
                  bg="#fff3e0").pack(side="left", padx=2)
        tk.Button(opt_mgr, text="options.xlsx 열기 (Excel)",
                  command=self._open_options_xlsx).pack(side="left", padx=2)
        tk.Button(opt_mgr, text="options.xlsx 폴더 열기",
                  command=lambda: subprocess.Popen(["explorer.exe", "/select,", self.options_xlsx_path])).pack(side="left", padx=2)
        self.options_status = tk.Label(opt_mgr, text="", fg="#555")
        self.options_status.pack(side="left", padx=12)

        # 5. 고급: 사용자 입력 포트 + 추가 스크립트
        adv = tk.LabelFrame(self.root, text="고급 입력 (CSV 옵션과 별개로 추가 적용됨)")

        port_row = tk.Frame(adv)
        port_row.pack(fill="x", padx=4, pady=2)
        tk.Label(port_row, text="사용자 입력 포트 (예: 22,80,443,1-1024 — 비우면 미사용):", width=44, anchor="w").pack(side="left")
        self.custom_ports = tk.StringVar(value="")
        tk.Entry(port_row, textvariable=self.custom_ports).pack(side="left", fill="x", expand=True)
        tk.Label(port_row, text="(입력 시 CSV 의 -p 옵션을 덮어씀)", fg="#888").pack(side="left", padx=4)

        nse_row = tk.Frame(adv)
        nse_row.pack(fill="x", padx=4, pady=2)
        tk.Label(nse_row, text="추가 NSE 스크립트 (콤마 구분, 비우면 미사용):", width=44, anchor="w").pack(side="left")
        self.custom_nse = tk.StringVar(value="")
        tk.Entry(nse_row, textvariable=self.custom_nse).pack(side="left", fill="x", expand=True)

        # 6. CSV 변환
        csv_frame = tk.LabelFrame(self.root, text="결과 CSV 변환")
        self.csv_convert = tk.BooleanVar(value=True)
        self.csv_open_only = tk.BooleanVar(value=True)
        tk.Checkbutton(csv_frame, text="CSV 로 변환", variable=self.csv_convert).pack(side="left", padx=6, pady=2)
        tk.Checkbutton(csv_frame, text="open 포트만 CSV 에 포함", variable=self.csv_open_only).pack(side="left", padx=6, pady=2)
        tk.Label(csv_frame, text=
                 "  CSV 컬럼: IP, PORT, 포트상태, 추측서비스(table), 확인서비스(probed), NSE스크립트명, 스크립트출력",
                 fg="#555").pack(side="left", padx=4)

        # 7. 실행 버튼
        run = tk.Frame(self.root)
        self.run_button = tk.Button(run, text="▶ 스캔 시작", command=self._run_scan,
                                    bg="#1e88e5", fg="white",
                                    font=("Segoe UI", 11, "bold"),
                                    padx=14, pady=4)
        self.run_button.pack(side="left", padx=2)
        self.stop_button = tk.Button(run, text="■ 중지", command=self._stop_scan,
                                     state="disabled", padx=10, pady=4)
        self.stop_button.pack(side="left", padx=2)
        tk.Button(run, text="명령 미리보기", command=self._preview_command, padx=10, pady=4).pack(side="left", padx=2)
        tk.Button(run, text="전체 로그 보기 (.log)", command=self._open_full_log, padx=10, pady=4).pack(side="left", padx=2)

        # 7. 로그 — PanedWindow 하단에 배치 (사용자가 sash 끌어 크기 조절)
        log_frame = tk.LabelFrame(self.paned, text="실시간 nmap 출력 (최근 275줄. 전체는 .log 파일)")
        # height=110 — 시각적으로 작은 영역 (사용자가 sash 끌어 늘릴 수 있음)
        self.paned.add(log_frame, minsize=70, stretch="always", height=110)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=5, bg="#0d1117",
                                                  fg="#e6edf3", insertbackground="white",
                                                  font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, padx=2, pady=2)

        # 8. 상태 바
        self.status_var = tk.StringVar(value="대기 중")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              anchor="w", relief="sunken", padx=6)

        # 9. ─── 명시적 pack 순서 (Layout buggability 방지) ───
        # bottom 부터 쌓아올림. side="bottom" widgets 는 호출 순서 = 아래→위.
        # status 가장 아래, run 그 위, csv → adv → opt_mgr 순.
        # 마지막에 paned (side=top, expand=True) 가 위쪽 잉여 공간 모두 차지.
        status_bar.pack(side="bottom", fill="x")
        run.pack(side="bottom", fill="x", padx=8, pady=(4, 2))
        csv_frame.pack(side="bottom", fill="x", padx=8, pady=2)
        adv.pack(side="bottom", fill="x", padx=8, pady=2)
        opt_mgr.pack(side="bottom", fill="x", padx=8, pady=2)
        self.paned.pack(side="top", fill="both", expand=True, padx=8, pady=(0, 4))

    # ----------------------------- options.xlsx 로딩 & 동적 패널
    def _reload_options(self, initial=False):
        # 1) xlsx 가 없을 때:
        #    - 구버전 csv 가 있으면 자동 마이그레이션
        #    - 없으면 기본값으로 새 xlsx 생성
        if not os.path.isfile(self.options_xlsx_path):
            if os.path.isfile(self.options_csv_path):
                ok, msg = migrate_csv_to_xlsx(self.options_csv_path, self.options_xlsx_path)
                if ok:
                    messagebox.showinfo("옵션 파일 마이그레이션", msg)
                else:
                    messagebox.showerror("마이그레이션 실패",
                        f"options.csv → options.xlsx 변환 실패.\n{msg}\n"
                        "options.csv 를 직접 확인하거나 삭제 후 다시 시작하세요.")
                    return
            else:
                try:
                    write_default_options_xlsx(self.options_xlsx_path)
                except OSError as e:
                    messagebox.showerror("options.xlsx 생성 실패",
                        f"기본 옵션 파일을 만들 수 없습니다.\n원인: {e}\n경로: {self.options_xlsx_path}")
                    return

        rows, errors = load_options_xlsx(self.options_xlsx_path)
        if errors:
            messagebox.showwarning(
                "options.xlsx 일부 행 무시",
                "다음 항목은 잘못되어 무시되었습니다:\n\n" +
                "\n".join("• " + e for e in errors) +
                "\n\n해결: Excel 로 options.xlsx 를 열어 해당 행을 수정 후 '옵션 다시 불러오기'.")
        if not rows:
            messagebox.showerror("options.xlsx 비어 있음",
                f"옵션 행이 하나도 없습니다.\n경로: {self.options_xlsx_path}\n"
                "해결: Excel 로 options.xlsx 를 열어 행을 추가하거나 파일을 삭제 후 '옵션 다시 불러오기' (기본값으로 자동 재생성).")
            return

        self.option_rows = rows
        self._rebuild_option_panels()
        # 옵션 row 수 기반 창 크기 동적 조정 (옵션이 많아지면 화면 한계까지 늘어남)
        self._apply_dynamic_size()
        msg = f"옵션 {len(rows)}개 로드됨 — {self.options_xlsx_path}"
        self.options_status.config(text=msg)
        if not initial:
            self.status_var.set(f"옵션 다시 불러옴 ({len(rows)}개)")

    def _rebuild_option_panels(self):
        """
        패널 재구성 — 두 pass:
        Pass 1: 라디오 그룹 LabelFrame (panel 위쪽, columnspan=4, 내부 가로 pack).
        Pass 2: 독립 체크박스 4 column grid (라디오 다음 row 부터).
        """
        for child in self.opts_frame.winfo_children():
            child.destroy()
        for child in self.nse_frame.winfo_children():
            child.destroy()
        self.option_vars = []
        self.group_vars = {}

        N_COLS = getattr(self, "panel_cols", 4)  # 화면 폭 기반 자동 결정 (2~6)

        # parent 별로 옵션 분류
        panel_rows = {self.opts_frame: [], self.nse_frame: []}
        for row in self.option_rows:
            parent = self.nse_frame if row["option"].startswith("--script") else self.opts_frame
            panel_rows[parent].append(row)

        group_seen_enabled = {}
        duplicate_warnings = []

        for parent, rows in panel_rows.items():
            # column weight 균등
            for c in range(N_COLS):
                parent.grid_columnconfigure(c, weight=1, uniform=f"opts_{id(parent)}")

            next_grid_row = 0

            # Pass 1: 라디오 그룹 LabelFrame (항상 1개 선택, ✕ 해제 없음)
            radio_strips = {}            # group -> radio_strip Frame
            group_first_option = {}      # group -> 첫번째 행의 option (활성=1 없을 때 폴백)
            for row in rows:
                if not row["group"]:
                    continue
                group = row["group"]
                if group not in radio_strips:
                    lf = tk.LabelFrame(parent, text=f"{group} (택 1)", fg="#1565c0")
                    lf.grid(row=next_grid_row, column=0, columnspan=N_COLS,
                            sticky="ew", padx=2, pady=(2, 4))
                    next_grid_row += 1
                    radio_strip = tk.Frame(lf)
                    radio_strip.pack(fill="x", padx=4, pady=2)
                    radio_strips[group] = radio_strip
                    self.group_vars[group] = tk.StringVar(value="")

                radio_strip = radio_strips[group]
                if group not in group_first_option:
                    group_first_option[group] = row["option"]

                if row["enabled"]:
                    if group in group_seen_enabled:
                        duplicate_warnings.append(
                            f"그룹 '{group}': 활성=1 행이 여러 개 — "
                            f"'{group_seen_enabled[group]}' 와 '{row['label']}'. 첫 번째만 적용."
                        )
                    else:
                        group_seen_enabled[group] = row["label"]
                        self.group_vars[group].set(row["option"])

                rb = tk.Radiobutton(
                    radio_strip, text=row["label"],
                    variable=self.group_vars[group], value=row["option"],
                )
                rb.pack(side="left", padx=4)
                if row.get("desc"):
                    Tooltip(rb, row["desc"])
                self.option_vars.append({
                    "kind": "radio", "var": self.group_vars[group],
                    "row": row, "group": group,
                })

            # 활성=1 없는 그룹은 첫 번째 옵션으로 폴백 (라디오는 항상 1개 선택 상태 보장)
            for group, first_opt in group_first_option.items():
                if group not in group_seen_enabled:
                    self.group_vars[group].set(first_opt)

            # Pass 2: 독립 체크박스 4 column grid
            cb_idx = 0
            for row in rows:
                if row["group"]:
                    continue
                v = tk.BooleanVar(value=row["enabled"])
                cb_row = next_grid_row + cb_idx // N_COLS
                cb_col = cb_idx % N_COLS
                cb = tk.Checkbutton(parent, text=row["label"], variable=v, anchor="w")
                cb.grid(row=cb_row, column=cb_col, sticky="w", padx=4, pady=1)
                if row.get("desc"):
                    Tooltip(cb, row["desc"])
                cb_idx += 1
                self.option_vars.append({"kind": "checkbox", "var": v, "row": row, "group": ""})

        if duplicate_warnings:
            messagebox.showwarning("그룹 중복 활성화",
                "\n".join("• " + w for w in duplicate_warnings) +
                "\n\n해결: Excel 에서 options.xlsx 의 같은 '그룹' 값 행 중 하나만 '활성화=1' 로 두세요.")

    def _clear_group(self, group):
        """라디오 그룹 선택 해제 — 그 그룹은 명령에 포함되지 않음."""
        if group in self.group_vars:
            self.group_vars[group].set("")

    def _calc_window_size(self):
        """옵션 row 수 기반 적정 창 크기 계산.
        옵션 늘어나면 화면 한계까지 height 확장 → 한계 도달 후에야 scrollbar 의미.
        리턴: (width, height)"""
        import math
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()

        basic_cb = sum(1 for r in self.option_rows
                       if not r["group"] and not r["option"].startswith("--script"))
        nse_cb = sum(1 for r in self.option_rows
                     if not r["group"] and r["option"].startswith("--script"))
        panel_cols = max(1, getattr(self, "panel_cols", 3))
        left_rows = math.ceil(basic_cb / panel_cols) if basic_cb else 0
        right_rows = math.ceil(nse_cb / panel_cols) if nse_cb else 0
        panel_rows = max(left_rows, right_rows, 1)
        panel_needed = panel_rows * 32 + 60  # checkbox row(32px) + LabelFrame title/padding

        radio_groups_basic = len({r["group"] for r in self.option_rows
                                  if r["group"] and not r["option"].startswith("--script")})
        radio_groups_nse = len({r["group"] for r in self.option_rows
                                if r["group"] and r["option"].startswith("--script")})
        radio_rows = max(radio_groups_basic, radio_groups_nse)
        radio_area = radio_rows * 60 + 10

        target_area = 80
        log_area = 110
        control_strip_total = 30 + 60 + 30 + 50  # opt_mgr + adv(2 rows) + csv + run
        status_bar = 25
        chrome_pad = 80

        ideal_h = chrome_pad + radio_area + target_area + panel_needed + log_area + control_strip_total + status_bar

        available_h = sh - 100
        final_h = min(ideal_h, available_h)
        final_h = max(700, final_h)

        final_w = min(1280, sw - 100)
        final_w = max(1000, final_w)
        return int(final_w), int(final_h)

    def _apply_dynamic_size(self):
        try:
            w, h = self._calc_window_size()
            self.root.geometry(f"{w}x{h}")
        except Exception:
            pass

    def _open_full_log(self):
        """가장 최근 스캔의 .log 파일을 시스템 기본 텍스트 뷰어로 엶."""
        if not self._log_file_path or not os.path.isfile(self._log_file_path):
            messagebox.showinfo("로그 없음",
                "아직 저장된 .log 파일이 없습니다.\n스캔을 한 번 돌리면 출력 폴더에 `<타겟>_<시각>.log` 가 생깁니다.")
            return
        try:
            os.startfile(self._log_file_path)  # type: ignore
        except OSError as e:
            messagebox.showerror("열기 실패", f"파일을 열 수 없음: {e}\n경로: {self._log_file_path}")

    def _open_options_xlsx(self):
        if not os.path.isfile(self.options_xlsx_path):
            try:
                write_default_options_xlsx(self.options_xlsx_path)
            except OSError as e:
                messagebox.showerror("열기 실패", f"파일을 만들 수 없습니다: {e}")
                return
        try:
            os.startfile(self.options_xlsx_path)  # type: ignore
        except OSError as e:
            messagebox.showerror("열기 실패",
                f"파일 연결 프로그램으로 열 수 없습니다.\n원인: {e}\n경로: {self.options_xlsx_path}")

    # ----------------------------- nmap detect button
    def _refresh_nmap_button(self):
        if self.nmap_exe and os.path.isfile(self.nmap_exe):
            self.nmap_button.config(
                text=f"  ✓ nmap 설치 확인됨: {self.nmap_exe}   (클릭하면 다른 nmap.exe 직접 선택)",
                bg="#2e7d32", fg="white", activebackground="#388e3c")
        else:
            self.nmap_button.config(
                text="  ✗ nmap 설치 안 됨 — 클릭해서 nmap.exe 직접 선택",
                bg="#c62828", fg="white", activebackground="#d32f2f")

    def _select_nmap_exe(self):
        path = filedialog.askopenfilename(
            title="nmap.exe 위치 선택",
            filetypes=[("nmap.exe", "nmap.exe"), ("모든 실행 파일", "*.exe")],
        )
        if path:
            if not os.path.isfile(path):
                messagebox.showerror("오류", f"파일이 존재하지 않습니다:\n{path}")
                return
            self.nmap_exe = path
            self.services_table = parse_nmap_services(self.nmap_exe)
            self._refresh_nmap_button()

    # ----------------------------- output folder
    def _choose_output_folder(self):
        folder = filedialog.askdirectory(title="출력 폴더 선택",
                                         initialdir=self.output_folder.get() or os.getcwd())
        if folder:
            self.output_folder.set(folder)

    def _open_output_folder(self):
        folder = self.output_folder.get()
        if os.path.isdir(folder):
            subprocess.Popen(["explorer.exe", folder])
        else:
            messagebox.showinfo("폴더 없음",
                f"폴더가 아직 만들어지지 않았습니다:\n{folder}\n"
                "스캔을 한 번 돌리면 자동 생성됩니다.")

    # ----------------------------- targets
    def _load_targets_file(self):
        path = filedialog.askopenfilename(
            title="타겟 파일 선택 (.txt - 한 줄에 하나)",
            filetypes=[("텍스트 파일", "*.txt"), ("모든 파일", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as e:
            messagebox.showerror("파일 읽기 실패",
                f"파일을 읽지 못했습니다.\n원인: {e}\n해결: 파일 경로/권한을 확인하세요.")
            return
        cur = self.targets_text.get("1.0", "end").strip()
        if cur:
            self.targets_text.insert("end", "\n" + content)
        else:
            self.targets_text.insert("end", content)

    def _gather_targets(self):
        raw = self.targets_text.get("1.0", "end").strip()
        if not raw:
            return []
        items = []
        for line in raw.splitlines():
            for part in line.split():
                part = part.strip()
                if part:
                    items.append(part)
        return items

    def _is_valid_hostname(self, host):
        if not host or len(host) > 253:
            return False
        labels = host.rstrip(".").split(".")
        if not labels:
            return False
        label_re = re.compile(r"^[A-Za-z0-9-]{1,63}$")
        for label in labels:
            if not label or not label_re.match(label):
                return False
            if label[0] == "-" or label[-1] == "-":
                return False
        return True

    def validate_targets(self, items):
        result = ValidationResult()
        seen = set()
        for raw in items:
            token = (raw or "").strip()
            if not token:
                continue
            if token in seen:
                result.warnings.append(f"중복 타깃 제거: {token}")
                continue
            seen.add(token)
            try:
                if "/" in token:
                    ipaddress.ip_network(token, strict=False)
                else:
                    ipaddress.ip_address(token)
                result.valid_items.append(token)
                continue
            except ValueError:
                pass
            if self._is_valid_hostname(token):
                result.valid_items.append(token)
            else:
                result.invalid_items.append(token)
                result.issues.append(ValidationIssue(
                    code="INVALID_TARGET",
                    field="targets",
                    message=f"유효하지 않은 타깃 형식: {token}",
                    hint="IP/CIDR/호스트명 형식을 확인하세요."
                ))
        return result

    def _gather_active_rows(self):
        """현재 체크된 체크박스 + 라디오 그룹의 선택된 행을 모아 리턴 (CSV 순서 유지)."""
        active = []
        # 그룹별 현재 선택값
        group_selected = {g: var.get() for g, var in self.group_vars.items()}
        seen_groups = set()  # 같은 그룹 행이 여러 번 추가되는 것 방지
        for entry in self.option_vars:
            row = entry["row"]
            if entry["kind"] == "checkbox":
                if entry["var"].get():
                    active.append(row)
            elif entry["kind"] == "radio":
                group = entry["group"]
                if group in seen_groups:
                    continue
                sel = group_selected.get(group, "")
                if sel and sel == row["option"]:
                    active.append(row)
                    seen_groups.add(group)
                # else: 이 행은 선택 안 됨 — 다음 행도 같은 그룹이면 이어서 매칭
        return active

    def parse_option_rows_to_tokens(self, rows):
        extra_tokens = []
        nse_scripts = []
        for row in rows:
            opt = row["option"]
            try:
                tokens = shlex.split(opt)
            except ValueError as e:
                messagebox.showwarning("옵션 파싱 경고",
                    f"options.xlsx {row['lineno']}번째 행의 옵션을 파싱하지 못했습니다.\n"
                    f"원인: {e}\n옵션: {opt}\n이 행은 무시됩니다.")
                continue
            if not tokens:
                continue
            if tokens[0] == "--script":
                if len(tokens) >= 2:
                    for s in tokens[1].split(","):
                        s = s.strip()
                        if s:
                            nse_scripts.append(s)
            elif tokens[0].startswith("--script="):
                val = tokens[0][len("--script="):]
                for s in val.split(","):
                    s = s.strip()
                    if s:
                        nse_scripts.append(s)
            else:
                extra_tokens.extend(tokens)
        return extra_tokens, nse_scripts

    def apply_custom_ports(self, extra_tokens, user_port):
        if not user_port:
            return extra_tokens
        cleaned = []
        skip_next = False
        for t in extra_tokens:
            if skip_next:
                skip_next = False
                continue
            if t == "-p":
                skip_next = True
                continue
            if t.startswith("-p"):
                continue
            cleaned.append(t)
        if re.match(r"^[\d,\- ]+$", user_port):
            cleaned.extend(["-p", f"T:{user_port}"])
        else:
            cleaned.extend(["-p", user_port])
        return cleaned

    def sanitize_output_args(self, extra_tokens):
        cleaned = []
        skip_next = False
        for t in extra_tokens:
            if skip_next:
                skip_next = False
                continue
            if t == "-oA" or t == "-oX" or t == "-oN" or t == "-oG":
                skip_next = True
                continue
            cleaned.append(t)
        return cleaned

    def merge_nse_scripts(self, base_scripts, custom_nse_raw):
        nse_scripts = list(base_scripts)
        custom_nse = (custom_nse_raw or "").strip()
        if custom_nse:
            for s in custom_nse.split(","):
                s = s.strip()
                if s:
                    nse_scripts.append(s)
        seen = set()
        uniq = []
        for s in nse_scripts:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return uniq

    def validate_option_conflicts(self, extra_tokens):
        result = ValidationResult(valid_items=list(extra_tokens))
        token_set = set(extra_tokens)
        for a, b in OPTION_CONFLICT_PREFIXES:
            if a in token_set and b in token_set:
                result.issues.append(ValidationIssue(
                    code="OPTION_CONFLICT",
                    field="options",
                    message=f"충돌 옵션 동시 선택: {a} + {b}",
                    hint="TCP 스캔 타입은 하나만 선택하세요."
                ))
        return result

    def _show_validation_error(self, title, cause, action, invalid_items=None):
        details = None
        if invalid_items:
            details = "\n".join(f"- {x}" for x in invalid_items[:10])
        t, msg = format_user_error(title, cause, action, details=details)
        messagebox.showerror(t, msg)

    # ----------------------------- 명령 조립
    def _build_command(self, targets):
        if not self.nmap_exe:
            return None
        cmd = [self.nmap_exe]
        active_rows = self._gather_active_rows()
        extra_tokens, nse_scripts = self.parse_option_rows_to_tokens(active_rows)
        conflicts = self.validate_option_conflicts(extra_tokens)
        if conflicts.issues:
            self._show_validation_error(
                "옵션 충돌 오류",
                "상호 배타 옵션이 동시에 선택되었습니다.",
                "TCP 스캔 타입 옵션을 하나만 선택하세요.",
                invalid_items=[i.message for i in conflicts.issues]
            )
            return None
        extra_tokens = self.apply_custom_ports(extra_tokens, self.custom_ports.get().strip())
        extra_tokens = self.sanitize_output_args(extra_tokens)
        cmd.extend(extra_tokens)
        merged_nse = self.merge_nse_scripts(nse_scripts, self.custom_nse.get())
        if merged_nse:
            cmd.extend(["--script", ",".join(merged_nse)])

        # 출력 prefix — 항상 -oA (CSV 변환에 XML 필요)
        try:
            self.output_prefix = self._build_output_prefix(targets)
        except OSError as e:
            raise OSError(f"출력 폴더 생성 실패: {e}")
        cmd.extend(["-oA", self.output_prefix])

        cmd.extend(targets)
        return cmd

    def _build_output_prefix(self, targets):
        folder = self.output_folder.get()
        os.makedirs(folder, exist_ok=True)
        first = targets[0] if targets else "scan"
        safe = re.sub(r'[\\/:*?"<>|]', "_", first)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{safe}_{ts}"
        candidate = os.path.join(folder, base)
        i = 2
        while any(os.path.exists(candidate + ext) for ext in (".nmap", ".xml", ".gnmap", ".csv")):
            candidate = os.path.join(folder, f"{base}_{i}")
            i += 1
        return candidate

    def _preview_command(self):
        gathered = self._gather_targets()
        if not gathered:
            messagebox.showinfo("미리보기", "타겟이 비어 있습니다.")
            return
        v = self.validate_targets(gathered)
        if v.invalid_items:
            self._show_validation_error(
                "미리보기",
                "타깃 형식 오류가 있습니다.",
                "IP/CIDR/호스트명 형식으로 수정하세요.",
                invalid_items=v.invalid_items
            )
            return
        targets = v.valid_items
        if not self.nmap_exe:
            messagebox.showerror("미리보기", "nmap 경로가 잘못되었습니다.")
            return
        try:
            cmd = self._build_command(targets)
        except OSError as e:
            messagebox.showerror("미리보기 실패", str(e))
            return
        if cmd is None:
            messagebox.showerror("미리보기", "명령 조립 실패.")
            return
        quoted = " ".join(_quote_win(p) for p in cmd)
        win = tk.Toplevel(self.root)
        win.title("실행될 nmap 명령")
        win.geometry("980x320")
        txt = scrolledtext.ScrolledText(win, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("end", quoted)

    # ----------------------------- run / stop
    def _run_scan(self):
        gathered = self._gather_targets()
        if not gathered:
            messagebox.showerror("오류",
                "타겟이 비어 있습니다.\n위쪽 텍스트박스에 IP/CIDR/호스트명을 입력하거나 '파일에서 불러오기' 사용.")
            return
        v = self.validate_targets(gathered)
        if v.invalid_items:
            self._show_validation_error(
                "오류",
                "유효하지 않은 타깃이 포함되어 스캔을 시작할 수 없습니다.",
                "IP/CIDR/호스트명 형식으로 수정 후 다시 시도하세요.",
                invalid_items=v.invalid_items
            )
            return
        targets = v.valid_items
        if not self.nmap_exe or not os.path.isfile(self.nmap_exe):
            messagebox.showerror("오류",
                "nmap 경로가 잘못되었습니다.\n상단 빨간 버튼을 클릭해서 nmap.exe 경로를 직접 지정하세요.")
            return
        try:
            cmd = self._build_command(targets)
        except OSError as e:
            messagebox.showerror("출력 폴더 생성 실패",
                f"폴더를 만들 수 없습니다.\n원인: {e}\n해결: 권한 또는 경로를 확인하세요.")
            return
        if cmd is None:
            messagebox.showerror("오류", "명령 조립 실패.")
            return

        self.log_text.delete("1.0", "end")
        self._log_lines_since_trim = 0
        while True:
            try:
                self._log_queue.get_nowait()
            except queue.Empty:
                break

        # 전체 로그 파일 open (.log)
        self._log_file_path = (self.output_prefix or "scan") + ".log"
        try:
            self._log_file = open(self._log_file_path, "w", encoding="utf-8", buffering=1)
        except OSError as e:
            self._log_file = None
            messagebox.showwarning("로그 파일 쓰기 실패",
                f"전체 로그 파일을 열지 못함: {e}\n로그창에는 출력되지만 .log 파일 저장 안 됨.")

        cmd_str = " ".join(_quote_win(p) for p in cmd)
        header = f"[명령] {cmd_str}\n\n"
        self.log_text.insert("end", header)
        self.log_text.see("end")
        if self._log_file:
            try:
                self._log_file.write(header)
                self._log_file.flush()
            except OSError:
                pass

        self.run_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set("스캔 진행 중...")
        self._start_log_pump()

        self.scan_thread = threading.Thread(target=self._scan_worker, args=(cmd,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, cmd):
        try:
            kwargs = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
            )
            if sys.platform == "win32":
                kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
            self.proc = subprocess.Popen(cmd, **kwargs)
            for line in self.proc.stdout:
                self._log_queue.put(line)
            self.proc.wait()
            rc = self.proc.returncode
            self.root.after(0, self._scan_done, rc)
        except FileNotFoundError as e:
            self.root.after(0, self._scan_error,
                f"nmap 실행 실패 (파일 없음): {e}\n해결: nmap 경로를 다시 지정하세요.")
        except PermissionError as e:
            self.root.after(0, self._scan_error,
                f"nmap 실행 권한 없음: {e}\n"
                "해결: 관리자 권한으로 실행하거나 -sS 대신 -sT 옵션 (CSV의 'TCP Connect 스캔') 사용.")
        except Exception as e:
            self.root.after(0, self._scan_error, f"예상치 못한 오류: {e}")

    def _append_log(self, line):
        self.log_text.insert("end", line)
        self.log_text.see("end")
        # 전체 로그 파일에도 동시에 기록 (디스크에 풀 로그 보존)
        if self._log_file:
            try:
                self._log_file.write(line)
                self._log_file.flush()
            except OSError:
                pass
        # rolling buffer — 일정 라인 수 누적될 때마다 정리
        self._log_lines_since_trim += 1
        if self._log_lines_since_trim >= 25:
            self._log_lines_since_trim = 0
            try:
                total = int(self.log_text.index("end-1c").split(".")[0])
                if total > self._log_max_lines + 25:
                    cut = total - self._log_max_lines
                    self.log_text.delete("1.0", f"{cut}.0")
                    self.log_text.insert(
                        "1.0",
                        f"... [상단 {cut - 1} 줄 잘림 — 전체 로그는 .log 파일 참조] ...\n"
                    )
            except Exception:
                pass

    def _append_log_batch(self, lines):
        if not lines:
            return
        merged = "".join(lines)
        self.log_text.insert("end", merged)
        self.log_text.see("end")
        if self._log_file:
            try:
                self._log_file.write(merged)
                self._log_file.flush()
            except OSError:
                pass
        self._log_lines_since_trim += len(lines)
        if self._log_lines_since_trim >= 25:
            self._log_lines_since_trim = 0
            try:
                total = int(self.log_text.index("end-1c").split(".")[0])
                if total > self._log_max_lines + 25:
                    cut = total - self._log_max_lines
                    self.log_text.delete("1.0", f"{cut}.0")
                    self.log_text.insert(
                        "1.0",
                        f"... [상단 {cut - 1} 줄 잘림 — 전체 로그는 .log 파일 참조] ...\n"
                    )
            except Exception:
                pass

    def _start_log_pump(self):
        if self._log_pump_after_id is not None:
            return
        self._log_pump_after_id = self.root.after(self._log_pump_interval_ms, self._pump_log_queue)

    def _pump_log_queue(self):
        self._log_pump_after_id = None
        lines = []
        for _ in range(self._log_batch_limit):
            try:
                lines.append(self._log_queue.get_nowait())
            except queue.Empty:
                break
        if lines:
            self._append_log_batch(lines)
        if (self.proc and self.proc.poll() is None) or (not self._log_queue.empty()):
            self._log_pump_after_id = self.root.after(self._log_pump_interval_ms, self._pump_log_queue)

    def _stop_scan(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.status_var.set("중지 요청됨...")
            except Exception:
                pass

    def _close_log_file(self):
        if self._log_file:
            try:
                self._log_file.close()
            except OSError:
                pass
            self._log_file = None

    def _scan_error(self, msg):
        self.run_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("스캔 오류")
        self._close_log_file()
        messagebox.showerror("스캔 오류", msg)

    def _scan_done(self, rc):
        self.run_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self._close_log_file()

        files_made = []
        for ext in (".nmap", ".xml", ".gnmap"):
            p = (self.output_prefix or "") + ext
            if os.path.isfile(p):
                files_made.append(p)

        if rc != 0 and not files_made:
            self.status_var.set(f"스캔 종료 (코드 {rc}) — 출력 없음")
            messagebox.showerror("스캔 실패",
                f"nmap 종료 코드: {rc}\n출력 파일이 만들어지지 않았습니다.\n위 로그 창에서 오류 메시지 확인.")
            return

        if self.csv_convert.get():
            xml_path = (self.output_prefix or "") + ".xml"
            if os.path.isfile(xml_path):
                try:
                    csv_path = self._convert_to_csv(xml_path)
                    if csv_path:
                        files_made.append(csv_path)
                except ET.ParseError as e:
                    messagebox.showerror("XML 파싱 실패",
                        f"nmap XML 파일을 읽지 못했습니다.\n원인: {e}\n해결: 스캔이 정상 종료됐는지 확인.")
                except OSError as e:
                    messagebox.showerror("CSV 쓰기 실패",
                        f"CSV 파일을 쓰지 못했습니다.\n원인: {e}\n해결: 디스크 공간/권한 확인.")
            else:
                self._append_log(f"\n[경고] XML 파일이 없어 CSV 변환을 건너뜀: {xml_path}\n")

        self.status_var.set(f"완료 — 파일 {len(files_made)}개 생성")
        list_txt = "\n".join("  " + os.path.basename(p) for p in files_made) or "  (없음)"
        ans = messagebox.askyesno("완료",
            f"스캔 완료. 파일 {len(files_made)}개 생성됨.\n\n"
            f"폴더: {self.output_folder.get()}\n\n{list_txt}\n\n폴더를 열까요?")
        if ans:
            self._open_output_folder()

    # ----------------------------- CSV 변환 (이전과 동일 로직)
    def _convert_to_csv(self, xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        rows = []
        open_only = self.csv_open_only.get()

        for host in root.findall("host"):
            addr = ""
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    addr = a.get("addr", "")
                    break
            if not addr:
                for a in host.findall("address"):
                    if a.get("addrtype") in ("ipv6", "mac"):
                        addr = a.get("addr", "")
                        break
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port in ports_el.findall("port"):
                portid = port.get("portid", "")
                proto = port.get("protocol", "")
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if open_only and state != "open":
                    continue
                try:
                    portnum = int(portid)
                except ValueError:
                    portnum = 0
                guessed = self.services_table.get((portnum, proto), "")
                svc_el = port.find("service")
                if svc_el is not None:
                    name = svc_el.get("name", "") or ""
                    method = svc_el.get("method", "") or ""
                    product = svc_el.get("product", "") or ""
                    version = svc_el.get("version", "") or ""
                    extrainfo = svc_el.get("extrainfo", "") or ""
                    if method == "probed":
                        merged = " ".join(p for p in (name, product, version, extrainfo) if p)
                        probed = merged.strip()
                    elif method == "table":
                        probed = f"{name}?" if name else ""
                    else:
                        probed = name
                else:
                    probed = ""
                scripts = port.findall("script")
                if not scripts:
                    rows.append([addr, portid, state, guessed, probed, "", ""])
                else:
                    for sc in scripts:
                        sid = sc.get("id", "") or ""
                        out = (sc.get("output", "") or "").replace("\r", " ").replace("\n", " | ")
                        rows.append([addr, portid, state, guessed, probed, sid, out])

        csv_path = (self.output_prefix or "") + ".csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP", "PORT", "포트상태", "추측서비스(table)", "확인서비스(probed)",
                        "NSE스크립트명", "스크립트출력"])
            for r in rows:
                w.writerow(r)
        return csv_path


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    NmapParserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
