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
  * **모든 셀이 shared string** 으로 저장돼 `-Pn`, `--version-all` 같은 값도 Excel 에서 수식 해석 안 됨.

핵심 CSV 변환 로직 (이전과 동일):
  * "추측서비스(table)" = nmap-services 파일 룩업 (-sV 미사용시 nmap 의 "기본 추측"과 동급).
  * "확인서비스(probed)" = XML <service>:
       method == "probed" -> name + product + version
       method == "table"  -> name 뒤에 ? (예: 'snapenetio?') = probe 실패
       <service> 요소 없음 -> 빈 문자열
"""

import os
import argparse
import glob
import hashlib
import re
import sys
import csv
import shlex
import ipaddress
import locale
import queue
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# 동봉된 xlsx 헬퍼 (stdlib only)
import xlsx_io

# NSE 스크립트 출력에서 핵심 필드(TLS_CN, SMB_OS, NTLM_Computer ...) 를 추출하는 헬퍼.
# 모듈이 없거나 import 실패해도 도구 동작은 멈추지 않고 NSE추출 컬럼만 빈 칸으로 둔다.
try:
    import nse_extract  # type: ignore
except Exception:
    nse_extract = None  # type: ignore


# ============================================================ defaults / loaders

OPTIONS_XLSX_NAME = "options.xlsx"
OPTIONS_CSV_NAME = "options.csv"  # 구버전 호환 (자동 마이그레이션 후 .bak 으로 이동)
CATEGORIES_XLSX_NAME = "categories.xlsx"


# ============================================================ categories
# (서비스명, 분류, 용도, 설명) — categories.xlsx 가 없으면 이 셋으로 생성.
# 객관적 관찰 분류만 — 권장노출/우선순위/권고 같은 판단은 외부(점검자/사용자)에서.
DEFAULT_CATEGORIES = [
    # 원격 접속
    ("ssh", "원격접속", "관리", "SSH 원격 셸/관리 접속"),
    ("telnet", "원격접속", "관리", "Telnet 평문 원격"),
    ("rdp", "원격접속", "관리", "Microsoft RDP"),
    ("ms-wbt-server", "원격접속", "관리", "Microsoft RDP"),
    ("vnc", "원격접속", "관리", "VNC 원격 화면"),
    ("vnc-http", "원격접속", "관리", "VNC over HTTP"),
    ("xrdp", "원격접속", "관리", "xrdp (Linux RDP)"),
    # 웹 / 프록시
    ("http", "웹", "사용자", "HTTP 웹 서버"),
    ("http-alt", "웹", "사용자", "HTTP 대체 포트"),
    ("https", "웹", "사용자", "HTTPS 암호화 웹"),
    ("https-alt", "웹", "사용자", "HTTPS 대체 포트"),
    ("ssl/http", "웹", "사용자", "HTTPS 암호화 웹"),
    ("ssl/https", "웹", "사용자", "HTTPS 암호화 웹"),
    ("ajp13", "웹", "내부통신", "AJP13 Tomcat 백엔드"),
    ("http-proxy", "프록시", "인프라", "HTTP 프록시 (Squid 등)"),
    ("socks", "프록시", "인프라", "SOCKS 프록시"),
    # 인쇄
    ("ipp", "인쇄", "사용자", "IPP 인쇄 (HTTP 기반)"),
    ("printer", "인쇄", "사용자", "LPD 인쇄"),
    ("lpd", "인쇄", "사용자", "LPD 인쇄"),
    # DBMS
    ("mysql", "DBMS", "시스템", "MySQL/MariaDB"),
    ("mariadb", "DBMS", "시스템", "MariaDB"),
    ("postgresql", "DBMS", "시스템", "PostgreSQL"),
    ("postgres", "DBMS", "시스템", "PostgreSQL"),
    ("mongodb", "DBMS", "시스템", "MongoDB"),
    ("mongo", "DBMS", "시스템", "MongoDB"),
    ("redis", "DBMS", "시스템", "Redis 키-값"),
    ("ms-sql-s", "DBMS", "시스템", "Microsoft SQL Server"),
    ("ms-sql-m", "DBMS", "시스템", "Microsoft SQL Server (monitor)"),
    ("oracle-tns", "DBMS", "시스템", "Oracle TNS Listener"),
    ("elasticsearch", "DBMS", "시스템", "Elasticsearch 검색엔진"),
    ("couchdb", "DBMS", "시스템", "Apache CouchDB"),
    ("neo4j", "DBMS", "시스템", "Neo4j 그래프 DB"),
    ("influxdb", "DBMS", "시스템", "InfluxDB 시계열"),
    ("memcache", "DBMS", "시스템", "Memcached"),
    ("memcached", "DBMS", "시스템", "Memcached"),
    ("cassandra", "DBMS", "시스템", "Cassandra"),
    ("hbase", "DBMS", "시스템", "HBase"),
    # 메시지큐
    ("amqp", "메시지큐", "내부통신", "RabbitMQ AMQP"),
    ("mqtt", "메시지큐", "내부통신", "MQTT"),
    ("nats", "메시지큐", "내부통신", "NATS"),
    ("kafka", "메시지큐", "내부통신", "Kafka"),
    # 메일
    ("smtp", "메일", "시스템", "SMTP 송신"),
    ("submission", "메일", "사용자", "SMTP submission"),
    ("smtps", "메일", "시스템", "SMTPS"),
    ("pop3", "메일", "사용자", "POP3"),
    ("pop3s", "메일", "사용자", "POP3S"),
    ("imap", "메일", "사용자", "IMAP"),
    ("imaps", "메일", "사용자", "IMAPS"),
    # 디렉토리 / 인증
    ("ldap", "디렉토리", "시스템", "LDAP 디렉토리"),
    ("ldaps", "디렉토리", "시스템", "LDAPS"),
    ("kerberos-sec", "인증", "시스템", "Kerberos KDC"),
    ("kpasswd", "인증", "시스템", "Kerberos kpasswd"),
    # DNS
    ("domain", "DNS", "인프라", "DNS"),
    ("dns", "DNS", "인프라", "DNS"),
    # 파일 공유 / 전송
    ("microsoft-ds", "파일공유", "시스템", "SMB Microsoft 파일공유"),
    ("netbios-ssn", "파일공유", "시스템", "NetBIOS Session"),
    ("netbios-ns", "파일공유", "시스템", "NetBIOS Name"),
    ("nbstat", "파일공유", "시스템", "NetBIOS Status"),
    ("nfs", "파일공유", "시스템", "NFS"),
    ("ftp", "파일전송", "사용자", "FTP"),
    ("ftps", "파일전송", "사용자", "FTPS"),
    ("tftp", "파일전송", "시스템", "TFTP"),
    ("sftp", "파일전송", "사용자", "SFTP"),
    # 시간 / 모니터링 / 로그
    ("ntp", "시간동기", "인프라", "NTP"),
    ("snmp", "모니터링", "모니터링", "SNMP"),
    ("snmptrap", "모니터링", "모니터링", "SNMP Trap"),
    ("zabbix-agent", "모니터링", "모니터링", "Zabbix Agent"),
    ("zabbix-trapper", "모니터링", "모니터링", "Zabbix Trapper"),
    ("prometheus", "모니터링", "모니터링", "Prometheus"),
    ("grafana", "모니터링", "사용자", "Grafana"),
    ("syslog", "로그수집", "시스템", "Syslog"),
    ("splunk", "로그분석", "보안", "Splunk"),
    # VPN / VoIP / 미디어
    ("isakmp", "VPN", "시스템", "IKE/IPsec"),
    ("ipsec-nat-t", "VPN", "시스템", "IPsec NAT-T"),
    ("openvpn", "VPN", "시스템", "OpenVPN"),
    ("sip", "VoIP", "사용자", "SIP"),
    ("rtsp", "미디어", "사용자", "RTSP"),
    # 네트워크 검색
    ("ssdp", "네트워크검색", "시스템", "SSDP UPnP"),
    ("upnp", "네트워크검색", "시스템", "UPnP"),
    ("mdns", "네트워크검색", "시스템", "Multicast DNS"),
    # RPC / 관리
    ("msrpc", "RPC", "시스템", "Microsoft RPC"),
    ("rpcbind", "RPC", "시스템", "ONC RPC portmapper"),
    ("sunrpc", "RPC", "시스템", "ONC RPC"),
    ("nfs-or-iis", "RPC", "시스템", "Microsoft RPC / NFS"),
    ("ipmi", "관리", "관리", "IPMI BMC 관리"),
    ("wsdapi", "관리", "시스템", "WS-Discovery"),
    ("vmware-auth", "관리", "관리", "VMware Authentication Daemon"),
    # 산업 제어
    ("modbus", "산업제어", "시스템", "Modbus"),
    ("enip", "산업제어", "시스템", "EtherNet/IP"),
    ("bacnet", "산업제어", "시스템", "BACnet"),
    ("s7", "산업제어", "시스템", "Siemens S7"),
    ("opcua", "산업제어", "시스템", "OPC UA"),
    # 진단 / 정보
    ("chargen", "진단", "시스템", "Character Generator (RFC 864)"),
    ("echo", "진단", "시스템", "Echo (RFC 862)"),
    ("discard", "진단", "시스템", "Discard (RFC 863)"),
    ("finger", "정보조회", "시스템", "Finger"),
    # 버전관리 / 분산
    ("git", "버전관리", "개발", "Git"),
    ("svn", "버전관리", "개발", "Subversion"),
    ("zookeeper", "분산조정", "내부통신", "ZooKeeper"),
    ("etcd", "분산조정", "내부통신", "etcd"),
    # 컨테이너 / CI
    ("docker", "컨테이너", "관리", "Docker API"),
    ("kubernetes", "컨테이너", "관리", "Kubernetes API"),
    ("jenkins", "CI/CD", "개발", "Jenkins"),
    ("gitlab", "CI/CD", "개발", "GitLab"),
    # 보안 도구
    ("nessus", "보안도구", "보안", "Nessus"),
]

# 서비스 노출 위험/공격 표면 가이드(최소 baseline) — categories.xlsx 의 5/6열 값이 비어있을 때 폴백.
# SERVICE_PROTOCOL_GUIDE — 4-tuple (표준포트, 프로토콜, 암호화, 인증)
#   프로토콜 enum: TCP / UDP / TCP+UDP
#   암호화 enum: 평문 / TLS / 암호화 / 선택 (clear/encrypted depending on config) / 암호화(자체)
#   인증 enum: 익명가능 / 사용자 / 키 / 인증서 / MFA / community / Kerberos / RAKP — 콤마 구분 가능
SERVICE_PROTOCOL_GUIDE = {
    # 원격접속
    "ssh":           ("22", "TCP", "암호화", "사용자/키"),
    "telnet":        ("23", "TCP", "평문", "사용자"),
    "rdp":           ("3389", "TCP", "선택 (NLA시 강제)", "사용자"),
    "ms-wbt-server": ("3389", "TCP", "선택 (NLA시 강제)", "사용자"),
    "vnc":           ("5900", "TCP", "평문 (확장으로 TLS)", "사용자"),
    "vnc-http":      ("5800", "TCP", "평문", "사용자"),
    "vmrdp":         ("2179", "TCP", "선택", "사용자"),
    "xrdp":          ("3389", "TCP", "선택", "사용자"),
    "rlogin":        ("513", "TCP", "평문", "신뢰관계/사용자"),
    "rsh":           ("514", "TCP", "평문", "신뢰관계"),
    "shell":         ("514", "TCP", "평문", "신뢰관계"),
    "rexec":         ("512", "TCP", "평문", "사용자"),
    # 웹 / 프록시
    "http":          ("80", "TCP", "평문", "익명가능"),
    "http-alt":      ("8080", "TCP", "평문", "익명가능"),
    "https":         ("443", "TCP", "TLS", "익명가능"),
    "https-alt":     ("8443", "TCP", "TLS", "익명가능"),
    "ssl/http":      ("443", "TCP", "TLS", "익명가능"),
    "ssl/https":     ("443", "TCP", "TLS", "익명가능"),
    "ajp13":         ("8009", "TCP", "평문", "사용자"),
    "ajp":           ("8009", "TCP", "평문", "사용자"),
    "http-proxy":    ("3128", "TCP", "선택", "사용자/익명"),
    "ftp-proxy":     ("8021", "TCP", "선택", "사용자"),
    "socks":         ("1080", "TCP", "선택", "사용자/익명"),
    "webpush":       ("443", "TCP", "TLS", "토큰"),
    # 인쇄
    "ipp":           ("631", "TCP", "선택", "사용자/익명"),
    "printer":       ("515", "TCP", "평문", "익명가능"),
    "lpd":           ("515", "TCP", "평문", "익명가능"),
    # DBMS
    "mysql":         ("3306", "TCP", "선택", "사용자"),
    "mariadb":       ("3306", "TCP", "선택", "사용자"),
    "postgresql":    ("5432", "TCP", "선택", "사용자"),
    "postgres":      ("5432", "TCP", "선택", "사용자"),
    "ms-sql-s":      ("1433", "TCP", "선택", "사용자"),
    "ms-sql-m":      ("1434", "UDP", "평문", "익명가능"),
    "oracle-tns":    ("1521", "TCP", "선택", "사용자"),
    "mongodb":       ("27017", "TCP", "선택", "사용자/익명"),
    "mongo":         ("27017", "TCP", "선택", "사용자/익명"),
    "redis":         ("6379", "TCP", "평문 (TLS 옵션)", "사용자/익명"),
    "elasticsearch": ("9200", "TCP", "선택", "사용자/익명"),
    "couchdb":       ("5984", "TCP", "선택", "사용자/익명"),
    "neo4j":         ("7687", "TCP", "선택", "사용자"),
    "influxdb":      ("8086", "TCP", "선택", "사용자/익명"),
    "memcache":      ("11211", "TCP+UDP", "평문", "익명가능"),
    "memcached":     ("11211", "TCP+UDP", "평문", "익명가능"),
    "cassandra":     ("9042", "TCP", "선택", "사용자"),
    "hbase":         ("16000", "TCP", "선택 (Kerberos)", "사용자/Kerberos"),
    "db2":           ("50000", "TCP", "선택", "사용자"),
    # 메시지큐
    "amqp":          ("5672", "TCP", "선택", "사용자"),
    "mqtt":          ("1883", "TCP", "선택", "사용자"),
    "nats":          ("4222", "TCP", "선택", "토큰"),
    "kafka":         ("9092", "TCP", "선택 (SASL/TLS)", "사용자/SASL"),
    # 메일
    "smtp":          ("25", "TCP", "선택 (STARTTLS)", "사용자/익명"),
    "submission":    ("587", "TCP", "TLS (STARTTLS)", "사용자"),
    "smtps":         ("465", "TCP", "TLS", "사용자"),
    "pop3":          ("110", "TCP", "선택 (STARTTLS)", "사용자"),
    "pop3s":         ("995", "TCP", "TLS", "사용자"),
    "imap":          ("143", "TCP", "선택 (STARTTLS)", "사용자"),
    "imaps":         ("993", "TCP", "TLS", "사용자"),
    # 디렉토리 / 인증
    "ldap":          ("389", "TCP+UDP", "평문 (StartTLS 옵션)", "사용자/익명"),
    "ldaps":         ("636", "TCP", "TLS", "사용자"),
    "cldap":         ("389", "UDP", "평문", "익명가능"),
    "kerberos-sec":  ("88", "TCP+UDP", "암호화(자체)", "Kerberos"),
    "kpasswd":       ("464", "TCP+UDP", "암호화(자체)", "Kerberos"),
    # DNS
    "domain":        ("53", "TCP+UDP", "평문 (DoT/DoH 옵션)", "익명가능"),
    "dns":           ("53", "TCP+UDP", "평문 (DoT/DoH 옵션)", "익명가능"),
    # 파일공유 / 전송
    "microsoft-ds":  ("445", "TCP", "SMB signing 옵션", "사용자/익명"),
    "netbios-ssn":   ("139", "TCP", "평문", "사용자/익명"),
    "netbios-ns":    ("137", "UDP", "평문", "익명가능"),
    "nbstat":        ("137", "UDP", "평문", "익명가능"),
    "nfs":           ("2049", "TCP+UDP", "선택 (Kerberos)", "사용자/익명"),
    "ftp":           ("21", "TCP", "평문 (FTPS 옵션)", "사용자/익명"),
    "ftps":          ("990", "TCP", "TLS", "사용자"),
    "tftp":          ("69", "UDP", "평문", "익명가능"),
    "sftp":          ("22", "TCP", "암호화 (SSH)", "사용자/키"),
    "rcp":           ("514", "TCP", "평문", "신뢰관계"),
    "ftp-data":      ("20", "TCP", "평문", "사용자"),
    # 시간 / 모니터링 / 로그
    "ntp":           ("123", "UDP", "평문 (NTS 옵션)", "익명가능"),
    "snmp":          ("161", "UDP", "평문 (v1/v2) / 암호화 (v3)", "community/사용자"),
    "snmptrap":      ("162", "UDP", "평문 (v1/v2) / 암호화 (v3)", "community/사용자"),
    "zabbix-agent":  ("10050", "TCP", "선택 (PSK/cert)", "PSK/인증서"),
    "zabbix-trapper":("10051", "TCP", "선택", "사용자"),
    "prometheus":    ("9090", "TCP", "선택", "사용자/익명"),
    "grafana":       ("3000", "TCP", "선택 (TLS)", "사용자"),
    "syslog":        ("514", "UDP", "평문 (TLS 옵션)", "익명가능"),
    "splunk":        ("8000", "TCP", "TLS", "사용자"),
    # VPN / VoIP / 미디어
    "isakmp":        ("500", "UDP", "암호화(자체)", "PSK/인증서"),
    "ipsec-nat-t":   ("4500", "UDP", "암호화(자체)", "PSK/인증서"),
    "openvpn":       ("1194", "UDP", "TLS", "인증서"),
    "sip":           ("5060", "TCP+UDP", "선택 (sips시 TLS)", "사용자"),
    "sip-tls":       ("5061", "TCP", "TLS", "사용자"),
    "rtsp":          ("554", "TCP", "선택", "사용자"),
    # 네트워크 검색
    "ssdp":          ("1900", "UDP", "평문", "익명가능"),
    "upnp":          ("1900", "UDP", "평문", "익명가능"),
    "mdns":          ("5353", "UDP", "평문", "익명가능"),
    # RPC / 관리
    "msrpc":         ("135", "TCP", "선택", "사용자"),
    "rpcbind":       ("111", "TCP+UDP", "평문", "익명가능"),
    "sunrpc":        ("111", "TCP+UDP", "평문", "익명가능"),
    "nfs-or-iis":    ("135", "TCP", "선택", "사용자"),
    "ipmi":          ("623", "UDP", "선택", "사용자/RAKP"),
    "wsdapi":        ("5357", "TCP", "평문", "익명가능"),
    "vmware-auth":   ("902", "TCP", "선택", "사용자"),
    "ipcserver":     ("0", "TCP", "선택", "사용자"),
    # 산업 제어
    "modbus":        ("502", "TCP", "평문", "익명가능"),
    "enip":          ("44818", "TCP+UDP", "평문", "익명가능"),
    "bacnet":        ("47808", "UDP", "평문", "익명가능"),
    "s7":            ("102", "TCP", "평문", "익명가능"),
    "opcua":         ("4840", "TCP", "선택 (TLS+인증)", "사용자/인증서"),
    "cadlock2":      ("0", "TCP", "선택", "사용자"),
    # 진단 / 정보
    "chargen":       ("19", "TCP+UDP", "평문", "익명가능"),
    "echo":          ("7", "TCP+UDP", "평문", "익명가능"),
    "discard":       ("9", "TCP+UDP", "평문", "익명가능"),
    "finger":        ("79", "TCP", "평문", "익명가능"),
    "irc":           ("6667", "TCP", "선택", "사용자"),
    # 버전관리 / 분산
    "git":           ("9418", "TCP", "선택 (SSH/TLS)", "사용자/익명"),
    "svn":           ("3690", "TCP", "선택", "사용자/익명"),
    "zookeeper":     ("2181", "TCP", "선택 (SASL)", "SASL/익명"),
    "etcd":          ("2379", "TCP", "선택 (TLS+클라인증)", "인증서"),
    # 컨테이너 / CI
    "docker":        ("2375", "TCP", "선택 (TLS+클라인증)", "인증서/익명"),
    "kubernetes":    ("6443", "TCP", "TLS", "인증서/Bearer"),
    "jenkins":       ("8080", "TCP", "선택 (TLS)", "사용자"),
    "gitlab":        ("443", "TCP", "TLS", "사용자"),
    # 보안도구
    "nessus":        ("8834", "TCP", "TLS", "사용자"),
    # 기타
    "914c-g":        ("0", "TCP", "선택", "사용자"),
}


def _protocol_guide_for(key):
    """SERVICE_PROTOCOL_GUIDE 항목을 4-tuple (표준포트, 프로토콜, 암호화, 인증) 로 반환.
    누락 시 빈 문자열."""
    e = SERVICE_PROTOCOL_GUIDE.get(key, ())
    if len(e) == 4:
        return e
    return ("", "", "", "")


# SERVICE_EXPOSURE_GUIDE — 4-tuple (위험도, 노출위험, 공격표면, 출처)
#   위험도: 상 / 중 / 하 (KISA 한국식 enum)
#   출처 우선순위 (한국 점검 환경 — 4종 매핑):
#     1순위: KISA "주요정보통신기반시설 취약점 분석·평가 상세 가이드" (U-01~U-72, W-01~W-72)
#     2순위: 국정원 "정보보안기본지침" / "기술적 보호조치 지침" / "암호모듈 정책(KCMVP)"
#            (한국 환경에서 흔한 telnet/ftp/smb1/snmp v1/v2/RDP/원격 자격증명 노출 등에 명시)
#     3순위: CIS Critical Security Controls v8
#     4순위: MITRE ATT&CK Technique ID
SERVICE_EXPOSURE_GUIDE = {
    # ---- 원격 접속
    "ssh":           ("중", "약한 비밀번호/구버전 시 무차별 대입·CVE 악용 가능", "브루트포스, OpenSSH CVE (CVE-2024-6387 등), 키 관리 미흡", "KISA U-01, 국정원 기술적보호조치 5.1, CIS 4.6, MITRE T1021.004"),
    "telnet":        ("상", "평문 통신으로 자격증명·세션 정보 그대로 노출", "패킷 스니핑, 중간자 공격, 자격증명 탈취", "KISA U-21, 국정원 정보보안기본지침 제32조, CIS 4.5, MITRE T1040"),
    "rdp":           ("상", "NLA 미적용 시 NTLM 정보 노출, BlueKeep 류 RCE 위험", "NTLM relay, BlueKeep, 무차별 대입", "KISA W-20, 국정원 정보보안기본지침 제29조(원격접근 통제), CIS 4.6, MITRE T1021.001"),
    "ms-wbt-server": ("상", "NLA 미적용 시 NTLM challenge 응답으로 호스트명/도메인 노출, BlueKeep 류 RCE 위험", "NTLM relay, BlueKeep, 무차별 대입", "KISA W-20, 국정원 정보보안기본지침 제29조(원격접근 통제), CIS 4.6, MITRE T1021.001"),
    "vnc":           ("상", "평문 인증·약한 비밀번호 시 화면 탈취 / 세션 하이재킹", "약한 인증, 세션 탈취, RFB 취약점", "KISA W-20, 국정원 정보보안기본지침 제29조(원격접근 통제), CIS 4.6, MITRE T1021.005"),
    "vnc-http":      ("상", "VNC over HTTP 평문 화면 탈취 / 약한 인증", "약한 인증, 세션 탈취", "KISA W-20, MITRE T1021.005"),
    "vmrdp":         ("상", "가상화 관리 채널 노출 시 hypervisor 권한 탈취 가능", "관리 세션 탈취, hypervisor escape", "KISA W-65, MITRE T1021.001"),
    "xrdp":          ("상", "Linux RDP 약한 인증 / NLA 미지원 구버전", "무차별 대입, 인증 우회", "KISA W-20, MITRE T1021.001"),
    "rlogin":        ("상", "신뢰관계 평문 인증 — .rhosts 위조 시 무인증 접근", "신뢰호스트 위조, 계정 탈취", "KISA U-23, CIS 4.5, MITRE T1021"),
    "rsh":           ("상", "rsh 평문 명령 실행 — 신뢰관계 악용 시 무인증 RCE", "신뢰관계 악용, 명령 실행", "KISA U-23, CIS 4.5, MITRE T1021"),
    "shell":         ("상", "rsh 셸 직접 노출 — 무인증 명령 실행 가능", "rsh 명령 실행 악용", "KISA U-23, MITRE T1021"),
    "rexec":         ("상", "원격 명령 실행 평문 인증", "자격증명 탈취, 명령 실행", "KISA U-23, MITRE T1021"),
    # ---- 웹 / 프록시
    "http":          ("중", "평문 통신, 응용 의존 취약점 (XSS/SQLi 등), 헤더 정보 노출", "OWASP Top10, Banner 정보 노출, 관리자 페이지", "KISA W-13, 국정원 기술적보호조치 6.5, OWASP Top10, MITRE T1190"),
    "http-alt":      ("중", "평문 HTTP 대체 포트 — 동일 취약점 면적", "OWASP Top10, Banner 정보 노출", "KISA W-13, OWASP Top10, MITRE T1190"),
    "https":         ("하", "TLS 설정 미흡 시 약한 cipher / TLS 1.0~1.1 / 자체서명 인증서 신뢰 문제", "TLS 다운그레이드, 약한 cipher, 인증서 오남용", "KISA U-66, 국정원 암호모듈 정책(KCMVP), NIST SP 800-52, MITRE T1573"),
    "https-alt":     ("하", "TLS 설정 미흡 시 약한 cipher / TLS 1.0~1.1", "TLS 다운그레이드, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "ssl/http":      ("하", "TLS over HTTP — 약한 cipher / 구버전 TLS 시 다운그레이드", "TLS 다운그레이드, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "ssl/https":     ("하", "TLS over HTTPS — 약한 cipher / 구버전 TLS", "TLS 다운그레이드, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "ajp13":         ("상", "AJP 외부 노출 시 Ghostcat (CVE-2020-1938) 으로 임의 파일 읽기", "Ghostcat (CVE-2020-1938), 파일 읽기, 요청 위조", "KISA W-13, CIS 4.8, MITRE T1190"),
    "ajp":           ("상", "AJP 외부 노출 시 임의 파일 읽기 / 요청 위조", "Ghostcat 류, 파일 읽기, 요청 위조", "KISA W-13, MITRE T1190"),
    "http-proxy":    ("상", "오픈 프록시 시 우회 접속 / 익명 트래픽 발판", "우회 접속, 익명 프록시 남용, SSRF", "KISA W-13, MITRE T1090"),
    "ftp-proxy":     ("상", "오픈 FTP 프록시 시 우회 접속 / 중계 악용", "우회 접속, 익명 프록시 남용", "KISA W-13, MITRE T1090"),
    "socks":         ("상", "오픈 SOCKS 프록시 시 우회 접속 / 익명 트래픽 발판", "우회 접속, 익명 프록시 남용", "KISA W-13, MITRE T1090"),
    "webpush":       ("중", "웹 푸시 엔드포인트 노출 시 인증 미흡 채널 오남용", "푸시 채널 오남용, 스팸 발송", "OWASP API, MITRE T1190"),
    # ---- 인쇄
    "ipp":           ("중", "외부 노출 시 익명 인쇄 큐 접근, CUPS CVE 악용", "출력물 유출, CUPS RCE (CVE-2024-47176 류)", "KISA U-23, MITRE T1133"),
    "printer":       ("중", "LPD 인쇄 평문, 인증 약함", "출력물 유출, 서비스 거부", "KISA U-23, CIS 4.8"),
    "lpd":           ("중", "LPD 인증 없는 인쇄 큐 접근", "출력물 유출, 서비스 거부", "KISA U-23, CIS 4.8"),
    # ---- DBMS (모두 외부 노출 차단 원칙)
    "mysql":         ("상", "외부 노출 시 무차별 대입, 버전·plugin 정보 노출, SQL 권한 탈취", "무차별 대입, SQL injection, 알려진 CVE", "KISA U-46, CIS 4.6, MITRE T1190"),
    "mariadb":       ("상", "외부 노출 시 무차별 대입, 버전 정보 노출", "무차별 대입, 알려진 CVE", "KISA U-46, CIS 4.6, MITRE T1190"),
    "postgresql":    ("상", "외부 노출 시 무차별 대입, scram-sha-256 미적용 시 약한 해시", "무차별 대입, 권한 탈취, CVE 악용", "KISA U-46, CIS 4.6, MITRE T1190"),
    "postgres":      ("상", "외부 노출 시 무차별 대입, 권한 탈취 가능", "무차별 대입, 권한 탈취", "KISA U-46, CIS 4.6, MITRE T1190"),
    "ms-sql-s":      ("상", "외부 노출 시 sa 무차별 대입, xp_cmdshell 활용 시 OS 명령 실행", "sa 무차별 대입, xp_cmdshell, 권한 상승", "KISA U-46, 국정원 기술적보호조치 6.4(DBMS 직접 노출 금지), CIS 4.6, MITRE T1190"),
    "ms-sql-m":      ("중", "MS-SQL Browser 서비스 — 인스턴스 정보 노출", "정보 수집 (instance 이름·포트)", "KISA U-46"),
    "oracle-tns":    ("상", "외부 노출 시 TNS poisoning, SID 무차별 대입, listener 정보 노출", "TNS poisoning, SID 무차별 대입", "KISA U-46, CIS 4.6, MITRE T1190"),
    "mongodb":       ("상", "기본 인증 없음 / bind 0.0.0.0 시 무인증 데이터 노출·변조", "무인증 접근, 데이터 변조, 랜섬웨어", "KISA U-46, CIS 4.6, MITRE T1190"),
    "mongo":         ("상", "기본 인증 없음 시 무인증 데이터 접근", "무인증 접근, 데이터 변조", "KISA U-46, CIS 4.6, MITRE T1190"),
    "redis":         ("상", "기본 requirepass 미설정 시 무인증 / SLAVEOF·CONFIG 활용 RCE", "무인증 접근, RCE (slaveof+config), 데이터 변조", "KISA U-46, CIS 4.6, MITRE T1190"),
    "elasticsearch": ("상", "X-Pack 인증 미적용 시 무인증 데이터 / 인덱스 노출", "무인증 접근, 데이터 유출, CVE 악용", "KISA U-46, CIS 4.6"),
    "couchdb":       ("상", "Admin Party (인증 미설정) 시 무인증 관리자 권한", "무인증 관리자, CVE-2017-12635 권한 상승", "KISA U-46, MITRE T1190"),
    "neo4j":         ("상", "기본 neo4j/neo4j 비밀번호 / 외부 노출 시 그래프 데이터 탈취", "기본 비밀번호, 무차별 대입", "KISA U-46, CIS 4.6"),
    "influxdb":      ("상", "인증 미설정 시 시계열 데이터 무인증 열람·변조", "무인증 접근, 데이터 변조", "KISA U-46, CIS 4.6"),
    "memcache":      ("상", "기본 인증 없음 / UDP amplification (1000x+)", "무인증 데이터, UDP 증폭 DDoS", "KISA U-46, CIS 4.8, US-CERT TA18-039A"),
    "memcached":     ("상", "기본 인증 없음 / UDP amplification", "무인증 데이터, UDP 증폭 DDoS", "KISA U-46, CIS 4.8, US-CERT TA18-039A"),
    "cassandra":     ("상", "기본 cassandra/cassandra / 외부 노출 시 데이터 탈취", "기본 비밀번호, 무차별 대입", "KISA U-46, CIS 4.6"),
    "hbase":         ("상", "Kerberos 미적용 시 무인증 / 외부 노출 시 데이터 탈취", "무인증, 데이터 변조", "KISA U-46, CIS 4.6"),
    "db2":           ("상", "외부 노출 시 무차별 대입, SQL 권한 탈취", "무차별 대입, 권한 탈취", "KISA U-46, CIS 4.6"),
    # ---- 메시지큐
    "amqp":          ("중", "기본 guest:guest 시 메시지 무인증 접근, TLS 미적용", "기본 자격증명, 메시지 변조", "CIS 4.6, MITRE T1133"),
    "mqtt":          ("중", "TLS·인증 미적용 시 IoT 메시지 노출·변조", "메시지 도청, 명령 위조", "CIS 4.6, MITRE T1557"),
    "nats":          ("중", "토큰/TLS 미적용 시 메시지 노출", "메시지 도청, 변조", "CIS 4.6"),
    "kafka":         ("중", "SASL/TLS 미적용 시 토픽 데이터 무인증 접근", "토픽 데이터 노출, 변조", "CIS 4.6, MITRE T1133"),
    # ---- 메일
    "smtp":          ("상", "open relay 시 스팸 릴레이 / SPF·DKIM 미적용 시 위변조", "스팸 릴레이, 사용자 열거, 위변조", "KISA W-22, CIS 9.4, MITRE T1071.003"),
    "submission":    ("중", "TLS 미적용 시 메일 자격증명 노출", "자격증명 탈취, 도청", "KISA W-22, NIST SP 800-177"),
    "smtps":         ("하", "TLS 1.2+ 미적용 시 약한 cipher", "TLS 다운그레이드, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "pop3":          ("상", "평문 인증으로 메일 자격증명·메일 내용 노출", "자격증명 탈취, 메일 도청", "KISA U-21, MITRE T1040"),
    "pop3s":         ("하", "TLS 1.2+ 미적용 시 약한 cipher", "TLS 다운그레이드", "KISA U-66, NIST SP 800-52"),
    "imap":          ("상", "평문 인증으로 메일 자격증명·메일 내용 노출", "자격증명 탈취, 메일 도청", "KISA U-21, MITRE T1040"),
    "imaps":         ("하", "TLS 1.2+ 미적용 시 약한 cipher", "TLS 다운그레이드", "KISA U-66, NIST SP 800-52"),
    # ---- 디렉토리 / 인증
    "ldap":          ("상", "익명 바인드 시 디렉토리 정보 / DN 트리 / 사용자명 무인증 열람", "익명 바인드, 무차별 대입, 정보 수집", "KISA W-44, CIS 4.10, MITRE T1087.002"),
    "ldaps":         ("중", "TLS 적용되어 도청은 차단되지만 익명 바인드 / 무차별 대입은 가능", "익명 바인드, 무차별 대입", "KISA W-44, CIS 4.10, MITRE T1087.002"),
    "cldap":         ("중", "Connectionless LDAP — UDP amplification 도구 / AD 정보 수집", "AD 정보 수집, UDP 증폭 DDoS (56x)", "KISA W-44, US-CERT TA14-017A, MITRE T1087.002"),
    "kerberos-sec":  ("상", "Kerberoasting / AS-REP roasting 으로 service account 해시 추출", "Kerberoasting (T1558.003), AS-REP roasting", "KISA W-44, CIS 16.5, MITRE T1558"),
    "kpasswd":       ("중", "약한 암호 정책 시 무차별 대입", "무차별 대입, 약한 암호", "KISA W-44"),
    # ---- DNS
    "domain":        ("중", "재귀 쿼리 외부 허용 시 DNS 증폭, zone transfer 시 내부 호스트명 노출", "DNS 증폭 (54x), zone transfer (AXFR)", "KISA U-15, CIS 4.10, MITRE T1018"),
    "dns":           ("중", "재귀 쿼리 외부 허용 시 DNS 증폭, zone transfer 시 내부 정보 노출", "DNS 증폭, zone transfer", "KISA U-15, CIS 4.10, MITRE T1018"),
    # ---- 파일 공유 / 전송
    "microsoft-ds":  ("상", "SMB1 활성 시 EternalBlue, NTLM relay, 익명 nullsession 가능", "EternalBlue (MS17-010), NTLM relay, 익명 SMB", "KISA W-08, 국정원 기술적보호조치 7.2, CIS 9.4, MITRE T1021.002"),
    "netbios-ssn":   ("상", "NetBIOS Session 외부 노출 시 SMB 취약점 / nullsession", "SMB 취약점, null session, NetBIOS 정보 수집", "KISA W-08, 국정원 기술적보호조치 7.2, CIS 9.4, MITRE T1021.002"),
    "netbios-ns":    ("상", "NetBIOS Name Service 외부 노출 시 NetBIOS poisoning", "NetBIOS poisoning, LLMNR 탈취", "KISA W-08, CIS 9.4, MITRE T1557.001"),
    "nbstat":        ("상", "NetBIOS Status — 외부 노출 시 호스트명·도메인 정보 노출", "정보 수집 (호스트명·MAC·사용자)", "KISA W-08, MITRE T1018"),
    "nfs":           ("상", "no_root_squash 시 root 권한 파일 변조 / 익명 mount", "익명 mount, root_squash 우회, 파일 변조", "KISA U-23, CIS 4.6, MITRE T1021"),
    "ftp":           ("상", "평문 인증, 익명 로그인 가능 시 무인증 파일 접근, FTP bounce", "자격증명 탈취, 익명 접근, FTP bounce, 디렉터리 트래버설", "KISA U-21, 국정원 기술적보호조치 7.1, CIS 4.5, MITRE T1567"),
    "ftps":          ("하", "TLS 적용되어 도청 차단되지만 약한 cipher 시 다운그레이드", "TLS 다운그레이드, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "tftp":          ("상", "인증 없는 파일 read/write — 설정파일 탈취·변조", "설정파일 탈취, 부팅 이미지 변조", "KISA U-23, CIS 4.5, MITRE T1567"),
    "sftp":          ("하", "SSH 채널 — 키 인증 시 안전. 약한 비밀번호 시 위험", "SSH 무차별 대입", "KISA U-01, CIS 4.6"),
    "rcp":           ("상", "rsh 기반 평문 파일 전송 — 인증 취약", "파일 무단 전송, 덮어쓰기", "KISA U-23, MITRE T1021"),
    # ---- 시간 / 모니터링 / 로그
    "ntp":           ("중", "monlist 활성 시 UDP amplification (556x), 시간 동기화 교란", "NTP amplification (CVE-2013-5211), 시간 변조", "KISA U-30, US-CERT TA14-013A, MITRE T1498.002"),
    "snmp":          ("상", "community 'public' 기본값 시 시스템 정보 무인증 열람·설정", "정보 수집, 설정 조회·변경, SNMPv1/v2c 약점", "KISA U-30, 국정원 기술적보호조치 6.3(SNMPv3 권장), CIS 4.8, MITRE T1018"),
    "snmptrap":      ("중", "외부 노출 시 모니터링 이벤트 평문 노출", "장비/이벤트 정보 수집", "KISA U-30, CIS 4.8"),
    "zabbix-agent":  ("중", "Server 화이트리스트 미적용 시 무인증 명령 실행 (UserParameter)", "무인증 명령 실행, 정보 수집", "KISA U-30, CIS 4.6"),
    "zabbix-trapper":("중", "외부 노출 시 모니터링 데이터 변조", "데이터 위조, 모니터링 우회", "CIS 4.6"),
    "prometheus":    ("중", "외부 노출 시 메트릭 무인증 열람 / 내부 정보 수집", "메트릭 노출, 정보 수집", "CIS 4.6, MITRE T1018"),
    "grafana":       ("중", "기본 admin/admin 시 대시보드·DB 자격증명 탈취", "기본 비밀번호, CVE 악용", "CIS 4.6, MITRE T1190"),
    "syslog":        ("중", "TLS 미적용 시 로그 평문 / 로그 인젝션", "로그 인젝션, 민감정보 유출", "KISA U-43, CIS 8.2"),
    "splunk":        ("중", "외부 노출 시 무차별 대입, 알려진 CVE", "무차별 대입, CVE 악용", "CIS 4.6, MITRE T1190"),
    # ---- VPN / VoIP / 미디어
    "isakmp":        ("중", "PSK 사용 시 weak PSK 무차별 대입, IKEv1 약점", "PSK 무차별 대입, IKEv1 aggressive mode", "KISA U-66, MITRE T1133"),
    "ipsec-nat-t":   ("중", "PSK 사용 시 weak PSK 무차별 대입", "PSK 무차별 대입", "KISA U-66, MITRE T1133"),
    "openvpn":       ("중", "약한 cipher / 인증서 검증 미흡 시 MITM", "MITM, 약한 cipher", "KISA U-66, NIST SP 800-52"),
    "sip":           ("상", "VoIP 인프라 — TLS 미적용 시 통화 도청 / 사용자 열거 / 요금 사기", "통화 도청, 사용자 열거, toll fraud", "KISA U-66, MITRE T1071"),
    "sip-tls":       ("중", "TLS 적용되지만 사용자 열거·요금 사기는 가능", "사용자 열거, toll fraud", "KISA U-66"),
    "rtsp":          ("중", "인증 미적용 시 미디어 스트림 무인증 접근", "스트림 도청, 인증 우회", "MITRE T1133"),
    # ---- 네트워크 검색
    "ssdp":          ("중", "UPnP/SSDP — UDP amplification (30x) / 내부 장비 정보 노출", "UDP 증폭, 장비 정보 수집", "KISA U-30, US-CERT TA14-017A, MITRE T1498.002"),
    "upnp":          ("중", "UPnP — 외부 노출 시 포트 매핑 무인증 추가", "포트 매핑 무인증, 정보 수집", "KISA U-30, MITRE T1133"),
    "mdns":          ("중", "Multicast DNS — 외부 노출 시 내부 호스트명 노출", "정보 수집, mDNS poisoning", "KISA U-15, MITRE T1557.001"),
    # ---- RPC / 관리
    "msrpc":         ("상", "Microsoft RPC 외부 노출 시 endpoint mapper 정보 / RPC CVE 악용", "endpoint mapper 정보 수집, RPC CVE", "KISA W-08, CIS 4.8, MITRE T1021.003"),
    "rpcbind":       ("상", "ONC RPC portmapper 외부 노출 시 RPC 서비스 매핑 / 측면이동 발판", "서비스 열거, NFS 정보 수집", "KISA U-23, CIS 4.8, MITRE T1018"),
    "sunrpc":        ("상", "ONC RPC 외부 노출 시 RPC 서비스 매핑", "서비스 열거, 측면이동", "KISA U-23, CIS 4.8, MITRE T1018"),
    "nfs-or-iis":    ("상", "포트 135 — Microsoft RPC / NFS 모호. RPC 정보 수집 가능", "RPC 정보 수집, 서비스 열거", "KISA W-08, MITRE T1018"),
    "ipmi":          ("상", "RAKP 인증 우회로 무인증 자격 해시 추출 / cipher 0 활성 시 무인증", "RAKP CVE-2013-4786, cipher 0, 펌웨어 탈취", "KISA W-65, US-CERT 2013-08, MITRE T1133"),
    "wsdapi":        ("중", "WS-Discovery 외부 노출 시 UDP amplification (153x) / 장비 정보 수집", "UDP 증폭 DDoS, 정보 수집", "KISA W-08, US-CERT 2019-08, MITRE T1498.002"),
    "vmware-auth":   ("중", "VMware Authentication Daemon 외부 노출 시 정보 수집·무차별 대입", "무차별 대입, 정보 수집", "KISA W-65, MITRE T1021"),
    "ipcserver":     ("상", "내부 IPC 서비스 직접 노출 시 권한상승 / 측면이동 발판", "권한 상승, 측면 이동", "KISA W-65, MITRE T1021"),
    # ---- 산업 제어 (외부 노출 절대 금지)
    "modbus":        ("상", "외부 노출 시 PLC 직접 제어 — 인증 없는 산업 제어 프로토콜", "PLC 직접 제어, 명령 위조, 모니터링", "KISA W-65, ICS-CERT, MITRE T0846"),
    "enip":          ("상", "외부 노출 시 EtherNet/IP 직접 제어 / 펌웨어 탈취", "PLC 제어, 펌웨어 탈취", "KISA W-65, ICS-CERT, MITRE T0846"),
    "bacnet":        ("상", "외부 노출 시 빌딩 자동화 시스템 직접 제어", "빌딩 시스템 제어, 모니터링", "KISA W-65, ICS-CERT"),
    "s7":            ("상", "외부 노출 시 Siemens S7 PLC 직접 제어 — Stuxnet 류 위협", "PLC 제어, 펌웨어 변조 (Stuxnet)", "KISA W-65, ICS-CERT, MITRE T0846"),
    "opcua":         ("상", "TLS+인증 미적용 시 OPC UA 데이터 변조 / 명령 위조", "데이터 변조, 명령 위조", "KISA W-65, ICS-CERT"),
    "cadlock2":      ("상", "제어/잠금 서비스 외부 노출 시 서비스 중단 유도", "서비스 중단, 오동작 유도", "KISA W-65"),
    # ---- 진단 / 정보 (RFC 진단용 — 사용 안 함 권장)
    "chargen":       ("상", "UDP amplification 도구로 악용 (200x+)", "DDoS 증폭, 정보 가치 0", "KISA W-15, US-CERT VU#222929, MITRE T1498.002"),
    "echo":          ("중", "UDP echo 반사 트래픽 / 진단용 오용", "반사 트래픽, 증폭 보조", "KISA W-15, CIS 4.8"),
    "discard":       ("하", "discard 진단 — 데이터 가치 없으나 비활성 권장", "진단 채널", "KISA W-15, CIS 4.8"),
    "finger":        ("중", "Finger — 사용자 정보 (로그인 사용자, 홈디렉토리) 노출", "사용자 정보 수집, 권한 상승 발판", "KISA U-21, CIS 4.8, MITRE T1087.001"),
    "irc":           ("중", "레거시 IRC 채널 — C2/봇넷 채널로 악용 가능", "C2 채널 악용, 봇넷", "MITRE T1071.001"),
    "ftp-data":      ("중", "FTP 데이터 채널 — 평문 전송", "도청, MITM", "KISA U-21, MITRE T1040"),
    # ---- 버전관리 / 분산
    "git":           ("중", "익명 접근 시 소스 코드 유출 / .git 디렉토리 노출", "소스 코드 유출, 자격증명 노출", "OWASP, MITRE T1213"),
    "svn":           ("중", "익명 접근 시 소스 코드 유출", "소스 코드 유출", "OWASP, MITRE T1213"),
    "zookeeper":     ("중", "SASL 미적용 시 분산 조정 데이터 무인증 접근", "무인증 접근, ACL 우회", "CIS 4.6"),
    "etcd":          ("상", "TLS·클라이언트 인증 미적용 시 클러스터 비밀(secrets) 무인증 노출", "secrets 노출, 클러스터 제어", "CIS 4.6, MITRE T1552"),
    # ---- 컨테이너 / CI
    "docker":        ("상", "Docker API TLS·인증 미적용 시 무인증 컨테이너 생성·호스트 RCE", "컨테이너 escape, host RCE, secrets 탈취", "CIS Docker, MITRE T1610"),
    "kubernetes":    ("상", "RBAC·TLS 미적용 시 클러스터 무인증 제어", "클러스터 제어, secrets 탈취, RCE", "CIS Kubernetes, MITRE T1552"),
    "jenkins":       ("상", "외부 노출 시 인증 우회·플러그인 RCE", "인증 우회, 플러그인 RCE, 자격증명 탈취", "CIS 4.6, MITRE T1190"),
    "gitlab":        ("중", "TLS·인증 적용 시 안전. CVE 패치 미적용 시 RCE", "CVE 악용 (GitLab RCE 시리즈)", "CIS 4.6, MITRE T1190"),
    # ---- 보안 도구
    "nessus":        ("중", "외부 노출 시 보안 도구 자체가 표적 — 자격증명·정책 탈취", "도구 자격증명 탈취", "CIS 4.6"),
    # ---- 기타 / 레거시
    "914c-g":        ("중", "레거시/벤더 전용 서비스 — 취약 구현 탐색", "취약 구현 탐색", "정보 부족"),
}


def default_options_as_rows():
    """DEFAULT_OPTIONS 튜플 → load_options_xlsx 가 반환하는 dict 행 리스트와 같은 포맷.
    메모리-only 모드(이슈 8 fallback) 에서 사용."""
    rows = []
    for i, (label, option, enabled, group, desc) in enumerate(DEFAULT_OPTIONS, start=2):
        rows.append({
            "label": label,
            "option": option,
            "enabled": str(enabled) == "1",
            "group": group,
            "desc": desc,
            "lineno": i,
        })
    return rows


def _exposure_guide_for(key):
    """SERVICE_EXPOSURE_GUIDE 항목을 4-tuple (위험도, 노출위험, 공격표면, 출처) 로 반환.
    구 schema (2-tuple) 도 호환해 빠진 필드는 빈 문자열."""
    e = SERVICE_EXPOSURE_GUIDE.get(key, ())
    if len(e) == 4:
        return e
    if len(e) == 2:
        # 구 schema: (노출위험, 공격표면) — 위험도/출처 비움
        return ("", e[0], e[1], "")
    return ("", "", "", "")


# categories.xlsx 13컬럼 권장 schema (첫 생성 시 사용 — 이후 사용자가 자유 이동/추가 가능)
CATEGORIES_STD_COLUMNS = [
    "서비스명", "표준포트", "프로토콜", "분류", "용도", "위험도",
    "암호화", "인증", "노출위험", "공격표면", "출처", "설명", "점검메모",
]
CATEGORIES_REQUIRED = ("서비스명",)  # 누락 시 에러


def default_categories_as_map():
    """DEFAULT_CATEGORIES + GUIDE dict 들 → load_categories_xlsx 와 같은 dict 포맷."""
    catmap = {}
    for tup in DEFAULT_CATEGORIES:
        if len(tup) >= 4:
            name, category, usage, desc = tup[0], tup[1], tup[2], tup[3]
        elif len(tup) == 3:
            name, category, usage, desc = tup[0], tup[1], "", tup[2]
        else:
            continue
        key = (name or "").strip().lower()
        if not key:
            continue
        risk, exposure, surface, source = _exposure_guide_for(key)
        port, proto, encryption, auth = _protocol_guide_for(key)
        catmap[key] = {
            "category": category, "usage": usage, "desc": desc,
            "risk": risk,
            "exposure_risk": exposure,
            "attack_surface": surface,
            "source": source,
            "port": port,
            "protocol": proto,
            "encryption": encryption,
            "auth": auth,
            "memo": "",
        }
    return catmap


def _build_default_category_row(name, category, usage, desc):
    """13컬럼 권장 순서로 한 행 만듦. 코드 dict 에서 표준포트/프로토콜/암호화/인증/위험도 등 보충."""
    key = (name or "").strip().lower()
    port, proto, encryption, auth = _protocol_guide_for(key)
    risk, exposure, surface, source = _exposure_guide_for(key)
    # std cols 순서: 서비스명, 표준포트, 프로토콜, 분류, 용도, 위험도, 암호화, 인증,
    #                노출위험, 공격표면, 출처, 설명, 점검메모
    return [name, port, proto, category, usage, risk, encryption, auth,
            exposure, surface, source, desc, ""]


def write_default_categories_xlsx(path):
    """categories.xlsx 가 없을 때 기본값으로 새 파일 작성 (13컬럼 권장 순서).
    schema: 서비스명 / 표준포트 / 프로토콜 / 분류 / 용도 / 위험도 /
            암호화 / 인증 / 노출위험 / 공격표면 / 출처 / 설명 / 점검메모
    사용자는 이후 Excel 에서 컬럼 자유 이동/추가 가능 — reader 가 헤더 이름 기반."""
    rows = [list(CATEGORIES_STD_COLUMNS)]
    for tup in DEFAULT_CATEGORIES:
        if len(tup) < 4:
            continue
        rows.append(_build_default_category_row(tup[0], tup[1], tup[2], tup[3]))
    # 컬럼 폭: 서비스명 / 표준포트 / 프로토콜 / 분류 / 용도 / 위험도 /
    #          암호화 / 인증 / 노출위험 / 공격표면 / 출처 / 설명 / 점검메모
    xlsx_io.write_xlsx(path, rows,
        col_widths=[20, 9, 11, 14, 12, 8, 22, 22, 38, 38, 36, 38, 26])


def load_categories_xlsx(path):
    """
    categories.xlsx 파싱 — **헤더 이름 기반** (컬럼 위치 무관, 사용자가 Excel 에서 자유 이동 가능).

    인식 헤더 (모두 선택, '서비스명' 만 필수):
      서비스명, 표준포트, 프로토콜, 분류, 용도, 위험도, 암호화, 인증,
      노출위험, 공격표면, 출처, 설명, 점검메모

    구버전 호환 (헤더 일부 누락):
      누락된 컬럼은 SERVICE_PROTOCOL_GUIDE / SERVICE_EXPOSURE_GUIDE 코드 dict 에서 자동 보충.
    사용자 추가 비표준 컬럼 (예: '담당자', '점검일자') 은 무시 (저장 시 그대로 보존하려면 마이그 스크립트 사용).

    리턴: ({서비스명_lower: {...}}, errors)
    """
    catmap = {}
    errors = []
    try:
        all_rows = xlsx_io.read_xlsx(path)
    except Exception as e:
        return {}, [f"categories.xlsx 읽기 실패: {e}"]
    if not all_rows:
        return {}, ["categories.xlsx 가 비어 있음."]

    header = [(c or "").strip() for c in all_rows[0]]
    # 헤더 이름 → 컬럼 인덱스 (위치 무관)
    col_idx = {h: i for i, h in enumerate(header) if h}

    # 필수 컬럼 검증
    for req in CATEGORIES_REQUIRED:
        if req not in col_idx:
            return {}, [f"필수 컬럼 '{req}' 가 categories.xlsx 헤더에 없음. "
                        f"현재 헤더: {header}"]

    def cell(row, col_name, default=""):
        i = col_idx.get(col_name)
        if i is None or i >= len(row):
            return default
        v = row[i]
        return (v or "").strip() if v is not None else default

    for i, row in enumerate(all_rows[1:], start=2):
        if not row or all(not (c or "").strip() for c in row):
            continue
        name = cell(row, "서비스명").lower()
        if not name:
            continue

        # 코드 dict 에서 default 보충
        guide_risk, guide_exposure, guide_surface, guide_source = _exposure_guide_for(name)
        guide_port, guide_proto, guide_encryption, guide_auth = _protocol_guide_for(name)

        # 분류/용도가 빈 칸이면 default DEFAULT_CATEGORIES 에서도 못 가져옴 (없으면 빈 칸 OK)
        category = cell(row, "분류")
        if not category:
            # DEFAULT_CATEGORIES 에서 보충
            for tup in DEFAULT_CATEGORIES:
                if len(tup) >= 4 and (tup[0] or "").strip().lower() == name:
                    category = tup[1]
                    break
            if not category:
                # 사용자가 분류 비웠으면 그래도 등록 (errors 에 warn 만)
                errors.append(f"{i}번째 행 '{name}': 분류 컬럼 비어 있음 — DEFAULT_CATEGORIES 에도 매핑 없음")
                category = "미분류"

        catmap[name] = {
            "category": category,
            "usage": cell(row, "용도"),
            "desc": cell(row, "설명"),
            "risk": cell(row, "위험도") or guide_risk,
            "exposure_risk": cell(row, "노출위험") or guide_exposure,
            "attack_surface": cell(row, "공격표면") or guide_surface,
            "source": cell(row, "출처") or guide_source,
            "port": cell(row, "표준포트") or guide_port,
            "protocol": cell(row, "프로토콜") or guide_proto,
            "encryption": cell(row, "암호화") or guide_encryption,
            "auth": cell(row, "인증") or guide_auth,
            "memo": cell(row, "점검메모"),  # 점검메모는 default 없음 — 사용자 입력 only
        }
    return catmap, errors

# (라벨, 옵션, 활성화, 그룹, 상세설명) — options.xlsx 가 없으면 이 셋으로 새로 만들어짐.
# 그룹 == "" → 독립 체크박스. 그룹 != "" → 같은 그룹끼리 라디오 (택 1).
# 상세설명 비어 있으면 툴팁 안 뜸. 채워져 있으면 hover 시 노란 툴팁 표시.
DEFAULT_OPTIONS = [
    ("응답 없는 호스트도 강제로 스캔", "-Pn", "1", "",
     "ICMP/ARP 호스트 디스커버리를 건너뜀. ICMP 차단 호스트 누락 방지. 죽은 IP까지 풀 포트 스윕하므로 시간이 약간 증가하지만 누락은 0."),
    ("DNS 역조회 안 함", "-n", "1", "",
     "PTR 역조회 시도하지 않음. 호스트가 많을수록 시간 단축 효과 큼. 결과에 호스트명이 안 들어가는 단점."),

    # ---- TCP 스캔 타입 (라디오 - 항상 택 1) — phase1 default = SYN
    ("SYN", "-sS", "1", "TCP 스캔 타입",
     "Half-open TCP SYN 스캔 (-sS). raw socket 권한(=관리자) 필요. 타겟에 완전한 TCP 연결을 안 만들어 stealth, 빠름. 권한 없으면 nmap이 자동으로 -sT 로 폴백."),
    ("Connect", "-sT", "0", "TCP 스캔 타입",
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

    # ---- 비그룹 옵션 (phase1 default — 사용자 기준 명령에 맞춰 활성=1 일괄 셋)
    ("UDP 주요 포트 스캔",
     "-sU -p U:7,53,67,68,69,88,123,135,137,138,139,161,162,389,400,500,514,520,623,1900,2049,4500,5060,5353,5355,11211", "1", "",
     "UDP 스캔 + 자주 쓰이는 26 포트 (DNS, NetBIOS, SNMP, Kerberos, IKE, SIP, NTP, NFS, mDNS 등). UDP 는 RST 응답 없어 느림. -p T:... 와 합쳐 단일 -p T:...,U:... 로 출력."),
    ("TCP 모든 포트 (1-65535)", "-p T:1-65535", "1", "",
     "TCP 65535 포트 전부 SYN 보냄. T4 기준 호스트당 5~15분. 전수 점검용 (phase1 기본)."),
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
    ("RST 제한 우회", "--defeat-rst-ratelimit", "1", "",
     "Linux tcp_challenge_ack_limit 같은 RST throttle 우회. closed 포트가 timeout 으로 filtered 오인되는 것 방지. 정확도 보호."),
    ("호스트그룹 64", "--min-hostgroup 64", "1", "",
     "한 번에 64개 호스트를 병렬로 스캔. /24 같은 큰 대역 스캔 시 처리량 증가."),
    ("동시 처리 100", "--max-parallelism 100", "1", "",
     "동시 in-flight probe 100개까지. 빠른 네트워크에서 처리량 증가."),
    ("Aggressive 모드 (-A)", "-A", "0", "",
     "공격적 옵션 묶음 (-O OS 식별 + -sV + -sC default NSE + --traceroute). phase1 default 에는 미포함."),
    ("OS 탐지 (-O)", "-O", "0", "",
     "OS 핑거프린팅. raw socket 권한(=관리자) 필요. 일반 사용자 권한이면 nmap 이 무시. "
     "결과는 CSV 의 OS 컬럼에 채워짐 (정확도 % 포함). 기본 비활성."),
    ("진행 stats 1분마다 출력 (--stats-every 1m)", "--stats-every 1m", "1", "",
     "1분마다 nmap 이 진행률 stats 라인을 stdout 에 강제로 씀. GUI 로그창이 buffer 때문에 한참 비어 보이는 문제 방지. 끄지 않는 것 권장."),

    # ---- NSE (옵션이 --script 로 시작하면 NSE 패널로 자동 분류) — phase1 default 활성=1 셋
    ("HTTP 식별", "--script http-headers,http-server-header,http-title", "1", "",
     "HTTP 응답 헤더, 서버 헤더, 페이지 타이틀 추출. 웹 서버 종류와 페이지 정보 빠르게 파악."),
    ("TLS 인증서 식별 (CN/SAN/Issuer)", "--script ssl-cert", "1", "",
     "TLS 인증서의 CN, SAN(Subject Alternative Name), Issuer, Validity 추출. 인증서가 내부 호스트명을 노출시키므로 점검 핵심."),
    ("TLS cipher / ALPN 식별", "--script ssl-enum-ciphers,tls-alpn", "1", "",
     "지원 TLS 버전, cipher suite, ALPN 프로토콜 (h2/http/1.1). 약한 cipher 사용 여부 확인용."),
    ("SSH 호스트키", "--script ssh-hostkey", "1", "",
     "SSH 호스트 키 fingerprint (RSA/ECDSA/ED25519) 추출. 호스트 식별 + 키 재사용 탐지."),
    ("SMB 식별", "--script nbstat,smb-os-discovery,smb-protocols", "1", "",
     "Windows OS 버전, 도메인, NetBIOS 이름, SMB 버전. AD 환경 점검 필수. (phase1: smb-security-mode 제외)"),
    ("DBMS 식별 (MS-SQL / Oracle)", "--script ms-sql-info,oracle-tns-version", "1", "",
     "MS-SQL Server, Oracle TNS 버전 정보. (phase1: mysql/mongodb/redis 별도 NSE 미포함)"),
    ("RDP 식별", "--script rdp-ntlm-info", "1", "",
     "RDP NTLM 정보 (호스트명/도메인). (phase1: rdp-enum-encryption / vnc-info / ajp-headers 미포함)"),
    ("UDP 응용 식별 (SNMP/IKE/SIP/NTP)", "--script snmp-info,ike-version,sip-methods,ntp-info", "1", "",
     "SNMP community / OID, IKE/IPsec 버전, SIP 지원 method, NTP 서버 정보. UDP 스캔(-sU)과 함께 써야 의미."),
    ("RPC 정보", "--script rpcinfo", "1", "",
     "Sun RPC (portmapper) 서비스 매핑. NFS, NIS 등 RPC 기반 서비스 식별."),
    ("LDAP/AD 식별", "--script ldap-rootdse", "0", "",
     "LDAP root DSE 정보 추출. AD/LDAP 서버 도메인, naming context. (phase1 default: 0)"),
    ("raw 응답 캡처 (식별 실패 포트)", "--script fingerprint-strings", "1", "",
     "식별 실패한 포트의 원본 응답 바이트 캡쳐 (fingerprint-strings). unknown 서비스 수동 분석 필수."),

    # ---- 서비스 커버리지 보강 (이슈 11)
    ("FTP 익명 로그인 / 시스템 식별",
     "--script ftp-anon,ftp-syst", "1", "",
     "FTP 익명 로그인 허용 여부 + SYST 응답(서버 OS/제품). 외부 노출 FTP 점검 핵심."),
    ("Telnet 암호화 지원 식별",
     "--script telnet-encryption", "1", "",
     "Telnet 서버 RFC2946 암호화 지원 여부. 미지원이면 평문 노출."),
    ("DNS 재귀 응답 / 서버 식별 (NSID)",
     "--script dns-recursion,dns-nsid", "1", "",
     "외부 open resolver 여부 + 서버 식별자(NSID, BIND 버전 등). 외부 DNS 점검 1순위."),
    ("VNC 식별 (버전 / 보안 타입 / 타이틀)",
     "--script vnc-info,vnc-title", "1", "",
     "VNC 서버 protocol 버전, 지원 security type(none/VNCAuth/TLS), 데스크톱 타이틀."),
    ("NTP monlist (DDoS amp 위험)",
     "--script ntp-monlist", "1", "",
     "ntpdc monlist 응답 — DDoS amplification 가능 여부. -sU 와 함께 의미."),
    ("일반 배너 캡처 (Rlogin / RSH 등 보완)",
     "--script banner", "0", "",
     "포트 첫 수십 바이트 그대로 캡처. Rlogin/RSH 등 NSE 직접 스크립트가 부족한 서비스 식별 보완. 기본 OFF."),
    ("SSH 인증 방식 / 알고리즘 (선택)",
     "--script ssh-auth-methods,ssh2-enum-algos", "0", "",
     "지원 인증(passwd/pubkey/keyboard) 및 KEX/cipher/MAC 알고리즘 목록. 약한 알고리즘 노출 식별. ssh-hostkey 보다 무거워 default OFF."),
    ("SNMP sysDescr (선택)",
     "--script snmp-sysdescr", "0", "",
     "snmp-info 의 community probe 보다 단순한 sysDescr 단독 조회. 빠른 SNMP 식별. 기본 OFF."),
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
    if not header:
        return [], ["options.xlsx 의 헤더가 비어 있습니다."]
    normalized = [(c or "").strip() for c in header]
    # 헤더 이름 → 컬럼 인덱스 (위치 무관 — 사용자가 Excel 에서 컬럼 자유 이동 가능)
    col_idx = {h: i for i, h in enumerate(normalized) if h}
    required = ["스캔 옵션", "옵션", "활성화"]
    missing = [r for r in required if r not in col_idx]
    if missing:
        return [], [f"options.xlsx 필수 헤더 누락: {missing} (현재 헤더: {normalized})"]

    def cell(row, col_name, default=""):
        i = col_idx.get(col_name)
        if i is None or i >= len(row):
            return default
        v = row[i]
        return v if v is not None else default

    for i, row in enumerate(all_rows[1:], start=2):
        if not row or all(not (c or "").strip() for c in row):
            continue
        label = (cell(row, "스캔 옵션") or "").strip()
        option = (cell(row, "옵션") or "").strip()
        enabled_raw = (cell(row, "활성화") or "").strip()
        group = (cell(row, "그룹") or "").strip()
        # 상세설명은 줄바꿈 보존 (strip 안 함)
        desc = cell(row, "상세설명") or ""
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
    """nmap 실행 파일 탐색.
    우선순위:
      1. NMAPPARSER_NMAP_EXE 환경변수 (회사 이미지에서 비표준 위치 강제 가능)
      2. C:\\Program Files (x86)\\Nmap\\nmap.exe
      3. C:\\Program Files\\Nmap\\nmap.exe
      4. _app_dir()/nmap.exe (동봉 케이스)
      5. shutil.which("nmap") — PATH 등록된 비표준 설치 (예: chocolatey, scoop, MSYS2)
    """
    env_path = os.environ.get("NMAPPARSER_NMAP_EXE", "").strip()
    if env_path and os.path.isfile(env_path):
        return env_path
    here = _app_dir()
    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.join(here, "nmap.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    # PATH 에 등록된 nmap 자동 탐지 (chocolatey, scoop 등)
    import shutil as _shutil
    found = _shutil.which("nmap")
    if found and os.path.isfile(found):
        return found
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


# tk Text 위젯에 BEL 들어가면 Windows system sound 재생 — log 출력 전 strip.
_LOG_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _quote_win(s):
    """Windows cmd 스타일 인용 (공백/특수문자 포함 시)."""
    if s and not re.search(r"[\s\"<>|&^]", s):
        return s
    return '"' + s.replace('"', '\\"') + '"'


# ============================================================ identification + remarks

def compute_identification_status(svc_el):
    """XML <service> 요소를 분석해 식별 상태 4값 중 하나 리턴.
    확인 / 추측 / tcpwrapped / 미확인"""
    if svc_el is None:
        return "미확인"
    name = (svc_el.get("name") or "").strip()
    method = (svc_el.get("method") or "").strip()
    if not name or name == "unknown":
        return "미확인"
    if name == "tcpwrapped":
        return "tcpwrapped"
    if method == "probed":
        return "확인"
    if method == "table":
        return "추측"
    return "미확인"


# (script_id_substring, label, regex) — NSE 결과에서 한 줄 요약 추출용
_REMARK_PATTERNS = [
    ("ssl-cert", "CN", re.compile(r"commonName=([^\n,/]+)")),
    ("smb-os-discovery", "OS", re.compile(r"OS:\s*([^\n]+)")),
    ("smb-os-discovery", "host", re.compile(r"Computer name:\s*([^\n]+)")),
    ("rdp-ntlm-info", "DNS_Computer_Name", re.compile(r"DNS_Computer_Name:\s*([^\n]+)")),
    ("rdp-ntlm-info", "Target_Name", re.compile(r"Target_Name:\s*([^\n]+)")),
    ("nbstat", "host", re.compile(r"Computer name:\s*([^\n]+)")),
    ("http-title", "title", re.compile(r"\A\s*([^\n]+)")),
]


def extract_key_line(script_id, output):
    """NSE 한 스크립트 출력에서 핵심 한 줄 키-값 추출. 없으면 빈 문자열."""
    if not output:
        return ""
    sid = (script_id or "").lower()
    for sid_match, label, regex in _REMARK_PATTERNS:
        if sid_match in sid:
            m = regex.search(output)
            if m:
                val = m.group(1).strip(" \t,")
                if not val:
                    continue
                if "doesn't have a title" in val.lower():
                    continue
                # 한 셀에 들어갈 수 있게 너무 길면 자름
                if len(val) > 80:
                    val = val[:77] + "..."
                return f"{label}={val}"
    return ""


def compute_remarks(detail, nse_data):
    """비고 컬럼 — detail 우선, 그 다음 NSE key-line 1~2개. 멀티라인 절대 X.
    nse_data = [(script_id, output), ...]"""
    parts = []
    if detail:
        parts.append(detail)
    for sid, out in (nse_data or []):
        key = extract_key_line(sid, out)
        if key and key not in parts:
            parts.append(key)
            if len(parts) >= 2:
                break
    return ", ".join(parts)


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


def _fmt_option_label(row):
    """옵션 라벨 표시 포맷: '[-sS] SYN' / '[--script ssh-hostkey] SSH 호스트키'.
    옵션 문자열이 길면 첫 토큰만 표시 ('[--script] HTTP 식별').
    """
    opt = (row.get("option") or "").strip()
    label = row.get("label") or ""
    if not opt:
        return label
    head = opt if len(opt) <= 24 else opt.split()[0]
    return f"[{head}] {label}"


def _is_udp_related(option_str):
    """option 문자열이 UDP 스캔과 직접 관련 있으면 True.
    조건: '-sU' 토큰 포함, 또는 '-p' 값 / '-p<value>' 의 값이 'U:' 포함.
    """
    if not option_str:
        return False
    toks = option_str.split()
    if "-sU" in toks:
        return True
    for i, t in enumerate(toks):
        if t == "-p" and i + 1 < len(toks) and "U:" in toks[i + 1]:
            return True
        if t.startswith("-p") and len(t) > 2 and "U:" in t[2:]:
            return True
    return False


def _user_data_dir():
    """OS 별 쓰기 가능한 사용자 데이터 폴더. 없으면 생성 시도.
    - Windows: %APPDATA%\\nmapParser
    - macOS:   ~/Library/Application Support/nmapParser
    - 그 외:   $XDG_CONFIG_HOME/nmapParser 또는 ~/.config/nmapParser
    """
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    d = os.path.join(base, "nmapParser")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _is_dir_writable(path):
    """파일을 실제로 한 번 써 보고 지움 — read-only 폴더(예: Program Files) 감지.

    회사 보안 환경의 AV 필터드라이버는 짧은 PermissionError / FileNotFoundError /
    OSError 를 던질 수 있으므로 모두 False 처리. probe 파일명에 PID 를 섞어
    동시 실행 충돌 방지.
    """
    if not path or not os.path.isdir(path):
        return False
    probe = os.path.join(path, f".nmapParser_write_probe.{os.getpid()}")
    try:
        with open(probe, "w") as f:
            f.write("")
        try:
            os.remove(probe)
        except OSError:
            pass  # 못 지워도 쓰기는 됐으니 OK
        return True
    except (OSError, PermissionError, FileNotFoundError):
        return False
    except Exception:
        # AV 필터드라이버가 별도 예외를 던질 수도 있음 — 모두 False
        return False


_DATA_DIR_PIN_NAME = "data_dir.txt"      # 구버전 호환 (단일 폴더만 저장)
_CONFIG_JSON_NAME = "config.json"        # {data_dir, options_xlsx, categories_xlsx}


def _read_pin_config():
    """user_data_dir 의 config.json 을 읽음.
    구버전 data_dir.txt 만 있을 경우엔 {"data_dir": ...} 로 변환 반환.
    """
    udd = _user_data_dir()
    cfg = {}
    try:
        p = os.path.join(udd, _CONFIG_JSON_NAME)
        if os.path.isfile(p):
            import json
            with open(p, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                cfg = obj
    except (OSError, ValueError):
        cfg = {}
    if not cfg:
        # 구버전 data_dir.txt 폴백
        try:
            old = os.path.join(udd, _DATA_DIR_PIN_NAME)
            if os.path.isfile(old):
                with open(old, "r", encoding="utf-8") as f:
                    d = f.read().strip()
                if d:
                    cfg = {"data_dir": d}
        except OSError:
            pass
    return cfg


def _write_pin_config(cfg):
    """config.json 에 기록. 실패해도 조용히 넘어감."""
    try:
        import json
        p = os.path.join(_user_data_dir(), _CONFIG_JSON_NAME)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def _read_pinned_data_dir():
    """구버전 호환 — 새 코드는 _read_pin_config() 사용 권장."""
    return _read_pin_config().get("data_dir") or None


def _write_pinned_data_dir(path):
    """구버전 호환 — config.json 의 data_dir 항목을 갱신."""
    cfg = _read_pin_config()
    cfg["data_dir"] = path or ""
    return _write_pin_config(cfg)


def _temp_data_dir():
    """tempfile.gettempdir() 하위에 nmapParser/ 를 만들어 반환. 실패 시 None.
    회사 보안 환경에서 %APPDATA% 까지 막혔을 때 마지막 디스크 fallback.
    """
    try:
        d = os.path.join(tempfile.gettempdir(), "nmapParser")
        os.makedirs(d, exist_ok=True)
        return d
    except OSError:
        return None


def _resolve_paths():
    """각 설정 파일 경로를 결정. 우선순위:
      1. NMAPPARSER_DATA_DIR 환경변수 (회사 이미지 / 강제 override)
      2. config.json 의 개별 파일 핀 (options_xlsx / categories_xlsx) — 파일 실존 시
      3. config.json 의 data_dir
      4. _app_dir() — 기존 xlsx 가 있거나 쓰기 가능한 경우
      5. _user_data_dir() — %APPDATA%\\nmapParser 등
      6. tempfile.gettempdir()/nmapParser — APPDATA 도 막힌 환경
      7. None (메모리-only 모드 신호)
    리턴: (data_dir | None, options_xlsx_path | None, categories_xlsx_path | None,
           memory_only: bool)
    """
    # 1) 환경변수 최우선 — 존재하고 쓰기 가능하면 즉시 채택
    env_dir = os.environ.get("NMAPPARSER_DATA_DIR", "").strip()
    if env_dir:
        try:
            os.makedirs(env_dir, exist_ok=True)
        except OSError:
            pass
        if os.path.isdir(env_dir) and _is_dir_writable(env_dir):
            return (env_dir,
                    os.path.join(env_dir, OPTIONS_XLSX_NAME),
                    os.path.join(env_dir, CATEGORIES_XLSX_NAME),
                    False)

    cfg = _read_pin_config()

    # 4)→2)→3) 순회로 data_dir 결정
    pinned_dir = cfg.get("data_dir")
    data_dir = None
    if pinned_dir and os.path.isdir(pinned_dir) and _is_dir_writable(pinned_dir):
        data_dir = pinned_dir
    else:
        here = _app_dir()
        has_existing = (
            os.path.isfile(os.path.join(here, OPTIONS_XLSX_NAME))
            or os.path.isfile(os.path.join(here, CATEGORIES_XLSX_NAME))
        )
        if has_existing or _is_dir_writable(here):
            data_dir = here
        else:
            udd = _user_data_dir()
            if udd and _is_dir_writable(udd):
                data_dir = udd
            else:
                tmp = _temp_data_dir()
                if tmp and _is_dir_writable(tmp):
                    data_dir = tmp

    if data_dir is None:
        # 메모리-only 모드 — 모든 디스크 쓰기 불가
        return (None, None, None, True)

    # 개별 파일 핀 (파일 실존 시에만 적용)
    pinned_opt = cfg.get("options_xlsx")
    options_path = (pinned_opt
                    if (pinned_opt and os.path.isfile(pinned_opt))
                    else os.path.join(data_dir, OPTIONS_XLSX_NAME))

    pinned_cat = cfg.get("categories_xlsx")
    categories_path = (pinned_cat
                       if (pinned_cat and os.path.isfile(pinned_cat))
                       else os.path.join(data_dir, CATEGORIES_XLSX_NAME))

    return data_dir, options_path, categories_path, False


def _resolve_data_dir():
    """구버전 호환 — _resolve_paths() 의 data_dir 만 반환 (None 일 수도 있음)."""
    return _resolve_paths()[0]


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



def load_categories_for_cli(categories_xlsx_path=None):
    """CLI 변환용 categories map 로드. 실패/미존재 시 기본값 사용."""
    if categories_xlsx_path and os.path.isfile(categories_xlsx_path):
        catmap, _errors = load_categories_xlsx(categories_xlsx_path)
        if catmap:
            return catmap
    return default_categories_as_map()


def convert_xml_to_csv_standalone(xml_path, csv_path, open_only=False, categories_xlsx_path=None, services_table=None):
    """GUI 없이 XML->CSV 단독 변환."""
    categories = load_categories_for_cli(categories_xlsx_path)
    if services_table is None:
        nmap_exe = find_nmap_exe()
        services_table = parse_nmap_services(nmap_exe) if nmap_exe else {}

    def _lookup_full_local(probed_name, guessed_name):
        for n in (probed_name, guessed_name):
            if n:
                key = n.rstrip("?").strip().lower()
                if key and key in categories:
                    info = categories[key]
                    return {
                        "category": info.get("category", "미분류"),
                        "usage": info.get("usage", ""),
                        "risk": info.get("risk", ""),
                        "encryption": info.get("encryption", ""),
                        "auth": info.get("auth", ""),
                        "port": info.get("port", ""),
                        "protocol": info.get("protocol", ""),
                        "exposure_risk": info.get("exposure_risk", ""),
                        "attack_surface": info.get("attack_surface", ""),
                        "source": info.get("source", ""),
                        "memo": info.get("memo", ""),
                    }
        return {"category": "미분류", "usage": "", "risk": "",
                "encryption": "", "auth": "", "port": "", "protocol": "",
                "exposure_risk": "", "attack_surface": "", "source": "", "memo": ""}

    root = parse_nmap_xml_resilient(xml_path)
    rows = []

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

        hostname = ""
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            first_hn = hostnames_el.find("hostname")
            if first_hn is not None:
                hostname = first_hn.get("name", "") or ""

        os_str = ""
        os_el = host.find("os")
        if os_el is not None:
            best = None
            for m in os_el.findall("osmatch"):
                try:
                    acc = int(m.get("accuracy", "0") or "0")
                except ValueError:
                    acc = 0
                if best is None or acc > best[1]:
                    best = (m.get("name", "") or "", acc)
            if best and best[0]:
                os_str = f"{best[0]} ({best[1]}%)" if best[1] else best[0]

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
            guessed = services_table.get((portnum, proto), "")
            svc_el = port.find("service")
            if svc_el is not None:
                name = svc_el.get("name", "") or ""
                method = svc_el.get("method", "") or ""
                product = svc_el.get("product", "") or ""
                version = svc_el.get("version", "") or ""
                extrainfo = svc_el.get("extrainfo", "") or ""
                ostype = svc_el.get("ostype", "") or ""
                if method == "probed":
                    probed_short = name
                elif method == "table":
                    probed_short = f"{name}?" if name else ""
                else:
                    probed_short = name
                detail = " ".join(p for p in (product, version, extrainfo, ostype) if p).strip()
            else:
                probed_short = ""
                detail = ""

            lookup = _lookup_full_local(probed_short, guessed)
            identification = compute_identification_status(svc_el)
            scripts = port.findall("script")
            nse_data = [(sc.get("id", "") or "", sc.get("output", "") or "") for sc in scripts]
            remarks = compute_remarks(detail, nse_data)
            sids_joined = ", ".join(sid for sid, _ in nse_data if sid)
            output_lines = []
            for sid, raw in nse_data:
                cleaned = (raw or "").replace("\r", " ").replace("\n", " | ")
                output_lines.append(f"[{sid}] {cleaned}" if sid else cleaned)
            output_joined = "\n".join(output_lines)

            # NSE 추출 (24번째 컬럼) — TLS_CN, SMB_OS, NTLM_Computer 등 키-값 한 줄.
            # nse_extract 모듈이 없거나 실패해도 빈 문자열로 안전 처리.
            nse_summary = ""
            if nse_extract is not None and nse_data:
                try:
                    merged = nse_extract.extract_all_nse(nse_data)
                    nse_summary = nse_extract.format_nse_summary(merged)
                except Exception:
                    nse_summary = ""

            rows.append([
                addr, hostname, os_str,
                proto, portid, lookup.get("port", ""),
                state, guessed, probed_short,
                identification,
                lookup.get("category", ""), lookup.get("usage", ""),
                lookup.get("risk", ""),
                lookup.get("encryption", ""), lookup.get("auth", ""),
                lookup.get("exposure_risk", ""), lookup.get("attack_surface", ""),
                lookup.get("source", ""),
                detail, remarks,
                sids_joined, output_joined,
                nse_summary,
                lookup.get("memo", ""),
            ])

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "IP", "호스트", "OS",
            "프로토콜", "포트", "표준포트",
            "포트상태", "추측서비스", "확인서비스(short)",
            "식별", "분류", "용도",
            "위험도", "암호화", "인증",
            "노출위험", "공격표면", "출처",
            "상세(제품/버전)", "비고",
            "NSE스크립트명", "스크립트출력",
            "NSE추출",
            "점검메모",
        ])
        for r in rows:
            w.writerow(r)


def run_cli_xml2csv(args):
    xml_input = args.xml2csv
    out_dir = args.out or os.path.dirname(os.path.abspath(xml_input)) or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)

    if os.path.isdir(xml_input):
        xml_files = sorted([os.path.join(xml_input, n) for n in os.listdir(xml_input) if n.lower().endswith('.xml')])
    else:
        xml_files = [xml_input]

    if not xml_files:
        print('[xml2csv] 변환 대상 xml 파일이 없습니다.')
        return 1

    nmap_exe = find_nmap_exe()
    services_table = parse_nmap_services(nmap_exe) if nmap_exe else {}

    ok_count = 0
    _set_system_awake(True)
    try:
        for xml_path in xml_files:
            if not os.path.isfile(xml_path):
                print(f'[xml2csv] 파일 없음: {xml_path}')
                continue
            base = os.path.splitext(os.path.basename(xml_path))[0]
            csv_path = os.path.join(out_dir, base + '.csv')
            try:
                convert_xml_to_csv_standalone(xml_path, csv_path, open_only=args.open_only,
                                              categories_xlsx_path=args.categories,
                                              services_table=services_table)
                ok_count += 1
                print(f'[xml2csv] OK: {xml_path} -> {csv_path}')
            except (ET.ParseError, OSError) as e:
                print(f'[xml2csv] FAIL: {xml_path} ({e})')
    finally:
        _set_system_awake(False)

    return 0 if ok_count else 1


def _normalize_for_diff(s):
    t = (s or "").strip().lower()
    return re.sub(r"\s+", " ", t)


def _digest_for_diff(*parts):
    base = "||".join(_normalize_for_diff(p) for p in parts)
    return hashlib.sha256(base.encode("utf-8", errors="replace")).hexdigest()


def parse_nmap_xml_resilient(xml_path):
    """중단/절전 등으로 XML tail 이 깨진 경우 가능한 범위에서 host 단위 복구 파싱."""
    try:
        return ET.parse(xml_path).getroot()
    except ET.ParseError:
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        last_host_end = text.rfind("</host>")
        if last_host_end == -1 or "<nmaprun" not in text:
            raise
        recovered = text[: last_host_end + len("</host>")] + "\n</nmaprun>\n"
        return ET.fromstring(recovered)


def _set_system_awake(enable):
    """Windows 절전 억제 토글. 비-Windows/실패 시 조용히 무시."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ES_CONTINUOUS = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001
        ES_AWAYMODE_REQUIRED = 0x00000040
        if enable:
            ctypes.windll.kernel32.SetThreadExecutionState(
                ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
            )
        else:
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
    except Exception:
        pass


def parse_csv_rows_for_diff(csv_path):
    rows = []
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            # 한국어 컬럼명 (도구가 출력하는 실제 헤더) 우선, 영문 fallback 은 v0.2 호환 / 외부 파이프라인용.
            ip = (row.get("IP") or row.get("ip") or "").strip()
            proto = ((row.get("프로토콜") or row.get("PROTO") or row.get("proto") or "").strip().lower())
            port = (row.get("포트") or row.get("PORT") or row.get("port") or "").strip()
            state = (row.get("포트상태") or row.get("STATE") or row.get("state") or "").strip().lower()
            service = (row.get("확인서비스(short)") or row.get("확인서비스") or row.get("SERVICE") or row.get("service") or "").strip()
            detail = (row.get("상세(제품/버전)") or row.get("상세") or row.get("DETAIL") or row.get("detail") or "").strip()
            nse = (row.get("스크립트출력") or row.get("NSE") or row.get("nse") or "").strip()
            # 24번째 컬럼: NSE추출 (key=value; ...) — 있을 때 digest 에 합산해 변경 감지 정밀도 향상.
            nse_summary = (row.get("NSE추출") or "").strip()
            if nse_summary:
                nse = (nse + "\n" + nse_summary) if nse else nse_summary
            if not (ip and proto and port):
                continue
            rows.append({
                "ip": ip,
                "proto": proto,
                "port": str(port),
                "state": state,
                "service": service,
                "detail": detail,
                "digest": _digest_for_diff(service, detail, nse),
            })
    return rows


def parse_xml_rows_for_diff(xml_path):
    rows = []
    root = parse_nmap_xml_resilient(xml_path)
    for host in root.findall("host"):
        ip = ""
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
                break
        if not ip:
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv6", "mac"):
                    ip = a.get("addr", "")
                    break
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            portid = (port.get("portid", "") or "").strip()
            proto = (port.get("protocol", "") or "").strip().lower()
            state_el = port.find("state")
            state = (state_el.get("state", "") if state_el is not None else "").strip().lower()
            svc_el = port.find("service")
            service = ""
            detail = ""
            if svc_el is not None:
                service = (svc_el.get("name", "") or "").strip()
                product = svc_el.get("product", "") or ""
                version = svc_el.get("version", "") or ""
                extrainfo = svc_el.get("extrainfo", "") or ""
                ostype = svc_el.get("ostype", "") or ""
                detail = " ".join(p for p in (product, version, extrainfo, ostype) if p).strip()
            scripts = port.findall("script")
            nse = "\n".join((sc.get("output", "") or "") for sc in scripts)
            if not (ip and proto and portid):
                continue
            rows.append({
                "ip": ip,
                "proto": proto,
                "port": str(portid),
                "state": state,
                "service": service,
                "detail": detail,
                "digest": _digest_for_diff(service, detail, nse),
            })
    return rows


def parse_rows_for_diff(path):
    low = path.lower()
    if low.endswith(".xml"):
        return parse_xml_rows_for_diff(path)
    return parse_csv_rows_for_diff(path)




def _safe_stem_for_path(path):
    stem = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r'[^A-Za-z0-9._-]+', '_', stem) or 'file'

def run_cli_diff(args):
    _set_system_awake(True)
    try:
        if not os.path.isfile(args.base):
            raise OSError(f"기준 파일이 없습니다: {args.base}")
        if not os.path.isfile(args.curr):
            raise OSError(f"현재 파일이 없습니다: {args.curr}")
        base_rows = parse_rows_for_diff(args.base)
        curr_rows = parse_rows_for_diff(args.curr)
        asset_id = args.asset or "default"
        out_dir = args.out or os.path.dirname(os.path.abspath(args.curr)) or os.getcwd()
        os.makedirs(out_dir, exist_ok=True)

        def keyf(r):
            return (asset_id, r["ip"], r["proto"], r["port"])

        base_map = {keyf(r): r for r in base_rows}
        curr_map = {keyf(r): r for r in curr_rows}
        all_keys = sorted(set(base_map) | set(curr_map))
        diff_rows = []
        snapshot_rows = []
        summary = {"NEW_OPEN": 0, "CLOSED": 0, "CHANGED": 0, "UNCHANGED": 0}

        for k in all_keys:
            b = base_map.get(k)
            c = curr_map.get(k)
            if b is None and c is not None and c.get("state") == "open":
                change = "NEW_OPEN"
            elif b is not None and b.get("state") == "open" and (c is None or c.get("state") != "open"):
                change = "CLOSED"
            elif b is not None and c is not None:
                changed_fields = []
                for fld in ("state", "service", "detail", "digest"):
                    if _normalize_for_diff(b.get(fld, "")) != _normalize_for_diff(c.get(fld, "")):
                        changed_fields.append(fld)
                change = "CHANGED" if changed_fields else "UNCHANGED"
            else:
                change = "UNCHANGED"

            summary[change] = summary.get(change, 0) + 1
            if args.only_changes and change == "UNCHANGED":
                continue
            changed_fields_txt = ""
            if b is not None and c is not None:
                changed_fields_txt = ",".join(
                    fld for fld in ("state", "service", "detail", "digest")
                    if _normalize_for_diff(b.get(fld, "")) != _normalize_for_diff(c.get(fld, ""))
                )
            diff_rows.append([
                change, asset_id, k[1], k[2], k[3],
                (b or {}).get("state", ""), (c or {}).get("state", ""),
                (b or {}).get("service", ""), (c or {}).get("service", ""),
                (b or {}).get("detail", ""), (c or {}).get("detail", ""),
                (b or {}).get("digest", ""), (c or {}).get("digest", ""),
                changed_fields_txt,
            ])

        for r in curr_rows:
            snapshot_rows.append([asset_id, r["ip"], r["proto"], r["port"], r["state"], r["service"], r["detail"], r["digest"]])

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_stem = _safe_stem_for_path(args.base)
        curr_stem = _safe_stem_for_path(args.curr)
        diff_path = os.path.join(out_dir, f"diff_{base_stem}_vs_{curr_stem}_{stamp}.csv")
        summary_path = os.path.join(out_dir, f"summary_{base_stem}_vs_{curr_stem}_{stamp}.csv")
        snapshot_path = os.path.join(out_dir, f"snapshot_{curr_stem}_{stamp}.csv")

        out_format = (getattr(args, "out_format", None) or "both").lower()
        wrote_csv = out_format in ("csv", "both")
        wrote_xlsx = out_format in ("xlsx", "both")

        diff_headers = ["change_type", "asset_id", "key_ip", "key_proto", "key_port",
                        "base_state", "curr_state", "base_service", "curr_service",
                        "base_detail", "curr_detail", "base_digest", "curr_digest",
                        "changed_fields"]
        summary_headers = ["asset_id", "new_open_count", "closed_count", "changed_count",
                           "unchanged_count", "total_keys_base", "total_keys_curr"]
        summary_row = [asset_id, summary["NEW_OPEN"], summary["CLOSED"], summary["CHANGED"],
                       summary["UNCHANGED"], len(base_map), len(curr_map)]
        snapshot_headers = ["asset_id", "ip", "proto", "port", "state", "service", "detail", "digest"]

        if wrote_csv:
            with open(diff_path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(diff_headers)
                w.writerows(diff_rows)
            with open(summary_path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(summary_headers)
                w.writerow(summary_row)
            with open(snapshot_path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(snapshot_headers)
                w.writerows(snapshot_rows)
            print(f"[diff] OK: {diff_path}")
            print(f"[diff] OK: {summary_path}")
            print(f"[diff] OK: {snapshot_path}")

        if wrote_xlsx:
            # 색칠 xlsx — change_type 별 행 색.
            #   NEW_OPEN  → 빨강 (FILL_NEW_OPEN)
            #   CLOSED    → 회색/자주 (FILL_CLOSED)
            #   CHANGED   → 노랑 (FILL_CHANGED)
            #   UNCHANGED → 흰색 (FILL_NONE)
            color_map = {
                "NEW_OPEN": xlsx_io.FILL_NEW_OPEN,
                "CLOSED":   xlsx_io.FILL_CLOSED,
                "CHANGED":  xlsx_io.FILL_CHANGED,
                "UNCHANGED": xlsx_io.FILL_NONE,
            }
            row_fills = [color_map.get((r[0] or "").upper(), xlsx_io.FILL_NONE) for r in diff_rows]

            xlsx_path = os.path.join(out_dir, f"diff_{base_stem}_vs_{curr_stem}_{stamp}.xlsx")
            sheets = [
                {
                    "name": "Diff",
                    "headers": diff_headers,
                    "rows": [[str(c) for c in r] for r in diff_rows],
                    "row_fills": row_fills,
                    "header_fill": xlsx_io.FILL_HEADER,
                    "col_widths": [12, 12, 14, 8, 8, 10, 10, 14, 14, 22, 22, 16, 16, 18],
                },
                {
                    "name": "Summary",
                    "headers": summary_headers,
                    "rows": [[str(c) for c in summary_row]],
                    "header_fill": xlsx_io.FILL_HEADER,
                    "col_widths": [14, 14, 14, 14, 14, 16, 16],
                },
                {
                    "name": "Snapshot",
                    "headers": snapshot_headers,
                    "rows": [[str(c) for c in r] for r in snapshot_rows],
                    "header_fill": xlsx_io.FILL_HEADER,
                    "col_widths": [14, 14, 8, 8, 10, 14, 22, 16],
                },
            ]
            try:
                xlsx_io.write_xlsx_multi(xlsx_path, sheets)
                print(f"[diff] OK: {xlsx_path}")
            except Exception as e:
                # xlsx 쓰기 실패해도 CSV 는 살아있어야 — 경고만 출력
                print(f"[diff] WARN: xlsx 쓰기 실패 ({e}), CSV 만 생성됨.")

        return 0
    finally:
        _set_system_awake(False)

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

        # 사용자 첫 인상: 창 프레임을 즉시 표시.
        # AV/Defender 가 .exe 를 스캔하느라 spawn 후 UI 까지 수 초 걸려도,
        # 빈 창이 먼저 떠 있어야 "멈춘 것" 처럼 보이지 않음.
        try:
            root.update_idletasks()
        except Exception:
            pass

        # 1280px 기준 panel 폭 ~620px → 한 cell 200~220px → 3 col 적정
        self.panel_cols = 3

        # 설정 폴더 / 파일 경로 — 쓰기 가능한 위치 자동 선택 (Program Files / 회사 보안
        # 디스크 / 네트워크 드라이브 등 read-only 환경 회피). 환경변수
        # NMAPPARSER_DATA_DIR 가 1순위, 그 다음 config.json 핀, _app_dir(), %APPDATA%,
        # %TEMP% 순. 모두 실패하면 메모리-only 모드.
        (self.data_dir, self.options_xlsx_path,
         self.categories_xlsx_path, self.memory_only) = _resolve_paths()
        if self.memory_only:
            # 메모리 모드에선 xlsx 파일 자체가 없음 — 경로는 None 유지하고 GUI 에서 안내.
            self.options_csv_path = None
        else:
            self.options_csv_path = os.path.join(self.data_dir, OPTIONS_CSV_NAME)
        self.categories = {}      # {서비스명_lower: (분류, 설명)}
        self.option_rows = []     # 옵션 파일에서 읽은 행
        self.option_vars = []     # [{"kind", "var", "row", "group"}, ...]
        self.group_vars = {}      # group_name -> StringVar

        self.nmap_exe = find_nmap_exe()
        # services_table 은 CSV 작성 시점에만 필요 — 첫 렌더 차단을 피하려고 지연 로딩.
        # nmap-services 는 ~22000줄로 콜드 디스크 / AV 실시간 검사 환경에서 100~500ms 가량 걸릴 수 있음.
        self.services_table = {}
        self._services_loaded = False

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 스캔 산출 폴더 기본값:
        #   1) NMAPPARSER_OUTPUT_DIR 환경변수
        #   2) data_dir/<timestamp>
        #   3) data_dir 가 None(메모리 모드) 이면 tempfile.gettempdir()/nmapParser/<ts>
        env_out = os.environ.get("NMAPPARSER_OUTPUT_DIR", "").strip()
        if env_out:
            output_default = os.path.join(env_out, ts)
        elif self.data_dir:
            output_default = os.path.join(self.data_dir, ts)
        else:
            output_default = os.path.join(tempfile.gettempdir(), "nmapParser", ts)
        self.output_folder = tk.StringVar(value=output_default)

        self.scan_thread = None
        self.proc = None
        self.output_prefix = None
        self._log_file = None         # 전체 로그 파일 핸들 (.log)
        self._log_file_path = None    # 마지막 .log 경로 (스캔 끝나도 보존 — '전체 로그 보기' 용)
        self._log_lines_since_trim = 0
        self._log_max_lines = 275  # 화면에 표시할 최대 줄 수 (rolling buffer)
        self._scan_was_stopped = False  # 사용자가 중지/창닫기로 abort 시 True

        # 창 닫기 시 좀비 nmap 방지
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._log_queue = queue.Queue()
        self._log_pump_after_id = None
        self._log_pump_interval_ms = 120
        self._log_batch_limit = 120

        self._build_static_ui()
        self._reload_categories(initial=True)
        self._reload_options(initial=True)
        self._refresh_nmap_button()

        # 모든 UI 가 그려진 후 services_table 비동기 로딩 — 첫 화면 응답성 우선.
        # 스캔 결과 CSV 변환 전까지만 채워지면 되므로 100ms 지연이 안전 마진.
        self.root.after(100, self._lazy_load_services_table)

    def _make_scrollable_panel(self, parent, title, header_widget=None):
        """LabelFrame + 내부 Canvas + Scrollbar + Inner Frame 구조 생성.

        header_widget 가 주어지면 LabelFrame 의 타이틀 자리에 그 위젯을 노출
        (labelwidget 패턴) — 우측에 버튼/체크박스를 끼워 넣을 때 사용.
        리턴: (outer_frame_to_pack, inner_frame_to_use_as_parent)"""
        if header_widget is not None:
            outer = tk.LabelFrame(parent, labelwidget=header_widget)
        else:
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
        # 0a. 관리자 권한 배너 (Windows 비관리자 시 빨간 경고)
        if sys.platform == "win32":
            try:
                import ctypes as _ctypes
                is_admin = bool(_ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = True  # 확인 실패면 경고 안 띄움
            if not is_admin:
                admin_banner = tk.Label(
                    self.root,
                    text="⚠ 일반 사용자 권한으로 실행 중 — '-sS' (SYN), '-sU' (UDP) 스캔은 관리자 권한 필요. "
                         ".bat / .exe 를 우클릭 → '관리자 권한으로 실행' 권장. "
                         "현재 권한으로는 'Connect (-sT)' 라디오 선택 시 정상 동작.",
                    bg="#c62828", fg="white",
                    font=("Segoe UI", 9, "bold"),
                    anchor="w", justify="left",
                    wraplength=1200,
                    padx=8, pady=4,
                )
                admin_banner.pack(fill="x", padx=8, pady=(8, 0))

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

        # 기본 패널 — 타이틀 우측에 [✓ UDP 스캔 사용] 마스터 토글 (이슈 6)
        opts_title = tk.Frame(mid)
        tk.Label(opts_title, text="기본 스캔 옵션 (options.xlsx 기반)",
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 8))
        self.udp_section_on = tk.BooleanVar(value=True)
        tk.Checkbutton(opts_title, text="UDP 스캔 사용",
                       variable=self.udp_section_on,
                       command=self._on_udp_toggle).pack(side="left")
        opts_outer, self.opts_frame = self._make_scrollable_panel(
            mid, "기본 스캔 옵션 (options.xlsx 기반)", header_widget=opts_title)
        opts_outer.pack(side="left", fill="both", expand=True, padx=(0, 4))

        # NSE 패널 — 타이틀 우측에 [✓ 스크립트 사용] + [전부 해제] (이슈 2 + 6)
        nse_title = tk.Frame(mid)
        tk.Label(nse_title, text="NSE 식별 스크립트 (options.xlsx 의 --script 행)",
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 8))
        self.nse_section_on = tk.BooleanVar(value=True)
        tk.Checkbutton(nse_title, text="스크립트 사용",
                       variable=self.nse_section_on,
                       command=self._on_nse_toggle).pack(side="left")
        tk.Button(nse_title, text="전부 해제",
                  command=self._deselect_all_nse, padx=4).pack(side="left", padx=(8, 0))
        nse_outer, self.nse_frame = self._make_scrollable_panel(
            mid, "NSE 식별 스크립트 (options.xlsx 의 --script 행)", header_widget=nse_title)
        nse_outer.pack(side="left", fill="both", expand=True, padx=(4, 0))

        # paned.pack 은 함수 끝에서 (모든 bottom 위젯 packed 후 잉여 공간 차지하게).

        # 4. 옵션 관리 버튼 줄
        opt_mgr = tk.Frame(self.root)
        tk.Button(opt_mgr, text="옵션 다시 불러오기", command=lambda: self._reload_options(initial=False),
                  bg="#fff3e0").pack(side="left", padx=2)
        tk.Button(opt_mgr, text="options.xlsx 열기 (Excel)",
                  command=self._open_options_xlsx).pack(side="left", padx=2)
        tk.Button(opt_mgr, text="options.xlsx 폴더 열기",
                  command=self._open_options_folder).pack(side="left", padx=2)
        # categories 관리
        tk.Button(opt_mgr, text="분류 다시 불러오기",
                  command=lambda: self._reload_categories(initial=False),
                  bg="#e3f2fd").pack(side="left", padx=(12, 2))
        tk.Button(opt_mgr, text="categories.xlsx 열기 (Excel)",
                  command=self._open_categories_xlsx).pack(side="left", padx=2)
        # 설정 파일 폴더 수동 지정 — 자동 생성이 막힌 경우 / 다른 위치에 둔 xlsx 를 쓰고 싶을 때.
        tk.Button(opt_mgr, text="설정 폴더 변경...",
                  command=lambda: self._relocate_config_dir(),
                  bg="#fce4ec").pack(side="left", padx=(12, 2))
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
        self.custom_nse_entry = tk.Entry(nse_row, textvariable=self.custom_nse)
        self.custom_nse_entry.pack(side="left", fill="x", expand=True)
        # custom_ports Entry 도 토글 대상이라 별도 핸들 보관
        self.custom_ports_entry = port_row.winfo_children()[1]  # 두 번째 자식 = Entry

        # 직접 명령어 override (이슈 7) — 옆 체크박스를 켜야 적용됨.
        ovr_row = tk.Frame(adv)
        ovr_row.pack(fill="x", padx=4, pady=2)
        tk.Label(ovr_row, text="직접 입력 명령 (전체 override):", width=44, anchor="w").pack(side="left")
        self.override_cmd = tk.StringVar(value="")
        self.override_cmd_entry = tk.Entry(ovr_row, textvariable=self.override_cmd)
        self.override_cmd_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.override_active = tk.BooleanVar(value=False)
        tk.Checkbutton(ovr_row, text="override 사용",
                       variable=self.override_active,
                       command=self._on_override_toggle).pack(side="left")
        tk.Label(adv, fg="#a06000",
                 text="  ⚠ override ON 시 다른 옵션 모두 무시. 출력 플래그(-oA 등)는 자동 보강.").pack(
            anchor="w", padx=4, pady=(0, 2))

        # 6. CSV 변환
        csv_frame = tk.LabelFrame(self.root, text="결과 CSV 변환")
        self.csv_convert = tk.BooleanVar(value=True)
        self.csv_open_only = tk.BooleanVar(value=True)
        self.diff_only_changes = tk.BooleanVar(value=True)
        self.diff_asset_id = tk.StringVar(value="default")
        tk.Checkbutton(csv_frame, text="CSV 로 변환", variable=self.csv_convert).pack(side="left", padx=6, pady=2)
        tk.Checkbutton(csv_frame, text="open 포트만 CSV 에 포함", variable=self.csv_open_only).pack(side="left", padx=6, pady=2)
        tk.Checkbutton(csv_frame, text="Diff 변경행만", variable=self.diff_only_changes).pack(side="left", padx=4, pady=2)
        tk.Label(csv_frame, text="asset_id:").pack(side="left", padx=(6, 2))
        tk.Entry(csv_frame, textvariable=self.diff_asset_id, width=12).pack(side="left", padx=(0, 4))
        tk.Button(csv_frame, text="XML 파일→CSV", command=self._convert_xml_file_dialog).pack(side="left", padx=4)
        tk.Button(csv_frame, text="XML 폴더 일괄→CSV", command=self._convert_xml_folder_dialog).pack(side="left", padx=4)
        tk.Button(csv_frame, text="기준/현재 비교(Diff)", command=self._run_diff_dialog).pack(side="left", padx=4)
        tk.Button(csv_frame, text="📂 CSV 취합", command=self._collect_csv_dialog,
                  bg="#e3f2fd").pack(side="left", padx=4)
        tk.Button(csv_frame, text="📊 시간축 보고서", command=self._generate_report_dialog,
                  bg="#fff3e0").pack(side="left", padx=4)
        tk.Label(csv_frame, text=
                 "  CSV 24컬럼: IP, 호스트, OS, 프로토콜, 포트, 표준포트, 포트상태, "
                 "추측서비스, 확인서비스, 식별, 분류, 용도, 위험도, 암호화, 인증, "
                 "노출위험, 공격표면, 출처, 상세, 비고, NSE, 출력, NSE추출, 점검메모",
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
        # 메모리-only 모드: DEFAULT_OPTIONS 를 직접 로드 (디스크 쓰기 불가 환경)
        if self.memory_only or not self.options_xlsx_path:
            self.option_rows = default_options_as_rows()
            self._rebuild_option_panels()
            self._apply_dynamic_size()
            self.options_status.config(
                text=f"옵션 {len(self.option_rows)}개 로드됨 — 메모리 모드 (디스크 쓰기 불가)")
            if not initial:
                self.status_var.set(
                    f"옵션 다시 불러옴 (메모리 모드, {len(self.option_rows)}개)")
            return

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
                    if self._offer_relocation_on_write_failure("options.xlsx", e):
                        return
                    messagebox.showerror("options.xlsx 생성 실패",
                        f"기본 옵션 파일을 만들 수 없습니다.\n원인: {e}\n경로: {self.options_xlsx_path}\n\n"
                        "상단의 '설정 폴더 변경' 버튼으로 쓰기 가능한 폴더를 지정할 수 있습니다.")
                    return

        # 시작 시 한 번만 — DEFAULT_OPTIONS 와 비교해 누락된 옵션이 있으면 popup 으로 추가 제안.
        # (사용자 활성=0 으로 추가 → 사용자가 GUI 에서 직접 켤 수 있음. 기존 활성/커스텀 보존.)
        if initial:
            try:
                self._maybe_offer_options_reconcile()
            except Exception:
                pass  # reconcile 은 nice-to-have. 실패해도 전체 부팅 안 막음.

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
                    radio_strip, text=_fmt_option_label(row),
                    variable=self.group_vars[group], value=row["option"],
                )
                rb.pack(side="left", padx=4)
                if row.get("desc"):
                    Tooltip(rb, row["desc"])
                self.option_vars.append({
                    "kind": "radio", "var": self.group_vars[group],
                    "row": row, "group": group, "widget": rb,
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
                cb = tk.Checkbutton(parent, text=_fmt_option_label(row),
                                    variable=v, anchor="w")
                cb.grid(row=cb_row, column=cb_col, sticky="w", padx=4, pady=1)
                if row.get("desc"):
                    Tooltip(cb, row["desc"])
                cb_idx += 1
                self.option_vars.append({"kind": "checkbox", "var": v,
                                         "row": row, "group": "", "widget": cb})

        if duplicate_warnings:
            messagebox.showwarning("그룹 중복 활성화",
                "\n".join("• " + w for w in duplicate_warnings) +
                "\n\n해결: Excel 에서 options.xlsx 의 같은 '그룹' 값 행 중 하나만 '활성화=1' 로 두세요.")

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

    def _reload_categories(self, initial=False):
        """categories.xlsx 로드. 없으면 기본값으로 자동 생성. 메모리-only 모드면
        DEFAULT_CATEGORIES 직접 사용."""
        if self.memory_only or not self.categories_xlsx_path:
            self.categories = default_categories_as_map()
            if not initial:
                self.status_var.set(
                    f"분류 다시 불러옴 (메모리 모드, {len(self.categories)}개)")
            return
        if not os.path.isfile(self.categories_xlsx_path):
            try:
                write_default_categories_xlsx(self.categories_xlsx_path)
            except OSError as e:
                if not initial:
                    if self._offer_relocation_on_write_failure("categories.xlsx", e):
                        return
                    messagebox.showerror("categories.xlsx 생성 실패",
                        f"분류 파일을 만들 수 없습니다.\n원인: {e}\n경로: {self.categories_xlsx_path}\n\n"
                        "상단의 '설정 폴더 변경' 버튼으로 쓰기 가능한 폴더를 지정할 수 있습니다.")
                self.categories = {}
                return
        # 시작 시 13컬럼 schema 마이그레이션 — 헤더가 부족하면 popup 으로 안내.
        if initial:
            self._maybe_offer_categories_migration()
        catmap, errors = load_categories_xlsx(self.categories_xlsx_path)
        if errors and not initial:
            messagebox.showwarning("categories.xlsx 일부 행 무시",
                "\n".join("• " + e for e in errors))
        self.categories = catmap
        if not initial:
            self.status_var.set(f"분류 다시 불러옴 ({len(catmap)}개)")

    def _maybe_offer_options_reconcile(self):
        """options.xlsx 를 DEFAULT_OPTIONS 와 비교 — 누락된 옵션이면 popup 으로 추가 안내.
        사용자 활성/커스텀 컬럼/사용자 추가 행 모두 보존.
        """
        path = self.options_xlsx_path
        if not path or not os.path.isfile(path):
            return
        try:
            raw = xlsx_io.read_xlsx(path)
        except Exception:
            return
        if not raw or len(raw) < 2:
            return

        header = [(c or "").strip() for c in raw[0]]
        # "옵션" 컬럼 (nmap 인자) 우선, 영문 fallback.
        opt_col_idx = None
        for cand in ("옵션", "option", "Option"):
            if cand in header:
                opt_col_idx = header.index(cand)
                break
        if opt_col_idx is None:
            return  # 헤더 비정상 — 재구성은 _reload_options 에 맡김

        existing_options = set()
        for r in raw[1:]:
            if opt_col_idx < len(r):
                v = (r[opt_col_idx] or "").strip()
                if v:
                    existing_options.add(v)

        missing = []
        # DEFAULT_OPTIONS 의 (label, option, enabled, group, desc) 를 그대로 사용.
        for tup in DEFAULT_OPTIONS:
            label, option = tup[0], tup[1]
            if option and option not in existing_options:
                missing.append(tup)
        if not missing:
            return

        # 사용자에게 추가 여부 물음. NSE 27 / scan-type 신규 옵션 등을 한 번에 흡수.
        sample = ", ".join(t[1] for t in missing[:8])
        if len(missing) > 8:
            sample += f", ... (+{len(missing) - 8})"
        ask = messagebox.askyesno(
            "options.xlsx 에 새 옵션 발견",
            f"도구 기본 옵션 셋에서 {len(missing)} 개의 새 옵션이 추가되었습니다.\n\n"
            f"예: {sample}\n\n"
            f"options.xlsx 에 추가할까요?\n"
            f"  · 사용자 활성/비활성 상태는 그대로 보존됩니다.\n"
            f"  · 새 옵션은 활성=0 (꺼짐) 상태로 추가됩니다 — GUI 에서 직접 켜세요.\n"
            f"  · 사용자가 추가한 행/컬럼도 그대로 보존됩니다.\n"
            f"  · 기존 파일은 .bak.<timestamp> 로 백업됩니다.\n\n"
            f"건너뛰기 (No) 면 현재 파일 그대로 사용합니다."
        )
        if not ask:
            return

        # 백업 + 추가 행 생성. xlsx_io 직접 read/write 로 사용자 컬럼 100% 보존.
        try:
            import shutil
            import time as _time
            ts = _time.strftime("%Y%m%d-%H%M%S")
            backup = f"{path}.bak.{ts}"
            shutil.copy2(path, backup)
        except OSError as e:
            messagebox.showerror("options.xlsx 백업 실패", f"오류: {e}")
            return

        # 새 행 = 헤더 너비에 맞춰 표준 4컬럼 + 사용자 추가 컬럼은 빈 문자열.
        # 표준 컬럼: 스캔 옵션(라벨) / 옵션 / 활성화 / 그룹 / 설명. 헤더 인덱스로 매핑.
        std_keys = {
            "스캔 옵션": 0, "스캔옵션": 0, "label": 0, "Label": 0,
            "옵션": 1, "option": 1, "Option": 1,
            "활성화": 2, "enabled": 2, "Enabled": 2,
            "그룹": 3, "group": 3, "Group": 3,
            "설명": 4, "desc": 4, "Desc": 4, "Description": 4,
        }
        col_map = {}
        for i, h in enumerate(header):
            key = std_keys.get(h)
            if key is not None and key not in col_map:
                col_map[key] = i

        # 누락된 옵션 추가
        new_rows_to_append = []
        for label, option, enabled, group, desc in missing:
            row = [""] * len(header)
            if 0 in col_map:
                row[col_map[0]] = label
            if 1 in col_map:
                row[col_map[1]] = option
            if 2 in col_map:
                row[col_map[2]] = "0"  # 사용자 결정 — 기본 꺼짐.
            if 3 in col_map:
                row[col_map[3]] = group or ""
            if 4 in col_map:
                row[col_map[4]] = desc or ""
            new_rows_to_append.append(row)

        all_rows = list(raw) + new_rows_to_append
        try:
            xlsx_io.write_xlsx(path, all_rows)
        except Exception as e:
            messagebox.showerror("options.xlsx 쓰기 실패", f"오류: {e}\n백업: {backup}")
            return

        messagebox.showinfo(
            "options.xlsx 옵션 추가 완료",
            f"{len(missing)}개의 새 옵션이 추가되었습니다 (활성=0).\n\n"
            f"백업: {os.path.basename(backup)}\n\n"
            f"GUI 의 '옵션 다시 불러오기' 또는 도구 재시작으로 반영됩니다.\n"
            f"필요한 옵션을 GUI 체크박스에서 켜세요."
        )

    def _maybe_offer_categories_migration(self):
        """categories.xlsx 헤더가 13컬럼 권장 schema 미만이면 popup 으로 안내.
        Yes 면 migrate_categories_to_13col.migrate_path 호출. 사용자 컬럼·편집 보존.
        """
        path = self.categories_xlsx_path
        if not path or not os.path.isfile(path):
            return
        try:
            raw = xlsx_io.read_xlsx(path)
        except Exception:
            return
        if not raw or not raw[0]:
            return

        # 13개 표준 컬럼: 서비스명/표준포트/프로토콜/분류/용도/위험도/암호화/인증/노출위험/공격표면/출처/설명/점검메모
        std = ["서비스명", "표준포트", "프로토콜", "분류", "용도", "위험도",
               "암호화", "인증", "노출위험", "공격표면", "출처", "설명", "점검메모"]
        header = [(c or "").strip() for c in raw[0]]
        missing = [c for c in std if c not in header]
        if not missing:
            return  # 이미 13컬럼

        # 위험 vs 효용 안내. 사용자 동의 시에만 실행.
        ask = messagebox.askyesno(
            "categories.xlsx 13컬럼 schema 마이그레이션",
            f"현재 categories.xlsx 헤더가 13컬럼 권장 schema 보다 부족합니다.\n\n"
            f"누락된 표준 컬럼: {', '.join(missing)}\n\n"
            f"13컬럼 schema 로 변환할까요?\n"
            f"  · 사용자 편집/추가 컬럼은 그대로 보존됩니다.\n"
            f"  · 기존 파일은 .bak.<timestamp> 로 백업됩니다.\n"
            f"  · 누락 표준 컬럼은 도구 기본값으로 채워집니다.\n\n"
            f"건너뛰기 (No) 를 누르면 현재 헤더 그대로 사용합니다."
        )
        if not ask:
            return

        try:
            # scripts/ 가 sys.path 에 없을 수 있어 동적 추가.
            import sys as _sys
            scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
            if scripts_dir not in _sys.path:
                _sys.path.insert(0, scripts_dir)
            from migrate_categories_to_13col import migrate_path
            result = migrate_path(path)
        except Exception as e:
            messagebox.showerror("마이그레이션 실패", f"오류: {e}")
            return

        if result.get("status") == "ok":
            extras = result.get("user_extra") or []
            extras_msg = ("\n사용자 추가 컬럼 보존: " + ", ".join(extras)) if extras else ""
            messagebox.showinfo(
                "마이그레이션 완료",
                f"13컬럼 schema 로 변환되었습니다.\n\n"
                f"백업: {os.path.basename(result.get('backup') or '')}\n"
                f"총 {result['total']}행 (새로 추가 {result['added']}개).{extras_msg}"
            )
        elif result.get("status") == "no_header":
            messagebox.showwarning(
                "마이그레이션 보류",
                "필수 헤더 '서비스명' 이 없어 자동 변환할 수 없습니다.\n"
                "Excel 에서 '서비스명' 컬럼을 직접 만든 뒤 도구를 다시 시작하세요."
            )
        elif result.get("status") in ("created", "empty"):
            messagebox.showinfo(
                "기본값 생성",
                "기존 파일이 비어 있어 기본값으로 새로 만들었습니다."
            )

    def _open_categories_xlsx(self):
        if self.memory_only or not self.categories_xlsx_path:
            messagebox.showinfo(
                "메모리 모드",
                "쓰기 가능한 폴더가 없어 메모리 모드로 동작 중입니다.\n"
                "'설정 폴더 변경...' 으로 폴더를 직접 지정하세요.")
            return
        if not os.path.isfile(self.categories_xlsx_path):
            try:
                write_default_categories_xlsx(self.categories_xlsx_path)
            except OSError as e:
                if self._offer_relocation_on_write_failure("categories.xlsx", e):
                    return
                messagebox.showerror("열기 실패", f"파일을 만들 수 없습니다: {e}")
                return
        try:
            os.startfile(self.categories_xlsx_path)  # type: ignore
        except OSError as e:
            messagebox.showerror("열기 실패", f"파일을 열 수 없음: {e}")

    def _lookup_full(self, probed_name, guessed_name):
        """확인서비스(short) 또는 추측서비스 이름으로 lookup.
        리턴 dict (모든 키 항상 존재):
            category, usage, risk, encryption, auth, port, protocol,
            exposure_risk, attack_surface, source, memo
        """
        for n in (probed_name, guessed_name):
            if n:
                key = n.rstrip("?").strip().lower()
                if key and key in self.categories:
                    info = self.categories[key]
                    return {
                        "category": info.get("category", "미분류"),
                        "usage": info.get("usage", ""),
                        "risk": info.get("risk", ""),
                        "encryption": info.get("encryption", ""),
                        "auth": info.get("auth", ""),
                        "port": info.get("port", ""),
                        "protocol": info.get("protocol", ""),
                        "exposure_risk": info.get("exposure_risk", ""),
                        "attack_surface": info.get("attack_surface", ""),
                        "source": info.get("source", ""),
                        "memo": info.get("memo", ""),
                    }
        return {"category": "미분류", "usage": "", "risk": "",
                "encryption": "", "auth": "", "port": "", "protocol": "",
                "exposure_risk": "", "attack_surface": "", "source": "", "memo": ""}

    def _open_options_folder(self):
        """options.xlsx 폴더 열기 — 메모리 모드 / UNC hang 대비 try/except."""
        if self.memory_only or not self.options_xlsx_path:
            messagebox.showinfo(
                "메모리 모드",
                "쓰기 가능한 폴더가 없어 메모리 모드로 동작 중입니다.\n"
                "'설정 폴더 변경...' 으로 폴더를 직접 지정하세요.")
            return
        try:
            subprocess.Popen(["explorer.exe", "/select,", self.options_xlsx_path])
        except (OSError, FileNotFoundError) as e:
            messagebox.showerror("폴더 열기 실패", f"{e}\n경로: {self.options_xlsx_path}")

    def _open_options_xlsx(self):
        if self.memory_only or not self.options_xlsx_path:
            messagebox.showinfo(
                "메모리 모드",
                "쓰기 가능한 폴더가 없어 메모리 모드로 동작 중입니다.\n"
                "'설정 폴더 변경...' 으로 폴더를 직접 지정하세요.")
            return
        if not os.path.isfile(self.options_xlsx_path):
            try:
                write_default_options_xlsx(self.options_xlsx_path)
            except OSError as e:
                if self._offer_relocation_on_write_failure("options.xlsx", e):
                    return
                messagebox.showerror("열기 실패", f"파일을 만들 수 없습니다: {e}")
                return
        try:
            os.startfile(self.options_xlsx_path)  # type: ignore
        except OSError as e:
            messagebox.showerror("열기 실패",
                f"파일 연결 프로그램으로 열 수 없습니다.\n원인: {e}\n경로: {self.options_xlsx_path}")

    # ----------------------------- 섹션 토글 / 전부 해제 / override (이슈 2/6/7)
    def _set_widgets_state(self, entries, state):
        """entries 의 각 dict 의 'widget' 을 state ('normal' / 'disabled') 로 변경.
        체크박스가 disabled 로 전환될 때 var 도 0 으로 초기화 — 명령에 자동 누락.
        """
        for e in entries:
            w = e.get("widget")
            if w is None:
                continue
            try:
                w.configure(state=state)
            except tk.TclError:
                pass
            if state == "disabled" and e.get("kind") == "checkbox":
                v = e.get("var")
                if v is not None:
                    try:
                        v.set(False)
                    except tk.TclError:
                        pass

    def _nse_entries(self):
        return [e for e in self.option_vars
                if (e.get("row") or {}).get("option", "").startswith("--script")]

    def _udp_entries(self):
        return [e for e in self.option_vars
                if _is_udp_related((e.get("row") or {}).get("option", ""))]

    def _deselect_all_nse(self):
        """이슈 2 — NSE 패널 모든 체크박스 해제 (state 는 그대로)."""
        for e in self._nse_entries():
            if e.get("kind") == "checkbox":
                v = e.get("var")
                if v is not None:
                    try:
                        v.set(False)
                    except tk.TclError:
                        pass
        self.status_var.set("NSE 체크박스 전부 해제됨")

    def _on_nse_toggle(self):
        on = bool(self.nse_section_on.get())
        self._set_widgets_state(self._nse_entries(), "normal" if on else "disabled")
        self.status_var.set("스크립트 사용 ON" if on else "스크립트 사용 OFF (NSE 모두 비활성)")

    def _on_udp_toggle(self):
        on = bool(self.udp_section_on.get())
        self._set_widgets_state(self._udp_entries(), "normal" if on else "disabled")
        self.status_var.set("UDP 스캔 ON" if on else "UDP 스캔 OFF")

    def _all_option_widgets(self):
        return list(self.option_vars)

    def _on_override_toggle(self):
        on = bool(self.override_active.get())
        target_state = "disabled" if on else "normal"
        # 모든 옵션 패널 위젯 + 고급 입력 두 칸 + 섹션 토글 두 칸
        self._set_widgets_state(self._all_option_widgets(), target_state)
        for w in (self.custom_ports_entry, self.custom_nse_entry):
            try:
                w.configure(state=target_state)
            except tk.TclError:
                pass
        # 섹션 토글 자체는 override 상태일 때 disable 로 (UX 일관성)
        # 하위 체크박스의 state 가 이미 변경됐으므로 마스터만 잠그면 됨.
        # (마스터 자체 위젯 핸들이 별도로 저장돼 있지 않아 패스 — 다음 리팩터 후보.)
        self.status_var.set("override 모드 ON" if on else "override 모드 OFF")

    # ----------------------------- 설정 파일 폴더 변경 (수동 지정 / 수동 생성)
    def _relocate_config_dir(self, prompt_reason=None):
        """설정 폴더(`options.xlsx` / `categories.xlsx` 위치) 직접 지정.

        - 쓰기 가능한 폴더만 허용.
        - 폴더 안에 기존 xlsx 가 있으면 그대로 사용, 없으면 기본값으로 새로 만듦.
        - 선택 결과는 `_user_data_dir()/config.json` 에 저장 → 다음 실행 시 자동 적용.
        - 폴더 선택을 취소하거나 실패하면 마지막 수단으로 xlsx 파일 직접 지정 흐름 제안.
        """
        title = "설정 파일 폴더 선택 (options.xlsx / categories.xlsx 위치)"
        if prompt_reason:
            messagebox.showinfo("설정 폴더 선택 안내",
                f"{prompt_reason}\n\n다음 창에서 쓰기 가능한 폴더를 직접 선택하세요.\n"
                "폴더에 기존 xlsx 가 있으면 그대로 사용하고, 없으면 기본값으로 새로 만듭니다.")
        # data_dir 가 None (메모리 모드) 일 때 os.path.isdir(None) 가 TypeError 던짐 → and-guard.
        initial = self.data_dir if (self.data_dir and os.path.isdir(self.data_dir)) else _user_data_dir()
        folder = filedialog.askdirectory(title=title, initialdir=initial)
        if not folder:
            return self._offer_file_direct_fallback("폴더 선택을 취소했습니다.")
        if not _is_dir_writable(folder):
            messagebox.showerror("쓰기 불가",
                f"선택한 폴더에 파일을 쓸 수 없습니다.\n{folder}")
            return self._offer_file_direct_fallback("선택한 폴더가 쓰기 불가였습니다.")

        new_options = os.path.join(folder, OPTIONS_XLSX_NAME)
        new_categories = os.path.join(folder, CATEGORIES_XLSX_NAME)
        new_options_csv = os.path.join(folder, OPTIONS_CSV_NAME)

        try:
            if not os.path.isfile(new_options) and not os.path.isfile(new_options_csv):
                write_default_options_xlsx(new_options)
            if not os.path.isfile(new_categories):
                write_default_categories_xlsx(new_categories)
        except OSError as e:
            messagebox.showerror("기본 파일 생성 실패",
                f"{folder} 에 기본 xlsx 를 만들 수 없습니다.\n원인: {e}")
            return self._offer_file_direct_fallback("폴더에 기본 파일 생성이 실패했습니다.")

        self.data_dir = folder
        self.options_xlsx_path = new_options
        self.options_csv_path = new_options_csv
        self.categories_xlsx_path = new_categories
        self.memory_only = False  # 사용자 폴더 지정 시 디스크 모드로 복귀
        # config.json 갱신 — 폴더 기반 모드로 통일하기 위해 개별 파일 핀은 비움.
        cfg = _read_pin_config()
        cfg["data_dir"] = folder
        cfg.pop("options_xlsx", None)
        cfg.pop("categories_xlsx", None)
        _write_pin_config(cfg)

        # 즉시 재로드
        self._reload_categories(initial=False)
        self._reload_options(initial=False)
        messagebox.showinfo("설정 폴더 변경 완료",
            f"설정 폴더가 다음으로 변경되었습니다:\n{folder}\n\n다음 실행 시에도 이 위치가 자동으로 사용됩니다.")
        return True

    def _offer_file_direct_fallback(self, reason):
        """폴더 기반 변경이 불가/취소된 경우 → xlsx 파일 직접 지정 흐름 제안 (last resort)."""
        ans = messagebox.askyesno(
            "xlsx 파일 직접 지정",
            f"{reason}\n\n"
            "마지막 방법으로 options.xlsx 와 categories.xlsx 를 각각 직접 지정하시겠습니까?\n"
            "(파일이 없으면 그 자리에 기본값으로 새로 만듭니다.)")
        if not ans:
            return False
        ok_opt = self._select_xlsx_file_directly("options")
        ok_cat = self._select_xlsx_file_directly("categories")
        return ok_opt or ok_cat

    def _select_xlsx_file_directly(self, what):
        """xlsx 파일 경로 직접 지정 (last-resort).

        what ∈ ('options', 'categories'). 파일이 없으면 그 자리에 기본값 작성.
        선택은 config.json 에 개별 파일 핀으로 저장 → 다음 실행 시에도 유지.
        """
        if what == "options":
            title = "options.xlsx 파일 지정 (기존 파일 선택 또는 새 파일명 입력)"
            default_name = OPTIONS_XLSX_NAME
            writer = write_default_options_xlsx
        else:
            title = "categories.xlsx 파일 지정 (기존 파일 선택 또는 새 파일명 입력)"
            default_name = CATEGORIES_XLSX_NAME
            writer = write_default_categories_xlsx

        initial_dir = self.data_dir if (self.data_dir and os.path.isdir(self.data_dir)) else _user_data_dir()
        path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=".xlsx",
            filetypes=[("Excel xlsx", "*.xlsx"), ("모든 파일", "*.*")],
            initialdir=initial_dir,
            initialfile=default_name,
            confirmoverwrite=False,
        )
        if not path:
            return False

        parent = os.path.dirname(os.path.abspath(path))
        existed = os.path.isfile(path)
        if not existed:
            if not _is_dir_writable(parent):
                messagebox.showerror("쓰기 불가",
                    f"파일을 만들 폴더에 쓸 수 없습니다.\n{parent}")
                return False
            try:
                writer(path)
            except OSError as e:
                messagebox.showerror("생성 실패", f"{path} 를 만들 수 없습니다.\n원인: {e}")
                return False

        if what == "options":
            self.options_xlsx_path = path
        else:
            self.categories_xlsx_path = path
        self.memory_only = False  # 파일 직접 지정도 메모리 모드 해제

        cfg = _read_pin_config()
        cfg[f"{what}_xlsx"] = path
        _write_pin_config(cfg)

        if what == "options":
            self._reload_options(initial=False)
        else:
            self._reload_categories(initial=False)

        messagebox.showinfo(
            f"{what}.xlsx 지정 완료",
            f"{what}.xlsx 경로가 다음으로 설정되었습니다:\n{path}\n\n"
            f"({'기존 파일 사용' if existed else '기본값으로 새로 생성'} — 다음 실행 시에도 유지)")
        return True

    def _offer_relocation_on_write_failure(self, what, err):
        """xlsx 자동 생성/쓰기 실패 시 사용자에게 폴더 변경 제안.

        Returns True 이면 사용자가 폴더 변경에 응했고 처리 완료(호출자는 추가 에러 표시 X).
        """
        ans = messagebox.askyesno(
            f"{what} 생성/쓰기 실패",
            f"현재 폴더에 파일을 만들 수 없습니다.\n경로: {self.data_dir}\n원인: {err}\n\n"
            f"쓰기 가능한 다른 폴더를 직접 지정하시겠습니까?\n"
            f"(취소 후에도 'xlsx 파일 직접 지정' 옵션을 한 번 더 안내합니다.)"
        )
        if not ans:
            # 폴더 변경을 거절해도 마지막 수단으로 파일 직접 지정 제안.
            return self._offer_file_direct_fallback("폴더 변경을 취소했습니다.")
        return self._relocate_config_dir(prompt_reason=f"{what} 자동 생성에 실패했습니다.")

    # ----------------------------- nmap-services 지연 로딩
    def _lazy_load_services_table(self):
        """첫 렌더 후에 nmap-services 파싱. 이미 로드됐으면 no-op."""
        if self._services_loaded:
            return
        if self.nmap_exe:
            try:
                self.services_table = parse_nmap_services(self.nmap_exe)
            except Exception:
                self.services_table = {}
        self._services_loaded = True

    def _ensure_services_table(self):
        """CSV 변환 등에서 services_table 이 반드시 필요한 시점에 동기 보강."""
        if not self._services_loaded:
            self._lazy_load_services_table()

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
            # 사용자가 nmap 을 새로 지정했으므로 services 테이블을 즉시 갱신.
            self._services_loaded = False
            self.services_table = {}
            self.root.after(0, self._lazy_load_services_table)
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
        # IP-처럼-생긴 입력은 ipaddress 실패 시 hostname fallback 안 함
        # (예: 192.168.1.999 가 hostname 으로 잘못 통과되는 버그 방지)
        ip_like_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,3})?$")
        for raw in items:
            token = (raw or "").strip()
            if not token:
                continue
            if token in seen:
                result.warnings.append(f"중복 타깃 제거: {token}")
                continue
            seen.add(token)
            looks_like_ip = bool(ip_like_re.match(token))
            ip_error = False
            try:
                if "/" in token:
                    ipaddress.ip_network(token, strict=False)
                else:
                    ipaddress.ip_address(token)
                result.valid_items.append(token)
                continue
            except ValueError:
                ip_error = True
            if ip_error and looks_like_ip:
                # IP 형식인데 octet/prefix 범위 벗어남
                result.invalid_items.append(token)
                result.issues.append(ValidationIssue(
                    code="INVALID_IP",
                    field="targets",
                    message=f"IP 주소 형식 오류 (octet 0-255 / prefix 0-32): {token}",
                    hint="각 octet 은 0-255, /N 은 0-32 범위여야 합니다."
                ))
                continue
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
        """
        다중 -p 통합 + 사용자 입력 포트 처리.
        - 옵션 표 여러 행에 -p 가 있으면 콤마로 합쳐 단일 -p 로
          (예: "TCP 모든 포트" -p T:1-65535 + "UDP 주요 포트" -sU -p U:7,53,...
                → -p T:1-65535,U:7,53,...)
        - 사용자 입력 포트 비어있지 않으면 옵션 표의 -p 들을 override
        """
        cleaned = []
        p_specs = []
        i = 0
        while i < len(extra_tokens):
            t = extra_tokens[i]
            if t == "-p" and i + 1 < len(extra_tokens):
                p_specs.append(extra_tokens[i + 1])
                i += 2
            elif t.startswith("-p") and len(t) > 2 and t not in ("-pn", "-Pn"):
                p_specs.append(t[2:])
                i += 1
            else:
                cleaned.append(t)
                i += 1

        user_port = (user_port or "").strip()
        if user_port:
            if re.match(r"^[\d,\- ]+$", user_port):
                p_specs = [f"T:{user_port}"]
            else:
                p_specs = [user_port]

        if p_specs:
            # T:... 가 먼저, U:... 가 나중 (사용자 기준 명령 관행)
            p_specs.sort(key=lambda s: (0 if s.startswith("T:") else 1 if s.startswith("U:") else 2))
            cleaned.extend(["-p", ",".join(p_specs)])
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

        # 직접 명령 override (이슈 7) — 옆 체크박스가 켜져 있으면 다른 모든 옵션 무시.
        if getattr(self, "override_active", None) and self.override_active.get():
            raw = (self.override_cmd.get() or "").strip()
            if not raw:
                messagebox.showerror("override 실패",
                    "직접 입력 명령이 비어 있습니다.\n예: nmap -sT -p 22,80 192.0.2.10")
                return None
            try:
                tokens = shlex.split(raw, posix=(sys.platform != "win32"))
            except ValueError as e:
                messagebox.showerror("override 파싱 실패", f"shlex 파싱 오류: {e}")
                return None
            # 사용자가 'nmap' 또는 절대경로 nmap.exe 로 시작했다면 제거 — self.nmap_exe 사용.
            if tokens:
                head_l = tokens[0].lower()
                if (head_l in ("nmap", "nmap.exe")
                        or head_l.endswith(("\\nmap.exe", "/nmap", "/nmap.exe"))):
                    tokens = tokens[1:]
            # 출력 플래그 제거 후 우리 -oA 강제 (CSV 파이프라인 보장).
            tokens = self.sanitize_output_args(tokens)
            # override 박스에 타겟이 명시 안 되면 GUI 타겟 자동 append.
            #   판단: -iL <file> / -iR / IP 토큰 (대략적 dotted-quad) / hostname-like 가 있으면 명시된 것으로 간주.
            already_has_target = False
            ip_like_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,3})?$")
            host_like_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")
            i = 0
            while i < len(tokens):
                t = tokens[i]
                low = t.lower()
                if low in ("-il", "-ir"):
                    already_has_target = True
                    break
                # 옵션 토큰 (-, --) 은 패스. 그 외 plain 토큰이면 IP/host 로 간주.
                if not t.startswith("-") and (ip_like_re.match(t) or host_like_re.match(t)):
                    # 단, 옵션의 인자 (예: -p 22) 는 제외 — 직전 토큰이 인자받는 옵션이면 skip.
                    prev = tokens[i - 1] if i > 0 else ""
                    arg_taking = {"-p", "-T", "-sn", "-sS", "-sT", "--script",
                                  "--script-args", "--source-port", "-D",
                                  "--max-retries", "--host-timeout", "--scan-delay",
                                  "--data-length", "--mtu", "-S", "-e", "--ttl"}
                    # arg-taking 옵션의 인자 자리는 plain 토큰일 수 있어 prev 가 그 옵션이면 skip.
                    # (정확한 판단은 어렵지만 대표 케이스만 잡아 false-positive 줄임.)
                    if prev not in arg_taking and not prev.startswith("--"):
                        already_has_target = True
                        break
                i += 1

            if not already_has_target and targets:
                # 사용자에게 알림 — "GUI 타겟이 자동 추가됩니다" (override 인 줄 알아도 타겟은 누락 자주 일어남).
                tokens = list(tokens) + list(targets)

            try:
                self.output_prefix = self._build_output_prefix(targets or ["custom"])
            except OSError as e:
                raise OSError(f"출력 폴더 생성 실패: {e}")
            return [self.nmap_exe] + tokens + ["-oA", self.output_prefix]

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
        # 한글 Windows 의 nmap.exe 는 콘솔 코드페이지(cp949) 로 출력 → utf-8 강제 시
        # mojibake. locale.getpreferredencoding(False) 가 그 코드페이지를 반환하므로
        # 사용. 그래도 누락 바이트는 errors="replace" 로 안전 처리.
        _set_system_awake(True)
        try:
            stream_encoding = locale.getpreferredencoding(False) or "utf-8"
        except Exception:
            stream_encoding = "utf-8"

        try:
            # cwd: v0.2 는 cwd 미지정 (=parent inherit). 87322f8/93a875d 에서 무조건 tempdir
            # 로 바꾸면서 일부 환경에서 권한/접근 이슈로 회귀가 발생한 정황이 있음.
            #   → 기본은 cwd=None (parent inherit, v0.2 동작) 으로 복귀.
            #   → 명령 안에 UNC 경로(\\server\share) 가 있을 때만 임시 폴더로 폴백.
            _scan_cwd = None
            try:
                if sys.platform == "win32":
                    for _tok in cmd:
                        if isinstance(_tok, str) and _tok.startswith("\\\\"):
                            import tempfile as _tempfile
                            _scan_cwd = _tempfile.gettempdir()
                            break
            except Exception:
                _scan_cwd = None

            kwargs = dict(
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                # bufsize=0 (unbuffered) — v0.2 기본값으로 복귀. read1 폴백 (a045f58) 으로
                # AttributeError 안전. -1 (OS full-buffer) 로 두면 nmap stdout 이 OS 버퍼에
                # 갇혀 GUI 가 수십 초간 무응답으로 보이고 watchdog 이 헛 경보를 낸다.
                bufsize=0,
                # PyInstaller --windowed 환경에서 부모 프로세스의 stdin/stdout 핸들이
                # None 또는 NUL 일 수 있어, 자식이 부모 stdin 을 잘못 상속받지 않게 명시 차단.
                stdin=subprocess.DEVNULL,
            )
            if _scan_cwd is not None:
                kwargs["cwd"] = _scan_cwd
            if sys.platform == "win32":
                # CREATE_NO_WINDOW + STARTUPINFO 둘 다 명시. 일부 Windows 버전에서
                # creationflags 만으로는 콘솔 창이 깜빡 뜰 수 있어 STARTUPINFO 보강.
                kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
                try:
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = 0  # SW_HIDE
                    kwargs["startupinfo"] = si
                except Exception:
                    pass

            # 진단 prelude: 사용자에게 GUI 가 살아 있음을 알려줌. AV / Defender 가
            # CreateProcess 단계에서 수 초 hang 되어도 이 라인은 미리 표시됨.
            self._log_queue.put("[nmapParser] 프로세스 시작 시도 "
                                "(AV / 보안 정책 검사로 수 초 ~ 수십 초 지연 가능)...\n")
            self.proc = subprocess.Popen(cmd, **kwargs)
            self._log_queue.put(
                f"[nmapParser] 프로세스 시작됨 (PID {self.proc.pid}). nmap 출력 대기 중...\n")
            # 즉시 종료된 프로세스 검출 — 권한/경로 오류로 nmap 이 시작 직후 죽은 경우
            try:
                rc_now = self.proc.poll()
                if rc_now is not None and rc_now != 0:
                    self._log_queue.put(
                        f"[nmapParser] 경고: nmap 이 시작 직후 종료됨 (returncode={rc_now}). "
                        "권한/경로/옵션을 확인하세요.\n")
            except Exception:
                pass

            # 출력 무응답 watchdog 시작 (30초 hint / 90초 warn).
            # 5/30초는 nmap 의 정상 phase 변경이나 NSE 로딩 중에도 헛 경보가 나서 상향.
            self._scan_last_output_at = time.monotonic()
            self._scan_started_at = time.monotonic()
            self._scan_watchdog_active = True
            self.root.after(15000, self._scan_watchdog_tick)

            buf = b""
            # bufsize=0 (unbuffered) 경로에서 stdout 이 RawIOBase 라 read1() 메서드가 없을 수 있음.
            # 안전하게 read1 우선, 없으면 read 폴백.
            reader = getattr(self.proc.stdout, "read1", None) or self.proc.stdout.read
            while True:
                try:
                    chunk = reader(4096)
                except (OSError, ValueError, AttributeError):
                    chunk = b""
                if not chunk:
                    break
                self._scan_last_output_at = time.monotonic()
                buf += chunk
                # 완전한 라인은 즉시 push. nmap progress bar 의 \r 도 라인 간주.
                while True:
                    nl_idx = -1
                    for sep in (b"\n", b"\r"):
                        idx = buf.find(sep)
                        if idx != -1 and (nl_idx == -1 or idx < nl_idx):
                            nl_idx = idx
                    if nl_idx == -1:
                        break
                    line_bytes = buf[:nl_idx + 1]
                    buf = buf[nl_idx + 1:]
                    try:
                        line_str = line_bytes.decode(stream_encoding, errors="replace")
                    except Exception:
                        line_str = line_bytes.decode("utf-8", errors="replace")
                    self._log_queue.put(line_str)
                # newline 없는 잔여가 충분히 길면(≥256B) partial flush — 진행 표시.
                if len(buf) >= 256:
                    try:
                        partial = buf.decode(stream_encoding, errors="replace")
                    except Exception:
                        partial = buf.decode("utf-8", errors="replace")
                    self._log_queue.put(partial)
                    buf = b""

            # 잔여 flush
            if buf:
                try:
                    self._log_queue.put(buf.decode(stream_encoding, errors="replace"))
                except Exception:
                    self._log_queue.put(buf.decode("utf-8", errors="replace"))

            self.proc.wait()
            rc = self.proc.returncode
            self._scan_watchdog_active = False
            self.root.after(0, self._scan_done, rc)
        except FileNotFoundError as e:
            self._scan_watchdog_active = False
            self.root.after(0, self._scan_error,
                f"nmap 실행 실패 (파일 없음): {e}\n해결: nmap 경로를 다시 지정하세요.")
        except PermissionError as e:
            self._scan_watchdog_active = False
            self.root.after(0, self._scan_error,
                f"nmap 실행 권한 없음: {e}\n"
                "해결: 관리자 권한으로 실행하거나 -sS 대신 -sT 옵션 (CSV의 'TCP Connect 스캔') 사용.")
        except Exception as e:
            self._scan_watchdog_active = False
            self.root.after(0, self._scan_error, f"예상치 못한 오류: {e}")
        finally:
            _set_system_awake(False)

    def _scan_watchdog_tick(self):
        """15초마다 실행 — 무응답 / 비정상 종료 모니터링.
        nmap 은 호스트 발견 / 포트 스캔 phase 전환 / NSE 로딩 중 정상적으로 30초 이상
        조용할 수 있음. 그래서 30초 hint, 90초에 비로소 warning.
        """
        if not getattr(self, "_scan_watchdog_active", False):
            return
        proc = self.proc
        if proc is None:
            return
        elapsed_silent = time.monotonic() - self._scan_last_output_at
        elapsed_total = time.monotonic() - self._scan_started_at
        rc = proc.poll()
        if rc is not None:
            # 비정상 종료 (출력 없이) 의 경우만 안내. 정상 종료는 read 루프 끝에서 처리.
            if elapsed_silent > 1:
                self._log_queue.put(
                    f"[nmapParser] 프로세스 조기 종료 감지 (rc={rc}). "
                    f"AV/정책 차단 가능성. 명령 / nmap.exe 경로 확인.\n")
            return
        if elapsed_silent >= 90:
            self.status_var.set(
                f"⚠ nmap 무응답 {int(elapsed_silent)}초 — DNS / 방화벽 / AV / NSE 로딩 가능성")
        elif elapsed_silent >= 30:
            self.status_var.set(
                f"nmap 출력 대기 중 ({int(elapsed_silent)}초 경과 / 총 {int(elapsed_total)}초)")
        # 다음 tick (15초)
        self.root.after(15000, self._scan_watchdog_tick)

    def _append_log(self, line):
        # BEL / 기타 invalid control char 제거 — tk system sound 폭주 방지.
        if line:
            line = _LOG_CTRL_CHAR_RE.sub("", line)
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
        # tk Text 위젯이 ASCII BEL (\x07) 을 만나면 Windows system sound 를 재생.
        # nmap progress bar / NSE 출력에 가끔 들어와 "지속적 알림음, 창은 안 뜸" 증상.
        # 다른 invalid control char (\x00-\x06, \x0b, \x0c, \x0e-\x1f) 도 안전하게 제거.
        # 허용: \t (\x09), \n (\x0a), \r (\x0d).
        merged = _LOG_CTRL_CHAR_RE.sub("", merged)
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
            self._scan_was_stopped = True
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                self.status_var.set("중지됨")
            except Exception:
                pass

    def _on_close(self):
        """창 X 버튼 — 스캔 중이면 nmap 자식 프로세스 강제 종료해 좀비 방지."""
        if self.proc and self.proc.poll() is None:
            ans = messagebox.askyesno(
                "스캔 진행 중",
                "스캔이 진행 중입니다. 종료하면 nmap 프로세스도 함께 강제 종료됩니다.\n계속할까요?")
            if not ans:
                return
            self._scan_was_stopped = True
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
            except Exception:
                pass
        self._close_log_file()
        try:
            self.root.destroy()
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

        # 사용자 abort 면 CSV 변환 skip + 친절 안내 (XML ParseError popup 회피)
        if self._scan_was_stopped:
            self._scan_was_stopped = False
            files_made = []
            for ext in (".nmap", ".xml", ".gnmap", ".log"):
                p = (self.output_prefix or "") + ext
                if os.path.isfile(p):
                    files_made.append(p)
            self.status_var.set("스캔 중지됨")
            messagebox.showinfo(
                "스캔 중지",
                "스캔이 중지되었습니다.\n\n"
                "부분 결과는 .nmap/.xml/.gnmap 파일로 저장됐습니다 (CSV 변환은 스킵).\n"
                f"폴더: {self.output_folder.get()}\n\n"
                + "\n".join("  " + os.path.basename(p) for p in files_made))
            return

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

    def _convert_xml_file_dialog(self):
        """스캔 없이 XML 파일 1개를 CSV로 변환."""
        xml_path = filedialog.askopenfilename(
            title="변환할 XML 파일 선택",
            filetypes=[("nmap XML", "*.xml"), ("모든 파일", "*.*")]
        )
        if not xml_path:
            return
        out_dir = filedialog.askdirectory(title="CSV 출력 폴더 선택", initialdir=self.output_folder.get() or os.getcwd())
        if not out_dir:
            return
        try:
            _set_system_awake(True)
            self._ensure_services_table()
            base = os.path.splitext(os.path.basename(xml_path))[0]
            csv_path = os.path.join(out_dir, base + ".csv")
            convert_xml_to_csv_standalone(
                xml_path, csv_path,
                open_only=self.csv_open_only.get(),
                categories_xlsx_path=self.categories_xlsx_path,
                services_table=self.services_table,
            )
            messagebox.showinfo("변환 완료", f"CSV 생성 완료:\n{csv_path}")
        except (ET.ParseError, OSError) as e:
            messagebox.showerror("변환 실패", f"XML->CSV 변환 중 오류: {e}")
        finally:
            _set_system_awake(False)

    def _convert_xml_folder_dialog(self):
        """스캔 없이 XML 폴더 일괄 변환."""
        folder = filedialog.askdirectory(title="XML 폴더 선택", initialdir=self.output_folder.get() or os.getcwd())
        if not folder:
            return
        out_dir = filedialog.askdirectory(title="CSV 출력 폴더 선택", initialdir=folder)
        if not out_dir:
            return
        xml_files = sorted([os.path.join(folder, n) for n in os.listdir(folder) if n.lower().endswith(".xml")])
        if not xml_files:
            messagebox.showinfo("변환 대상 없음", "선택한 폴더에 XML 파일이 없습니다.")
            return
        ok = 0
        fails = []
        _set_system_awake(True)
        try:
            self._ensure_services_table()
            for xml_path in xml_files:
                try:
                    base = os.path.splitext(os.path.basename(xml_path))[0]
                    csv_path = os.path.join(out_dir, base + ".csv")
                    convert_xml_to_csv_standalone(
                        xml_path, csv_path,
                        open_only=self.csv_open_only.get(),
                        categories_xlsx_path=self.categories_xlsx_path,
                        services_table=self.services_table,
                    )
                    ok += 1
                except (ET.ParseError, OSError) as e:
                    fails.append(f"{os.path.basename(xml_path)}: {e}")
        finally:
            _set_system_awake(False)
        msg = f"완료: {ok}/{len(xml_files)}개 변환"
        if fails:
            msg += "\n\n실패 목록:\n" + "\n".join(fails[:15])
        messagebox.showinfo("일괄 변환 결과", msg)

    def _collect_csv_dialog(self):
        """폴더 선택 → 하위 모든 *.csv 를 새 폴더로 복사 (recursive).
        시간축 누적 점검 결과를 한 폴더에 모으는 용도."""
        from pathlib import Path
        import shutil as _shutil
        from datetime import datetime as _dt

        src = filedialog.askdirectory(title="CSV 가 들어 있는 상위 폴더 선택 (recursive)")
        if not src:
            return
        if not os.path.isdir(src):
            messagebox.showerror("오류", f"폴더를 찾을 수 없습니다:\n{src}")
            return

        ts = _dt.now().strftime("%Y%m%d_%H%M%S")
        dst_dir = os.path.join(src, f"_collected_{ts}")
        try:
            os.makedirs(dst_dir, exist_ok=True)
        except OSError as e:
            messagebox.showerror("폴더 생성 실패",
                f"수집 폴더를 만들 수 없습니다.\n경로: {dst_dir}\n원인: {e}")
            return

        # recursive 하게 *.csv 찾기.
        #   1) 방금 만든 dst_dir 자체 제외.
        #   2) 같은 폴더 재실행 시 만들어진 이전 _collected_<ts>/ 폴더도 제외 (중복 누적 방지).
        #   3) 파일 내용 hash 가 같으면 dedup (다른 위치에 같은 CSV 사본이 있을 때).
        import hashlib as _hashlib

        def _is_under_collected_dir(path_obj):
            for parent in path_obj.parents:
                name = parent.name
                if name.startswith("_collected_") and len(name) > len("_collected_") + 4:
                    return True
            return False

        try:
            csv_paths = []
            for p in Path(src).rglob("*.csv"):
                try:
                    if Path(dst_dir) in p.parents:
                        continue
                    if _is_under_collected_dir(p):
                        continue
                except Exception:
                    pass
                if p.is_file():
                    csv_paths.append(p)
        except OSError as e:
            messagebox.showerror("탐색 실패", f"파일 탐색 중 오류:\n{e}")
            return

        # hash dedup — 같은 stem 이라도 내용 다르면 둘 다, 같으면 첫 것만 보존.
        seen_hashes = set()
        deduped = []
        skipped_dup = 0
        for p in csv_paths:
            try:
                h = _hashlib.md5()
                with open(str(p), "rb") as fh:
                    while True:
                        b = fh.read(64 * 1024)
                        if not b:
                            break
                        h.update(b)
                digest = h.hexdigest()
            except OSError:
                # hash 실패 시 stem+size 로 fallback
                try:
                    digest = f"{p.stem}-{p.stat().st_size}"
                except OSError:
                    digest = str(p)
            if digest in seen_hashes:
                skipped_dup += 1
                continue
            seen_hashes.add(digest)
            deduped.append(p)
        csv_paths = deduped

        if not csv_paths:
            messagebox.showinfo("CSV 없음", f"하위 폴더에 .csv 파일이 없습니다.\n경로: {src}")
            try:
                os.rmdir(dst_dir)
            except OSError:
                pass
            return

        # 복사 (충돌 시 _2, _3 suffix)
        copied = 0
        oldest = newest = None
        fail_list = []
        for src_path in csv_paths:
            try:
                stem = src_path.stem
                suffix = src_path.suffix
                target = os.path.join(dst_dir, src_path.name)
                idx = 2
                while os.path.exists(target):
                    target = os.path.join(dst_dir, f"{stem}_{idx}{suffix}")
                    idx += 1
                _shutil.copy2(str(src_path), target)
                copied += 1
                mtime = src_path.stat().st_mtime
                if oldest is None or mtime < oldest:
                    oldest = mtime
                if newest is None or mtime > newest:
                    newest = mtime
            except (OSError, _shutil.Error) as e:
                fail_list.append(f"{src_path.name}: {e}")

        oldest_str = _dt.fromtimestamp(oldest).strftime("%Y-%m-%d %H:%M") if oldest else "—"
        newest_str = _dt.fromtimestamp(newest).strftime("%Y-%m-%d %H:%M") if newest else "—"
        msg = (f"CSV 취합 완료\n\n"
               f"수집 폴더: {dst_dir}\n"
               f"수집된 CSV: {copied}개 (실패 {len(fail_list)}개, 중복 dedup {skipped_dup}개)\n"
               f"가장 오래된 파일: {oldest_str}\n"
               f"가장 최근 파일: {newest_str}")
        if fail_list:
            msg += "\n\n실패 (앞 10개):\n" + "\n".join(fail_list[:10])
        messagebox.showinfo("CSV 취합 결과", msg)
        # 폴더 자동 열기
        try:
            if sys.platform == "win32":
                os.startfile(dst_dir)  # type: ignore
        except OSError:
            pass

    def _generate_report_dialog(self):
        """GUI 에서 CSV 폴더를 선택해 5(or 6) 시트 시간축 xlsx 보고서 생성."""
        folder = filedialog.askdirectory(
            title="시간축 보고서 — CSV 폴더 선택 (여러 시점 *.csv 가 있는 디렉토리)"
        )
        if not folder:
            return
        try:
            import report_generator  # 지연 import
        except Exception as e:
            messagebox.showerror("보고서 생성 실패", f"report_generator 모듈 로드 실패: {e}")
            return

        # 보고서 저장 위치 선택 (기본: 폴더 안 report_<ts>.xlsx)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"report_{ts}.xlsx"
        out_path = filedialog.asksaveasfilename(
            title="보고서 저장 위치",
            initialdir=folder,
            initialfile=default_name,
            defaultextension=".xlsx",
            filetypes=[("Excel xlsx", "*.xlsx")],
        )
        if not out_path:
            return

        try:
            result = report_generator.generate_report(folder, out_path)
        except Exception as e:
            messagebox.showerror("보고서 생성 실패", f"오류: {e}")
            return

        try:
            file_count = len(report_generator.collect_csv_files(folder))
        except Exception:
            file_count = 0
        messagebox.showinfo(
            "보고서 생성 완료",
            f"5(또는 6) 시트 xlsx 보고서가 생성되었습니다.\n\n"
            f"입력 CSV: {file_count}개\n출력: {result}\n\n"
            f"폴더가 자동으로 열립니다."
        )
        try:
            if sys.platform == "win32":
                os.startfile(os.path.dirname(result))  # type: ignore
        except OSError:
            pass

    def _run_diff_dialog(self):
        """GUI에서 기준/현재 파일을 선택해 diff CSV 생성."""
        base_path = filedialog.askopenfilename(
            title="기준 파일 선택 (.xml/.csv)",
            filetypes=[("지원 파일", "*.xml *.csv"), ("모든 파일", "*.*")]
        )
        if not base_path:
            return
        curr_path = filedialog.askopenfilename(
            title="현재 파일 선택 (.xml/.csv)",
            filetypes=[("지원 파일", "*.xml *.csv"), ("모든 파일", "*.*")]
        )
        if not curr_path:
            return
        out_dir = filedialog.askdirectory(
            title="Diff 출력 폴더 선택",
            initialdir=self.output_folder.get() or os.getcwd()
        )
        if not out_dir:
            return

        asset_id = (self.diff_asset_id.get() or "default").strip() or "default"

        class _Args:
            pass
        args = _Args()
        args.diff = True
        args.base = base_path
        args.curr = curr_path
        args.out = out_dir
        args.asset = asset_id
        args.only_changes = bool(self.diff_only_changes.get())
        args.out_format = "both"  # GUI 기본 — CSV + 색칠 xlsx 둘 다
        try:
            rc = run_cli_diff(args)
            if rc == 0:
                base_stem = _safe_stem_for_path(base_path)
                curr_stem = _safe_stem_for_path(curr_path)
                diff_candidates = sorted(glob.glob(os.path.join(
                    out_dir, f"diff_{base_stem}_vs_{curr_stem}_*.csv")), key=os.path.getmtime)
                summary_candidates = sorted(glob.glob(os.path.join(
                    out_dir, f"summary_{base_stem}_vs_{curr_stem}_*.csv")), key=os.path.getmtime)
                snapshot_candidates = sorted(glob.glob(os.path.join(
                    out_dir, f"snapshot_{curr_stem}_*.csv")), key=os.path.getmtime)
                diff_name = os.path.basename(diff_candidates[-1]) if diff_candidates else "(diff 파일 확인 필요)"
                summary_name = os.path.basename(summary_candidates[-1]) if summary_candidates else "(summary 파일 확인 필요)"
                snapshot_name = os.path.basename(snapshot_candidates[-1]) if snapshot_candidates else "(snapshot 파일 확인 필요)"
                messagebox.showinfo(
                    "Diff 완료",
                    "기준/현재 비교가 완료되었습니다.\n"
                    f"- 기준: {os.path.basename(base_path)}\n"
                    f"- 현재: {os.path.basename(curr_path)}\n"
                    f"- diff: {diff_name}\n"
                    f"- summary: {summary_name}\n"
                    f"- snapshot: {snapshot_name}\n"
                    f"- 출력 폴더: {out_dir}"
                )
                try:
                    if messagebox.askyesno("폴더 열기", "결과 폴더를 열까요?"):
                        if os.path.isdir(out_dir):
                            if sys.platform == "win32":
                                os.startfile(out_dir)  # type: ignore
                            else:
                                subprocess.Popen(["xdg-open", out_dir])
                except Exception:
                    pass
            else:
                messagebox.showerror("Diff 실패", "비교 작업이 실패했습니다.")
        except (ET.ParseError, OSError, ValueError) as e:
            messagebox.showerror("Diff 실패", f"비교 중 오류: {e}")

    # ----------------------------- CSV 변환 (이전과 동일 로직)
    def _convert_to_csv(self, xml_path):
        # CSV 작성 시점엔 services 테이블이 반드시 채워져야 함 — 지연 로드 보강.
        self._ensure_services_table()
        root = parse_nmap_xml_resilient(xml_path)
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
            # 호스트명 (DNS PTR 또는 nmap 이 받은 사용자 입력 hostname)
            hostname = ""
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                first_hn = hostnames_el.find("hostname")
                if first_hn is not None:
                    hostname = first_hn.get("name", "") or ""
            # OS — best osmatch (가장 정확도 높은 것), "이름 (정확도%)" 포맷
            os_str = ""
            os_el = host.find("os")
            if os_el is not None:
                best = None
                for m in os_el.findall("osmatch"):
                    try:
                        acc = int(m.get("accuracy", "0") or "0")
                    except ValueError:
                        acc = 0
                    if best is None or acc > best[1]:
                        best = (m.get("name", "") or "", acc)
                if best and best[0]:
                    os_str = f"{best[0]} ({best[1]}%)" if best[1] else best[0]

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
                    ostype = svc_el.get("ostype", "") or ""
                    if method == "probed":
                        probed_short = name
                    elif method == "table":
                        probed_short = f"{name}?" if name else ""
                    else:
                        probed_short = name
                    detail = " ".join(p for p in (product, version, extrainfo, ostype) if p).strip()
                else:
                    probed_short = ""
                    detail = ""

                lookup = self._lookup_full(probed_short, guessed)

                # 식별 (4값) — service XML 노드 그대로 분석
                identification = compute_identification_status(svc_el)

                # 비고 — detail + NSE key-line 1~2개 (멀티라인 X)
                scripts = port.findall("script")
                nse_data = [(sc.get("id", "") or "", sc.get("output", "") or "") for sc in scripts]
                remarks = compute_remarks(detail, nse_data)

                # 한 포트 = 한 행 (이슈 3) — NSE 스크립트가 N 개여도 단일 row.
                sids_joined = ", ".join(sid for sid, _ in nse_data if sid)
                output_lines = []
                for sid, raw in nse_data:
                    cleaned = (raw or "").replace("\r", " ").replace("\n", " | ")
                    output_lines.append(f"[{sid}] {cleaned}" if sid else cleaned)
                output_joined = "\n".join(output_lines)

                # NSE 추출 (24번째 컬럼) — TLS_CN/SMB_OS/NTLM_Computer 등 핵심 필드 한 줄.
                nse_summary = ""
                if nse_extract is not None and nse_data:
                    try:
                        merged = nse_extract.extract_all_nse(nse_data)
                        nse_summary = nse_extract.format_nse_summary(merged)
                    except Exception:
                        nse_summary = ""

                rows.append([
                    addr, hostname, os_str,                     # host-level
                    proto, portid, lookup.get("port", ""),       # 프로토콜 / 포트 / 표준포트
                    state, guessed, probed_short,
                    identification,
                    lookup.get("category", ""), lookup.get("usage", ""),
                    lookup.get("risk", ""),
                    lookup.get("encryption", ""), lookup.get("auth", ""),
                    lookup.get("exposure_risk", ""), lookup.get("attack_surface", ""),
                    lookup.get("source", ""),
                    detail, remarks,
                    sids_joined, output_joined,
                    nse_summary,                                 # NSE추출 (24번째)
                    lookup.get("memo", ""),                     # 점검메모 (사용자 편집)
                ])

        csv_path = (self.output_prefix or "") + ".csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "IP", "호스트", "OS",
                "프로토콜", "포트", "표준포트",
                "포트상태", "추측서비스", "확인서비스(short)",
                "식별", "분류", "용도",
                "위험도", "암호화", "인증",
                "노출위험", "공격표면", "출처",
                "상세(제품/버전)", "비고",
                "NSE스크립트명", "스크립트출력",
                "NSE추출",
                "점검메모",
            ])
            for r in rows:
                w.writerow(r)
        return csv_path


def main():
    parser = argparse.ArgumentParser(description="nmapParser")
    parser.add_argument("--xml2csv", help="XML 파일 또는 XML 폴더를 CSV로 변환")
    parser.add_argument("--out", help="xml2csv 출력 폴더")
    parser.add_argument("--open-only", action="store_true", help="open 포트만 CSV 포함")
    parser.add_argument("--categories", help="categories.xlsx 경로 (선택)")
    parser.add_argument("--diff", action="store_true", help="기준/현재 파일 비교(diff) 실행")
    parser.add_argument("--base", help="diff 기준 파일 (.xml/.csv)")
    parser.add_argument("--curr", help="diff 현재 파일 (.xml/.csv)")
    parser.add_argument("--asset", help="asset_id (기본: default)")
    parser.add_argument("--only-changes", action="store_true", help="diff에서 변경 행만 출력")
    parser.add_argument("--out-format", dest="out_format", choices=["csv", "xlsx", "both"],
                        default="both",
                        help="diff 출력 포맷 (csv|xlsx|both, 기본 both)")
    parser.add_argument("--report", action="store_true",
                        help="시간축 5시트 xlsx 보고서 생성 (--csv-folder 와 함께 사용)")
    parser.add_argument("--csv-folder", dest="csv_folder",
                        help="--report 입력 폴더 (.csv 파일들이 있는 디렉토리)")
    args = parser.parse_args()

    if args.xml2csv:
        return run_cli_xml2csv(args)

    if args.diff:
        if not args.base or not args.curr:
            parser.error("--diff 사용 시 --base 와 --curr 가 필요합니다.")
        try:
            return run_cli_diff(args)
        except (OSError, ET.ParseError, ValueError) as e:
            print(f"[diff] FAIL: {e}")
            return 1

    if args.report:
        try:
            import report_generator  # 지연 import — GUI 부팅 비용 0.
            return report_generator.run_cli_report(args)
        except Exception as e:
            print(f"[report] FAIL: {e}")
            return 1

    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    NmapParserApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
