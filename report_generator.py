# -*- coding: utf-8 -*-
"""시간축 보고서 생성기 — CSV 폴더의 여러 시점 스캔 결과를 단일 xlsx 보고서로 합침.

Excel 추적/보고용 최종 시트 구성:
  00_보고요약
  01_스캔증적
  02_시간축히트맵
  03_변경추적대장
  04_현재Open포트
  05_현재스캔전체
  06_증적파일목록
  07_서비스별확인설정

CLI:
  python nmapParser.py --report --csv-folder <폴더> [--out <xlsx>]

GUI 에서는 _generate_report_dialog 가 이 모듈을 호출.
"""

import csv
import glob
import ipaddress
import os
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime

import xlsx_io


# CSV 24컬럼 표준 헤더 (한국어 우선)
CSV_HEADERS_KO = [
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
]

# 보고서용 표시 정책: 원본 CSV는 호환을 위해 그대로 읽되, Excel 보고서에는
# 비숙련 사용자가 바로 이해하기 어려운 컬럼명/중복 컬럼을 줄인다.
REPORT_EXCLUDED_HEADERS = {"암호화", "인증"}
REPORT_CSV_HEADERS = [h for h in CSV_HEADERS_KO if h not in REPORT_EXCLUDED_HEADERS]
DISPLAY_HEADER_MAP = {
    "IP_3옥텟": "IP대역",
    "추측서비스": "포트기반추정서비스",
    "확인서비스(short)": "스캔식별서비스",
    "확인서비스": "스캔식별서비스",
}
NUMERIC_REPORT_COLUMNS = {"포트", "표준포트", "행 수", "크기_KB", "관측횟수", "변경횟수", "표시순서"}
STATE_DISPLAY_KO = {
    "NEW_OPEN": "신규OPEN",
    "KEEP": "유지",
    "CHANGED": "변경",
    "CLOSED": "닫힘",
    "UNOBSERVED": "미관측",
    "OUT_OF_SCOPE": "대상아님",
}


def _display_header(name):
    return DISPLAY_HEADER_MAP.get(name, name)


def _display_headers(headers):
    return [_display_header(h) for h in headers]


def _display_state_token(token):
    return STATE_DISPLAY_KO.get(token, token)


def _numeric_columns_for(headers):
    return [h for h in headers if h in NUMERIC_REPORT_COLUMNS]


# ---------- 시점(timestamp) 추출
_TS_RE = re.compile(r"(\d{8}_\d{6}|\d{4}-?\d{2}-?\d{2}[_T]\d{2}-?\d{2}-?\d{2})")


def _extract_timestamp(filename):
    """파일명에서 timestamp 추출. 못 찾으면 mtime, 그것도 없으면 파일명 그대로."""
    base = os.path.basename(filename)
    m = _TS_RE.search(base)
    if m:
        return m.group(1)
    try:
        ts = os.path.getmtime(filename)
        return datetime.fromtimestamp(ts).strftime("%Y%m%d_%H%M%S")
    except OSError:
        return base


def _read_csv_rows_with_headers(csv_path):
    """CSV 파일에서 (rows, encoding, headers)로 읽음. utf-8-sig 우선, cp949 폴백."""
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            with open(csv_path, "r", encoding=enc, newline="") as f:
                reader = csv.DictReader(f)
                return list(reader), enc, list(reader.fieldnames or [])
        except UnicodeDecodeError:
            continue
    return [], "utf-8", []


def _read_csv_rows(csv_path):
    """CSV 파일에서 dict 리스트로 읽음. utf-8-sig 우선, cp949 폴백."""
    rows, enc, _headers = _read_csv_rows_with_headers(csv_path)
    return rows, enc


def _validate_required_headers(headers, csv_path=""):
    required = ["IP", "프로토콜", "포트", "포트상태"]
    present = {str(h).strip() for h in (headers or []) if h is not None}
    missing = [h for h in required if h not in present]
    if missing:
        where = f" ({os.path.basename(csv_path)})" if csv_path else ""
        raise ValueError(f"필수 열 누락{where}: {', '.join(missing)}")


def _row_get(row, key, *fallbacks):
    """한국어 + 영문 fallback lookup."""
    v = row.get(key, "")
    if v:
        return v
    for k in fallbacks:
        v = row.get(k, "")
        if v:
            return v
    return ""


def _key_for_row(row):
    """IP:port/proto — 히트맵 row 키."""
    ip = _row_get(row, "IP", "ip").strip()
    proto = _row_get(row, "프로토콜", "PROTO", "proto").strip().lower()
    port = _row_get(row, "포트", "PORT", "port").strip()
    if not (ip and proto and port):
        return None
    return f"{ip}:{port}/{proto}"


def _state_for_row(row):
    """포트상태 normalized."""
    return _row_get(row, "포트상태", "STATE", "state").strip().lower()


def _service_signature(row):
    """확인서비스 + 상세 + NSE추출 — 변경 감지용 시그니처."""
    svc = _row_get(row, "확인서비스(short)", "확인서비스", "SERVICE", "service").strip()
    det = _row_get(row, "상세(제품/버전)", "상세", "DETAIL", "detail").strip()
    nse = _canonical_nse_summary(_row_get(row, "NSE추출"))
    sig = f"{svc}|{det}|{nse}"
    return re.sub(r"\s+", " ", sig.lower()).strip()


def _canonical_nse_summary(summary):
    """NSE추출 key=value 요약을 순서/공백 noise 없이 비교 가능한 문자열로 정규화."""
    pairs = []
    for part in (summary or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = re.sub(r"\s+", " ", k.strip())
        v = re.sub(r"\s+", " ", v.strip())
        if k:
            pairs.append((k.lower(), v.lower()))
    return ";".join(f"{k}={v}" for k, v in sorted(pairs))


def _risk_for_row(row):
    """위험도 — 상/중/하 또는 빈 문자열."""
    r = _row_get(row, "위험도").strip()
    return r if r in ("상", "중", "하") else ""


# ---------- 시트 생성기

def _build_sheet_status(rows_kr):
    """현황 시트 — 24컬럼 그대로."""
    headers = CSV_HEADERS_KO
    rows = []
    for r in rows_kr:
        rows.append([_row_get(r, h, h.upper()) for h in headers])
    return {
        "name": "현황",
        "headers": headers,
        "rows": rows,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [14, 14, 12, 8, 6, 12, 8, 14, 18, 8, 10, 10,
                       6, 14, 14, 28, 28, 24, 30, 24, 18, 30, 30, 20],
    }


def _build_sheet_heatmap(snapshots):
    """히트맵 시트 — 행=IP:port/proto, 열=각 시점, 셀=상태(색).

    snapshots = [(label, rows_dict_list), ...]  (시간 순 정렬됨)
    """
    timepoints = [s[0] for s in snapshots]
    # 모든 키 모으기
    all_keys = set()
    per_tp = []  # [(tp_label, {key: row_dict}), ...]
    for label, rows in snapshots:
        d = {}
        for r in rows:
            k = _key_for_row(r)
            if not k:
                continue
            d[k] = r
        all_keys.update(d.keys())
        per_tp.append((label, d))

    # 한 번이라도 open 이었던 키만 — 노이즈(filtered/closed 만) 제거
    keys_filtered = []
    for k in sorted(all_keys, key=lambda s: (s.split(":")[0], int(s.split(":")[1].split("/")[0]) if s.split(":")[1].split("/")[0].isdigit() else 0)):
        ever_open = False
        for _, d in per_tp:
            r = d.get(k)
            if r and _state_for_row(r) == "open":
                ever_open = True
                break
        if ever_open:
            keys_filtered.append(k)

    headers = ["IP:port/proto"] + timepoints + ["서비스"]
    body_rows = []
    cell_fills_all = []

    for k in keys_filtered:
        prev_open = False
        prev_signature = ""
        # 가장 최근 서비스 (마지막 open 발견된 시점의 service)
        last_service = ""
        cells = [k]
        cell_fills = [xlsx_io.FILL_NONE]
        for label, d in per_tp:
            r = d.get(k)
            if r is None:
                cells.append("")
                cell_fills.append(xlsx_io.FILL_UNOBSERVED)
                # prev_open 유지 (관측 안 함은 상태 변화 아님)
                continue
            state = _state_for_row(r)
            if state == "open":
                svc = _row_get(r, "확인서비스(short)", "확인서비스", "service").strip()
                signature = _service_signature(r)
                last_service = svc or last_service
                if prev_open:
                    if signature != prev_signature:
                        cells.append("변경")
                        cell_fills.append(xlsx_io.FILL_CHANGED)
                    else:
                        cells.append("유지")
                        cell_fills.append(xlsx_io.FILL_KEEP)
                else:
                    cells.append("신규")
                    cell_fills.append(xlsx_io.FILL_NEW_OPEN)
                prev_open = True
                prev_signature = signature
            elif state in ("closed", "filtered"):
                if prev_open:
                    cells.append("닫힘")
                    cell_fills.append(xlsx_io.FILL_CLOSED)
                else:
                    cells.append("")
                    cell_fills.append(xlsx_io.FILL_NONE)
                prev_open = False
                prev_signature = ""
            else:
                cells.append(state)
                cell_fills.append(xlsx_io.FILL_NONE)
        cells.append(last_service)
        cell_fills.append(xlsx_io.FILL_NONE)
        body_rows.append(cells)
        cell_fills_all.append(cell_fills)

    return {
        "name": "히트맵",
        "headers": headers,
        "rows": body_rows,
        "cell_fills": cell_fills_all,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [22] + [14] * len(timepoints) + [22],
    }


def _build_sheet_change_history(snapshots):
    """변경 이력 시트 — 시점 i → i+1 의 NEW_OPEN / CLOSED / CHANGED 카운트."""
    headers = ["from", "to", "NEW_OPEN", "CLOSED", "CHANGED", "UNCHANGED"]
    rows = []
    row_fills = []
    for i in range(len(snapshots) - 1):
        from_label, from_rows = snapshots[i]
        to_label, to_rows = snapshots[i + 1]

        from_open = {}
        for r in from_rows:
            k = _key_for_row(r)
            if k and _state_for_row(r) == "open":
                from_open[k] = _service_signature(r)
        to_open = {}
        for r in to_rows:
            k = _key_for_row(r)
            if k and _state_for_row(r) == "open":
                to_open[k] = _service_signature(r)

        new_open = len(set(to_open.keys()) - set(from_open.keys()))
        closed = len(set(from_open.keys()) - set(to_open.keys()))
        changed = 0
        unchanged = 0
        for k in set(from_open.keys()) & set(to_open.keys()):
            if from_open[k] != to_open[k]:
                changed += 1
            else:
                unchanged += 1

        rows.append([from_label, to_label, str(new_open), str(closed), str(changed), str(unchanged)])
        # 색: NEW_OPEN > 0 이면 빨강 행, CLOSED > 0 이면 자주, 둘 다 없고 CHANGED > 0 이면 노랑
        if new_open > 0:
            row_fills.append(xlsx_io.FILL_NEW_OPEN)
        elif closed > 0:
            row_fills.append(xlsx_io.FILL_CLOSED)
        elif changed > 0:
            row_fills.append(xlsx_io.FILL_CHANGED)
        else:
            row_fills.append(xlsx_io.FILL_NONE)

    return {
        "name": "변경이력",
        "headers": headers,
        "rows": rows,
        "row_fills": row_fills,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [18, 18, 12, 12, 12, 12],
    }


def _build_sheet_risk_trend(snapshots):
    """위험도 추이 시트 — 시점별 상/중/하 카운트 (open 포트 기준)."""
    headers = ["시점", "상", "중", "하", "기타", "open 합계"]
    rows = []
    row_fills = []
    for label, snap_rows in snapshots:
        c_high = c_mid = c_low = c_other = 0
        for r in snap_rows:
            if _state_for_row(r) != "open":
                continue
            risk = _risk_for_row(r)
            if risk == "상":
                c_high += 1
            elif risk == "중":
                c_mid += 1
            elif risk == "하":
                c_low += 1
            else:
                c_other += 1
        total = c_high + c_mid + c_low + c_other
        rows.append([label, str(c_high), str(c_mid), str(c_low), str(c_other), str(total)])
        # 위험도 상이 1 이상이면 행 강조
        row_fills.append(xlsx_io.FILL_RISK_HIGH if c_high > 0 else xlsx_io.FILL_NONE)
    return {
        "name": "위험도추이",
        "headers": headers,
        "rows": rows,
        "row_fills": row_fills,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [18, 8, 8, 8, 8, 14],
    }


def _build_sheet_meta(snapshots, csv_folder, file_meta=None):
    """메타 시트 — 입력 폴더, CSV 파일 목록, 시점, 인코딩."""
    headers = ["index", "timestamp", "filename", "encoding", "행 수"]
    meta_by_label = {}
    for label, fname, enc in (file_meta or []):
        meta_by_label[label] = (fname, enc)
    rows = []
    for i, (label, snap_rows) in enumerate(snapshots, start=1):
        fname, enc = meta_by_label.get(label, ("", ""))
        rows.append([str(i), label, fname, enc, str(len(snap_rows))])
    # csv_folder 정보 한 줄 추가
    if csv_folder:
        rows.insert(0, ["", "csv_folder", csv_folder, "", ""])
        rows.insert(1, ["", "report_generated_at",
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "", ""])
    return {
        "name": "메타",
        "headers": headers,
        "rows": rows,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [8, 24, 50, 14, 10],
    }


def _build_sheet_nse_detail(latest_rows):
    """NSE 상세 시트 — 가장 최근 시점의 NSE추출 필드를 column 별로 펼침.
    NSE추출 컬럼이 모든 행에서 비어 있으면 None 반환 (시트 생략 신호).
    """
    nse_cells = [(_key_for_row(r), _row_get(r, "NSE추출")) for r in latest_rows]
    nse_cells = [(k, v) for k, v in nse_cells if k and v]
    if not nse_cells:
        return None

    # 모든 키 수집 (TLS_CN, SMB_OS, ...)
    all_field_keys = []
    seen = set()
    parsed_per_row = []
    for key, summary in nse_cells:
        d = {}
        # "TLS_CN=foo; SMB_OS=Linux"  -> dict
        for part in summary.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k and v:
                    d[k] = v
                    if k not in seen:
                        seen.add(k)
                        all_field_keys.append(k)
        parsed_per_row.append((key, d))

    # 보기 좋은 순서로 정렬: TLS_*, HTTP_*, SMB_*, NTLM_*, SSH_*, NetBIOS_*, NTP_*, SNMP_*, ...
    def _sort_key(k):
        order = ["TLS_", "HTTP_", "SSH_", "SMB_", "NTLM_", "NetBIOS_",
                 "NTP_", "SNMP_", "MSSQL_", "Oracle_", "IKE_", "SIP_",
                 "RPC_", "Raw_"]
        for i, p in enumerate(order):
            if k.startswith(p):
                return (i, k)
        return (len(order), k)

    all_field_keys.sort(key=_sort_key)
    headers = ["IP:port/proto"] + all_field_keys
    rows = []
    for key, d in parsed_per_row:
        row = [key] + [d.get(k, "") for k in all_field_keys]
        rows.append(row)
    return {
        "name": "NSE상세",
        "headers": headers,
        "rows": rows,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [22] + [16] * len(all_field_keys),
    }


# ---------- 진입점

def collect_csv_files(csv_folder):
    """폴더 안의 *.csv 파일을 timestamp 순으로 정렬해 반환.
    diff/snapshot/summary 패턴은 제외 (--diff 결과물). 시점별 정렬은 timestamp 기준."""
    if not os.path.isdir(csv_folder):
        raise FileNotFoundError(f"CSV 폴더 없음: {csv_folder}")
    out = []
    for path in glob.glob(os.path.join(csv_folder, "*.csv")):
        base = os.path.basename(path).lower()
        # diff CLI 결과물 제외
        if base.startswith(("diff_", "summary_", "snapshot_")):
            continue
        out.append((path, _extract_timestamp(path)))
    out.sort(key=lambda x: (x[1], x[0]))
    counts = {}
    unique = []
    for path, label in out:
        counts[label] = counts.get(label, 0) + 1
        unique_label = label if counts[label] == 1 else f"{label}_{counts[label]}"
        unique.append((path, unique_label))
    return unique


# ---------- XLSX 중심 최종 산출물 생성기

def _split_key(key):
    """'ip:port/proto' 형태의 내부 키를 Excel 필터용 컬럼으로 분해."""
    try:
        ip, rest = key.split(":", 1)
        port, proto = rest.split("/", 1)
        return ip, proto, port
    except ValueError:
        return key, "", ""


def _ip_3octet(ip):
    parts = (ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ""


def _parse_nse_summary(summary):
    d = {}
    for part in (summary or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k:
            d[k] = v
    return d


def _row_service(row):
    return _row_get(row, "확인서비스(short)", "확인서비스", "service").strip() or _row_get(row, "추측서비스").strip()


def _parse_port_targets(port_text):
    """nmap -p 형식의 최소 포트 scope 파서. 알 수 없는 표현식은 UNKNOWN 처리."""
    ports = {"tcp": set(), "udp": set(), "any": set()}
    unknown = False
    current_proto = "any"
    for raw in re.split(r"[,\s]+", port_text or ""):
        token = raw.strip().strip('"\'')
        if not token:
            continue
        proto = current_proto
        if ":" in token:
            prefix, rest = token.split(":", 1)
            p = prefix.strip().upper()
            if p == "T":
                proto = current_proto = "tcp"
                token = rest
            elif p == "U":
                proto = current_proto = "udp"
                token = rest
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, end = token.split("-", 1)
            if start.isdigit() and end.isdigit():
                a, b = int(start), int(end)
                if 1 <= a <= b <= 65535:
                    ports[proto].update(str(p) for p in range(a, b + 1))
                    continue
            unknown = True
            continue
        if token.isdigit() and 1 <= int(token) <= 65535:
            ports[proto].add(str(int(token)))
        else:
            unknown = True
    return {"known": any(ports.values()), "ports": ports, "unknown": unknown, "raw": port_text or ""}


def _parse_scope_targets(target_text, ports=None):
    """보고서용 최소 scope 파서. CIDR/IP와 명시적 -p 포트만 확정 판정한다."""
    networks = []
    unknown = False
    for raw in re.split(r"[\s,;]+", target_text or ""):
        token = raw.strip().strip('"\'')
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
            continue
        except ValueError:
            pass
        # 10.0.0.1-50 같은 nmap shorthand는 일부러 추정하지 않는다.
        unknown = True
    port_scope = _parse_port_targets(ports)
    scope = {
        "known": bool(networks),
        "networks": networks,
        "raw": target_text or "",
        "port_known": port_scope["known"],
        "ports": port_scope["ports"],
        "port_raw": port_scope["raw"],
    }
    if not networks and unknown:
        scope["known"] = False
    return scope


def _ip_in_scope(ip, scope):
    if not scope or not scope.get("known"):
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(addr in net for net in scope.get("networks", []))


def _port_in_scope(port, proto, scope):
    if not scope or not scope.get("port_known"):
        return None
    port = str(port or "").strip()
    if port.isdigit():
        port = str(int(port))
    proto = (proto or "").strip().lower()
    ports = scope.get("ports") or {}
    return port in (ports.get("any") or set()) or port in (ports.get(proto) or set())


def _scope_for_missing_key(label, key, scope_info=None):
    ip, proto, port = _split_key(key)
    scope = (scope_info or {}).get(label)
    in_scope = _ip_in_scope(ip, scope)
    port_in_scope = _port_in_scope(port, proto, scope)
    if in_scope is False or port_in_scope is False:
        return "OUT_OF_SCOPE"
    return "UNOBSERVED"


def _duplicate_port_count(snapshots):
    count = 0
    for _label, rows in snapshots:
        seen = set()
        for r in rows:
            k = _key_for_row(r)
            if not k:
                continue
            if k in seen:
                count += 1
            seen.add(k)
    return count


def _build_snapshot_maps(snapshots):
    out = []
    for label, rows in snapshots:
        d = {}
        for r in rows:
            k = _key_for_row(r)
            if k:
                d[k] = r
        out.append((label, d))
    return out


def _latest_row_for_key(per_tp, key):
    for _label, d in reversed(per_tp):
        if key in d:
            return d[key]
    return {}


def _change_type_for_key(per_tp, key, scope_info=None):
    if per_tp and key not in per_tp[-1][1]:
        return _scope_for_missing_key(per_tp[-1][0], key, scope_info)
    prev_open = False
    prev_sig = ""
    last = "UNOBSERVED"
    for label, d in per_tp:
        r = d.get(key)
        if r is None:
            last = _scope_for_missing_key(label, key, scope_info)
            continue
        state = _state_for_row(r)
        if state == "open":
            sig = _service_signature(r)
            if prev_open:
                last = "CHANGED" if sig != prev_sig else "KEEP"
            else:
                last = "NEW_OPEN"
            prev_open = True
            prev_sig = sig
        elif state in ("closed", "filtered"):
            last = "CLOSED" if prev_open else state.upper()
            prev_open = False
            prev_sig = ""
        else:
            last = state.upper() if state else "UNOBSERVED"
    return last


def _state_token_timeline(per_tp, key, scope_info=None):
    prev_open = False
    prev_sig = ""
    tokens = []
    fills = []
    for label, d in per_tp:
        r = d.get(key)
        if r is None:
            token = _scope_for_missing_key(label, key, scope_info)
            tokens.append(token)
            fills.append(xlsx_io.FILL_UNOBSERVED)
            continue
        state = _state_for_row(r)
        if state == "open":
            sig = _service_signature(r)
            if prev_open:
                token = "CHANGED" if sig != prev_sig else "KEEP"
                fill = xlsx_io.FILL_CHANGED if token == "CHANGED" else xlsx_io.FILL_KEEP
            else:
                token = "NEW_OPEN"
                fill = xlsx_io.FILL_NEW_OPEN
            prev_open = True
            prev_sig = sig
        elif state in ("closed", "filtered"):
            token = "CLOSED" if prev_open else state.upper()
            fill = xlsx_io.FILL_CLOSED if token == "CLOSED" else xlsx_io.FILL_NONE
            prev_open = False
            prev_sig = ""
        else:
            token = state.upper() if state else ""
            fill = xlsx_io.FILL_NONE
        tokens.append(token)
        fills.append(fill)
    return tokens, fills


def _all_observed_open_keys(per_tp):
    keys = set()
    for _label, d in per_tp:
        for k, r in d.items():
            if _state_for_row(r) == "open":
                keys.add(k)
    def sort_key(k):
        ip, proto, port = _split_key(k)
        return (ip, proto, int(port) if str(port).isdigit() else 0, str(port))
    return sorted(keys, key=sort_key)


def _build_sheet_summary_final(snapshots, csv_folder, scope_info=None, file_meta=None):
    latest_label = snapshots[-1][0]
    latest_rows = snapshots[-1][1]
    latest_csv = ""
    if file_meta:
        latest_csv = {label: fname for label, fname, _enc in file_meta}.get(latest_label, "")
    per_tp = _build_snapshot_maps(snapshots)
    all_open_keys = _all_observed_open_keys(per_tp)
    current_open_rows = [r for r in latest_rows if _state_for_row(r) == "open"]
    current_open = len(current_open_rows)
    current_total = sum(1 for r in latest_rows if _key_for_row(r))
    cumulative_ips = { _split_key(k)[0] for k in all_open_keys }
    current_open_ips = { _row_get(r, "IP") for r in current_open_rows if _row_get(r, "IP") }
    current_non_open = sum(1 for r in latest_rows if _key_for_row(r) and _state_for_row(r) != "open")
    duplicate_count = _duplicate_port_count(snapshots)
    scope_missing = sum(1 for label, _rows in snapshots if not ((scope_info or {}).get(label) or {}).get("known"))
    port_scope_missing = sum(1 for label, _rows in snapshots if not ((scope_info or {}).get(label) or {}).get("port_known"))
    headers = ["섹션", "항목", "값", "판단/사용 방법", "증적/연결 시트"]
    rows = [
        ["보고 기준", "현재 스캔 시점", latest_label, "이번 보고서에서 우선 확인할 최신 관측 시점", "01_스캔증적"],
        ["보고 기준", "입력 폴더", csv_folder, "CSV 및 원본 증적 파일을 모으는 기본 결과 디렉터리", "06_증적파일목록"],
        ["보고 기준", "최신 CSV 파일", latest_csv, "이번 스캔 open/전체 시트의 기준 파일", "04_현재Open포트, 05_현재스캔전체"],
        ["지금까지 스캔 통합", "스캔 파일 수", str(len(snapshots)), "보고서에 통합된 CSV 시점 수", "01_스캔증적"],
        ["지금까지 스캔 통합", "누적 관측 포트 수", str(len(all_open_keys)), "한 번이라도 open으로 관측된 IP/프로토콜/포트 수", "02_시간축히트맵"],
        ["지금까지 스캔 통합", "누적 관측 IP 수", str(len(cumulative_ips)), "한 번이라도 open 포트가 있었던 IP 수", "02_시간축히트맵"],
        ["이번 스캔", "이번 스캔 전체 포트 행 수", str(current_total), "최신 CSV에서 확인된 전체 포트 상태 행", "05_현재스캔전체"],
        ["이번 스캔", "이번 스캔 open 포트 수", str(current_open), "최신 스캔에서 open인 포트만 우선 확인", "04_현재Open포트"],
        ["이번 스캔", "이번 스캔 open IP 수", str(len(current_open_ips)), "최신 스캔에서 open 포트가 있는 IP 수", "04_현재Open포트"],
        ["이번 스캔", "이번 스캔 non-open 행 수", str(current_non_open), "closed/filtered 등 open이 아닌 최신 포트 상태 행", "05_현재스캔전체"],
        ["데이터 품질 경고", "IP 범위정보없음", str(scope_missing), "IP 범위정보가 없으면 OUT_OF_SCOPE 판정이 제한됨", "00_보고요약"],
        ["데이터 품질 경고", "포트 범위정보없음", str(port_scope_missing), "-p/스캔포트 정보가 없으면 포트 일부 스캔 여부 판정이 제한됨", "00_보고요약"],
        ["데이터 품질 경고", "중복 포트 행", str(duplicate_count), "동일 IP/프로토콜/포트 중복은 마지막 행 기준 처리", "01_스캔증적"],
        ["상태 정의", "UNOBSERVED", "미관측", "해당 시점 스캔 대상일 수 있으나 결과 행이 없음. 닫힘 아님", "02_시간축히트맵"],
        ["상태 정의", "OUT_OF_SCOPE", "측정대상아님", "해당 시점 IP 또는 포트 스캔 범위 밖. 닫힘/조치 대상으로 단정 금지", "02_시간축히트맵"],
        ["Excel 사용", "추천 필터", "위험도/담당자/처리상태/처리기한", "통합 현황은 히트맵, 최신 확인은 현재 Open 포트 시트를 사용", "02_시간축히트맵, 04_현재Open포트"],
    ]
    return {"name": "00_보고요약", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [18, 24, 42, 64, 38]}


def _build_sheet_scan_evidence_final(snapshots, csv_folder, file_meta=None):
    headers = ["scan_id", "역할", "시점", "CSV파일", "XML파일", "NMAP파일", "GNMAP파일", "LOG파일", "CSV인코딩", "행 수", "비고"]
    meta = {label: (fname, enc) for label, fname, enc in (file_meta or [])}
    rows = []
    for i, (label, snap_rows) in enumerate(snapshots):
        role = "현재" if i == len(snapshots) - 1 else ("기준" if i == len(snapshots) - 2 else "과거")
        csv_name, enc = meta.get(label, ("", ""))
        stem = os.path.splitext(csv_name)[0] if csv_name else label
        rows.append([label, role, label, csv_name, stem + ".xml", stem + ".nmap", stem + ".gnmap", stem + ".log", enc, str(len(snap_rows)), ""])
    return {"name": "01_스캔증적", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [24, 10, 18, 34, 34, 34, 34, 34, 12, 8, 30],
            "numeric_columns": _numeric_columns_for(headers)}


def _build_sheet_heatmap_final(snapshots, scope_info=None):
    per_tp = _build_snapshot_maps(snapshots)
    timepoints = [label for label, _rows in snapshots]
    headers = ["자산키", "IP", "IP대역", "호스트", "OS", "프로토콜", "포트", "스캔식별서비스", "분류", "용도", "위험도", "현재상태", "관측횟수", "변경횟수", "마지막변경유형", "담당자", "처리상태", "처리기한", "점검메모"] + timepoints
    rows = []
    cell_fills = []
    row_fills = []
    for key in _all_observed_open_keys(per_tp):
        ip, proto, port = _split_key(key)
        latest = _latest_row_for_key(per_tp, key)
        tokens, fills = _state_token_timeline(per_tp, key, scope_info=scope_info)
        change = _change_type_for_key(per_tp, key, scope_info=scope_info)
        observed = sum(1 for t in tokens if t not in ("UNOBSERVED", "OUT_OF_SCOPE"))
        changes = sum(1 for t in tokens if t in ("NEW_OPEN", "CHANGED", "CLOSED"))
        row = [
            f"{ip}|{proto}|{port}", ip, _ip_3octet(ip), _row_get(latest, "호스트"), _row_get(latest, "OS"), proto, port,
            _row_service(latest), _row_get(latest, "분류"), _row_get(latest, "용도"), _row_get(latest, "위험도"),
            _state_for_row(latest), str(observed), str(changes), _display_state_token(change), "", "미확인" if change in ("NEW_OPEN", "CHANGED") else "", "", _row_get(latest, "점검메모"),
        ] + [_display_state_token(t) for t in tokens]
        rows.append(row)
        rf = {"NEW_OPEN": xlsx_io.FILL_NEW_OPEN, "CHANGED": xlsx_io.FILL_CHANGED, "CLOSED": xlsx_io.FILL_CLOSED}.get(change, xlsx_io.FILL_KEEP)
        row_fills.append(rf)
        cf = [None] * (len(headers) - len(timepoints)) + fills
        if _row_get(latest, "위험도") == "상":
            cf[11] = xlsx_io.FILL_RISK_HIGH
        cell_fills.append(cf)
    return {"name": "02_시간축히트맵", "headers": headers, "rows": rows, "row_fills": row_fills, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [22, 15, 12, 14, 22, 10, 8, 18, 18, 14, 12, 8, 12, 10, 16, 12, 12, 14, 32] + [18] * len(timepoints),
            "numeric_columns": _numeric_columns_for(headers)}


def _build_sheet_tracking_final(snapshots, file_meta=None, scope_info=None):
    per_tp = _build_snapshot_maps(snapshots)
    baseline = snapshots[-2][0] if len(snapshots) >= 2 else ""
    current = snapshots[-1][0]
    stem_by_label = {label: os.path.splitext(fname)[0] for label, fname, _enc in (file_meta or [])}
    headers = ["관리ID", "변경유형", "심각도", "비교기준시점", "current_scan_id", "baseline_scan_id", "IP", "IP대역", "호스트", "프로토콜", "포트", "스캔식별서비스", "포트상태", "위험도", "changed_state", "changed_service", "changed_detail", "changed_nse", "원본XML", "원본LOG", "담당자", "처리상태", "처리기한", "승인/변경티켓", "확인근거", "점검/조치메모"]
    rows, row_fills, cell_fills = [], [], []
    idx = 1
    for key in _all_observed_open_keys(per_tp):
        change = _change_type_for_key(per_tp, key, scope_info=scope_info)
        if change in ("KEEP", "UNOBSERVED", "OUT_OF_SCOPE"):
            continue
        ip, proto, port = _split_key(key)
        latest = _latest_row_for_key(per_tp, key)
        current_row = per_tp[-1][1].get(key, {}) if per_tp else {}
        base_row = per_tp[-2][1].get(key, {}) if len(per_tp) >= 2 else {}
        row = [
            f"TRK-{idx:04d}", change, _row_get(latest, "위험도"), baseline, current, baseline, ip, _ip_3octet(ip), _row_get(latest, "호스트"), proto, port,
            _row_service(latest), _state_for_row(latest), _row_get(latest, "위험도"),
            "1" if _state_for_row(current_row) != _state_for_row(base_row) else "0",
            "1" if _row_service(current_row) != _row_service(base_row) else "0",
            "1" if _row_get(current_row, "상세(제품/버전)") != _row_get(base_row, "상세(제품/버전)") else "0",
            "1" if _canonical_nse_summary(_row_get(current_row, "NSE추출")) != _canonical_nse_summary(_row_get(base_row, "NSE추출")) else "0",
            stem_by_label.get(current, current) + ".xml", stem_by_label.get(current, current) + ".log", "", "미확인" if change in ("NEW_OPEN", "CHANGED") else "종결", "", "", "", _row_get(latest, "점검메모"),
        ]
        rows.append(row)
        row_fills.append({"NEW_OPEN": xlsx_io.FILL_NEW_OPEN, "CHANGED": xlsx_io.FILL_CHANGED, "CLOSED": xlsx_io.FILL_CLOSED}.get(change, xlsx_io.FILL_NONE))
        cf = [None] * len(headers)
        if _row_get(latest, "위험도") == "상":
            cf[2] = cf[13] = xlsx_io.FILL_RISK_HIGH
        cell_fills.append(cf)
        idx += 1
    return {"name": "03_변경추적대장", "headers": headers, "rows": rows, "row_fills": row_fills, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [14, 14, 8, 18, 22, 22, 15, 12, 14, 10, 8, 18, 10, 8, 12, 14, 14, 12, 28, 28, 12, 12, 14, 18, 30, 48],
            "numeric_columns": _numeric_columns_for(headers)}



def _build_sheet_current_ports_final(latest_label, latest_rows):
    csv_headers = list(REPORT_CSV_HEADERS)
    base_headers = ["scan_id", "IP대역"] + _display_headers(csv_headers)
    nse_keys = []
    seen = set()
    for r in latest_rows:
        for k in _parse_nse_summary(_row_get(r, "NSE추출")).keys():
            if k not in seen:
                seen.add(k)
                nse_keys.append(k)
    headers = base_headers + nse_keys
    rows, cell_fills = [], []
    for r in latest_rows:
        ip = _row_get(r, "IP")
        port = _row_get(r, "포트")
        nse = _parse_nse_summary(_row_get(r, "NSE추출"))
        row = [latest_label, _ip_3octet(ip)] + [_row_get(r, h, h.upper()) for h in csv_headers] + [nse.get(k, "") for k in nse_keys]
        rows.append(row)
        cf = [None] * len(headers)
        if _row_get(r, "위험도") == "상":
            try:
                cf[headers.index("위험도")] = xlsx_io.FILL_RISK_HIGH
            except ValueError:
                pass
        cell_fills.append(cf)
    return {"name": "05_현재스캔전체", "headers": headers, "rows": rows, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [22, 12] + [14] * len(csv_headers) + [18] * len(nse_keys),
            "numeric_columns": _numeric_columns_for(headers)}


def _build_sheet_current_open_ports_final(latest_label, latest_rows):
    open_rows = [r for r in latest_rows if _state_for_row(r) == "open"]
    sheet = _build_sheet_current_ports_final(latest_label, open_rows)
    sheet["name"] = "04_현재Open포트"
    return sheet


def _sha256_file(path):
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _build_sheet_file_list_final(csv_folder):
    headers = ["파일ID", "scan_id", "파일명", "확장자", "종류", "수정일시", "크기_KB", "SHA256", "보관폴더", "검증상태", "비고"]
    rows = []
    patterns = ["*.xml", "*.nmap", "*.gnmap", "*.log", "*.csv"]
    files = []
    for pat in patterns:
        files.extend(glob.glob(os.path.join(csv_folder, pat)))
    files = sorted(set(files))
    kind = {".xml": "XML 원본", ".nmap": "NMAP 원문", ".gnmap": "GNMAP 원문", ".log": "실행 로그", ".csv": "CSV 정규화", ".xlsx": "XLSX"}
    for i, p in enumerate(files, start=1):
        ext = os.path.splitext(p)[1].lower()
        stat = os.stat(p)
        stem = os.path.splitext(os.path.basename(p))[0]
        rows.append([f"FILE-{i:04d}", stem, os.path.basename(p), ext, kind.get(ext, "파일"), datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"), str(round(stat.st_size / 1024, 1)), _sha256_file(p), os.path.dirname(p), "OK", ""])
    return {"name": "06_증적파일목록", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [12, 24, 36, 10, 16, 20, 10, 66, 36, 12, 28],
            "numeric_columns": _numeric_columns_for(headers)}


def _build_sheet_service_settings_final():
    headers = ["표시순서", "사용자표시명", "활성화", "서비스범주", "내부_NSE_목록", "결과_분해컬럼", "설명", "비고"]
    rows = [
        ["1", "웹/HTTP 확인", "ON", "웹", "http-headers, http-server-header, http-title", "HTTP_Server, HTTP_Title", "웹 서버 종류와 페이지 제목 확인", ""],
        ["2", "TLS/인증서 확인", "ON", "TLS", "ssl-cert, ssl-enum-ciphers, tls-alpn", "TLS_CN, TLS_Issuer, TLS_NotAfter", "인증서 주체/발급자/만료일 확인", ""],
        ["3", "SSH 확인", "ON", "원격접속", "ssh-hostkey", "SSH_FP_SHA256", "SSH 호스트키 fingerprint 확인", ""],
        ["4", "Windows/SMB 확인", "ON", "파일공유", "nbstat, smb-os-discovery, smb-protocols", "SMB_OS, SMB_Computer, SMB_Domain, SMB_HasV1", "Windows 자산/도메인/SMBv1 확인", ""],
        ["5", "RDP 확인", "ON", "원격접속", "rdp-ntlm-info", "NTLM_Computer, NTLM_Domain", "RDP 호스트명/도메인 확인", ""],
        ["6", "DBMS 확인", "ON", "DBMS", "ms-sql-info, oracle-tns-version", "MSSQL_Version, Oracle_Version", "DB 서비스 버전/리스너 정보 확인", ""],
        ["7", "UDP 주요 서비스 확인", "ON", "UDP", "snmp-info, ike-version, sip-methods, ntp-info", "SNMP_sysDescr, IKE_Version, SIP_Methods, NTP_Stratum", "SNMP/IKE/SIP/NTP 응답 확인", ""],
        ["8", "미식별 응답 확인", "ON", "기타", "fingerprint-strings", "Raw_FirstLine", "식별 실패 포트의 원본 응답 일부 확인", ""],
    ]
    return {"name": "07_서비스별확인설정", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [10, 24, 10, 16, 48, 48, 48, 28],
            "numeric_columns": _numeric_columns_for(headers)}


def _load_scope_from_xml(xml_path):
    """nmap XML의 실제 scaninfo/host 주소에서 최소 scope를 읽는다."""
    if not os.path.isfile(xml_path):
        return None
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return None

    targets = []
    seen_targets = set()
    for addr in root.findall(".//address"):
        value = (addr.attrib.get("addr") or "").strip()
        if not value or value in seen_targets:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        seen_targets.add(value)
        targets.append(value)

    port_parts = []
    for scaninfo in root.findall("scaninfo"):
        services = (scaninfo.attrib.get("services") or "").strip()
        if not services:
            continue
        proto = (scaninfo.attrib.get("protocol") or "").strip().lower()
        if proto == "tcp":
            port_parts.append("T:" + services)
        elif proto == "udp":
            port_parts.append("U:" + services)
        else:
            port_parts.append(services)

    if not targets and not port_parts:
        return None
    return _parse_scope_targets(" ".join(targets), ports=",".join(port_parts))


def _load_scope_for_csv(csv_path, rows):
    """CSV 메타 컬럼/sidecar/log에서 최소 target+port scope를 읽는다. 없으면 unknown."""
    for r in rows:
        target = _row_get(r, "스캔대상", "대상범위", "target", "targets", "scope").strip()
        ports = _row_get(r, "스캔포트", "포트범위", "scan_ports", "port_scope", "ports").strip()
        if target or ports:
            return _parse_scope_targets(target, ports=ports)
    stem = os.path.splitext(csv_path)[0]
    xml_scope = _load_scope_from_xml(stem + ".xml")
    if xml_scope is not None:
        return xml_scope
    for suffix in (".targets", ".scope", ".target.txt", ".targets.txt"):
        p = stem + suffix
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8-sig") as f:
                    return _parse_scope_targets(f.read())
            except OSError:
                pass
    log_path = stem + ".log"
    if os.path.isfile(log_path):
        try:
            with open(log_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                text = f.read(4096)
            m = re.search(r"\[명령\]\s*(.+)", text)
            if m:
                tokens = shlex.split(m.group(1), posix=False)
                targets = []
                ports = ""
                skip_next = False
                for i, tok in enumerate(tokens[1:], start=1):
                    if skip_next:
                        skip_next = False
                        continue
                    if tok == "-p":
                        if i + 1 < len(tokens):
                            ports = tokens[i + 1]
                        skip_next = True
                        continue
                    if tok.startswith("-p") and len(tok) > 2:
                        ports = tok[2:]
                        continue
                    if tok in ("-oA", "-oX", "-oN", "-oG", "-oS", "-iL", "--top-ports"):
                        skip_next = True
                        continue
                    if tok.startswith("-"):
                        continue
                    targets.append(tok)
                if targets or ports:
                    return _parse_scope_targets(" ".join(targets), ports=ports)
        except Exception:
            pass
    return _parse_scope_targets("")


def _build_final_report_sheets(snapshots, csv_folder, file_meta=None, scope_info=None):
    latest_label, latest_rows = snapshots[-1]
    return [
        _build_sheet_summary_final(snapshots, csv_folder, scope_info=scope_info, file_meta=file_meta),
        _build_sheet_scan_evidence_final(snapshots, csv_folder, file_meta),
        _build_sheet_heatmap_final(snapshots, scope_info=scope_info),
        _build_sheet_tracking_final(snapshots, file_meta=file_meta, scope_info=scope_info),
        _build_sheet_current_open_ports_final(latest_label, latest_rows),
        _build_sheet_current_ports_final(latest_label, latest_rows),
        _build_sheet_file_list_final(csv_folder),
        _build_sheet_service_settings_final(),
    ]


def generate_individual_xlsx(csv_path, out_path=None):
    """CSV 하나를 개별 스캔 XLSX로 변환. 원본 workflow 보조 산출물."""
    rows, enc = _read_csv_rows(csv_path)
    if not any(_key_for_row(r) for r in rows):
        raise ValueError("유효한 nmapParser CSV 행이 없습니다: IP/프로토콜/포트 컬럼 확인")
    if out_path is None:
        out_path = os.path.splitext(csv_path)[0] + ".xlsx"
    label = _extract_timestamp(csv_path)
    stem = os.path.splitext(os.path.basename(csv_path))[0]
    port_sheet = _build_sheet_current_ports_final(label, rows)
    port_sheet["name"] = "포트현황"
    evidence = {"name": "스캔증적", "headers": ["scan_id", "CSV파일", "XML파일", "NMAP파일", "GNMAP파일", "LOG파일", "CSV인코딩", "행 수"],
                "rows": [[label, os.path.basename(csv_path), stem + ".xml", stem + ".nmap", stem + ".gnmap", stem + ".log", enc, str(len(rows))]],
                "header_fill": xlsx_io.FILL_HEADER, "col_widths": [24, 34, 34, 34, 34, 34, 12, 8],
                "numeric_columns": ["행 수"]}
    service = _build_sheet_service_settings_final()
    service["name"] = "서비스별확인"
    xlsx_io.write_xlsx_multi(out_path, [port_sheet, evidence, service])
    return out_path


def generate_report(csv_folder, out_path=None):
    """csv_folder 의 CSV 를 Excel 추적/보고 중심의 최종 9시트 xlsx 로 통합."""
    files = collect_csv_files(csv_folder)
    if not files:
        raise ValueError(f"CSV 파일이 없습니다: {csv_folder}")

    snapshots = []
    file_meta = []
    scope_info = {}
    for path, label in files:
        rows, enc, headers = _read_csv_rows_with_headers(path)
        _validate_required_headers(headers, path)
        snapshots.append((label, rows))
        file_meta.append((label, os.path.basename(path), enc))
        scope_info[label] = _load_scope_for_csv(path, rows)

    if not snapshots:
        raise ValueError("읽을 수 있는 CSV 가 없습니다.")
    valid_row_count = sum(1 for _label, rows in snapshots for r in rows if _key_for_row(r))
    if valid_row_count == 0:
        raise ValueError("유효한 nmapParser CSV 행이 없습니다: IP/프로토콜/포트 컬럼 확인")

    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(csv_folder, f"report_{ts}.xlsx")

    xlsx_io.write_xlsx_multi(out_path, _build_final_report_sheets(snapshots, csv_folder, file_meta, scope_info=scope_info))
    return out_path


def run_cli_report(args):
    """nmapParser.py --report --csv-folder <path> [--out <xlsx>]"""
    folder = getattr(args, "csv_folder", None)
    if not folder:
        print("[report] FAIL: --csv-folder 가 필요합니다.")
        return 1
    out_path = getattr(args, "out", None)
    try:
        result = generate_report(folder, out_path)
    except Exception as e:
        print(f"[report] FAIL: {e}")
        return 1
    try:
        files = collect_csv_files(folder)
        latest = os.path.basename(files[-1][0]) if files else ""
        sheet_count = 0
        try:
            import zipfile
            with zipfile.ZipFile(result) as z:
                sheet_count = len([n for n in z.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")])
        except Exception:
            sheet_count = 0
        print(f"[report] OK: {result}")
        print(f"[report] SUMMARY: csv_files={len(files)} sheets={sheet_count} latest={latest}")
    except Exception:
        print(f"[report] OK: {result}")
    return 0
