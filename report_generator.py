# -*- coding: utf-8 -*-
"""시간축 보고서 생성기 — CSV 폴더의 여러 시점 스캔 결과를 단일 xlsx 보고서로 합침.

5(또는 6)시트 구성:
  1. 현황      — 가장 최근 시점 CSV 24컬럼 그대로
  2. 히트맵    — 행=IP:port/proto, 열=시점, 셀 색=상태 (신규/유지/닫힘/미관측)
  3. 변경 이력  — 시점 i→i+1 (NEW_OPEN, CLOSED, CHANGED) 카운트
  4. 위험도 추이 — 시점별 상/중/하 카운트
  5. 메타      — CSV 파일 인덱스 + 명령 (있다면)
  6. NSE 상세  — 가장 최근 시점의 NSE 추출 필드 펼침 (TLS_CN, SMB_OS, NTLM_Computer ...)
                — NSE추출 컬럼이 비어 있으면 시트 자체를 생략

CLI:
  python nmapParser.py --report --csv-folder <폴더> [--out <xlsx>]

GUI 에서는 _generate_report_dialog 가 이 모듈을 호출.
"""

import csv
import glob
import os
import re
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


def _read_csv_rows(csv_path):
    """CSV 파일에서 dict 리스트로 읽음. utf-8-sig 우선, cp949 폴백."""
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            with open(csv_path, "r", encoding=enc, newline="") as f:
                return list(csv.DictReader(f)), enc
        except UnicodeDecodeError:
            continue
    return [], "utf-8"


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
    nse = _row_get(row, "NSE추출").strip()
    sig = f"{svc}|{det}|{nse}"
    return re.sub(r"\s+", " ", sig.lower()).strip()


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
    return out


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


def _change_type_for_key(per_tp, key):
    if per_tp and key not in per_tp[-1][1]:
        return "UNOBSERVED"
    prev_open = False
    prev_sig = ""
    last = "UNOBSERVED"
    for _label, d in per_tp:
        r = d.get(key)
        if r is None:
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


def _state_token_timeline(per_tp, key):
    prev_open = False
    prev_sig = ""
    tokens = []
    fills = []
    for _label, d in per_tp:
        r = d.get(key)
        if r is None:
            tokens.append("UNOBSERVED")
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


def _build_sheet_summary_final(snapshots, csv_folder):
    latest_label = snapshots[-1][0]
    baseline_label = snapshots[-2][0] if len(snapshots) >= 2 else ""
    per_tp = _build_snapshot_maps(snapshots)
    counts = {"NEW_OPEN": 0, "CHANGED": 0, "CLOSED": 0, "KEEP": 0}
    for key in _all_observed_open_keys(per_tp):
        counts[_change_type_for_key(per_tp, key)] = counts.get(_change_type_for_key(per_tp, key), 0) + 1
    headers = ["섹션", "항목", "값", "판단/사용 방법", "증적/연결 시트"]
    rows = [
        ["보고 기준", "현재 스캔 시점", latest_label, "이 파일이 대표하는 관측 시점", "01_스캔증적"],
        ["보고 기준", "비교 기준 시점", baseline_label, "NEW/CHANGED/CLOSED 판정 기준", "03_변경추적대장"],
        ["보고 기준", "입력 폴더", csv_folder, "CSV 및 원본 증적 파일을 모으는 기본 결과 디렉터리", "07_증적파일목록"],
        ["변경 요약", "신규 Open", str(counts.get("NEW_OPEN", 0)), "담당자/승인근거 확인 필요", "03_변경추적대장"],
        ["변경 요약", "변경", str(counts.get("CHANGED", 0)), "서비스/상세/NSE 변경 사유 확인", "03_변경추적대장"],
        ["변경 요약", "닫힘", str(counts.get("CLOSED", 0)), "종결 또는 다음 스캔 재확인", "03_변경추적대장"],
        ["Excel 사용", "추천 필터", "변경유형/위험도/담당자/처리상태/처리기한", "복합값을 분해해 필터/정렬 중심으로 사용", "02_시간축히트맵, 05_현재포트현황"],
    ]
    return {"name": "00_보고요약", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [14, 22, 42, 56, 34]}


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
            "col_widths": [24, 10, 18, 34, 34, 34, 34, 34, 12, 8, 30]}


def _build_sheet_heatmap_final(snapshots):
    per_tp = _build_snapshot_maps(snapshots)
    timepoints = [label for label, _rows in snapshots]
    headers = ["자산키", "IP", "IP_3옥텟", "호스트", "OS", "프로토콜", "포트", "포트번호정수", "확인서비스", "분류", "용도", "위험도", "현재상태", "관측횟수", "변경횟수", "마지막변경유형", "담당자", "처리상태", "처리기한", "점검메모"] + timepoints
    rows = []
    cell_fills = []
    row_fills = []
    for key in _all_observed_open_keys(per_tp):
        ip, proto, port = _split_key(key)
        latest = _latest_row_for_key(per_tp, key)
        tokens, fills = _state_token_timeline(per_tp, key)
        change = _change_type_for_key(per_tp, key)
        observed = sum(1 for t in tokens if t != "UNOBSERVED")
        changes = sum(1 for t in tokens if t in ("NEW_OPEN", "CHANGED", "CLOSED"))
        row = [
            f"{ip}|{proto}|{port}", ip, _ip_3octet(ip), _row_get(latest, "호스트"), _row_get(latest, "OS"), proto, port, port,
            _row_service(latest), _row_get(latest, "분류"), _row_get(latest, "용도"), _row_get(latest, "위험도"),
            _state_for_row(latest), str(observed), str(changes), change, "", "미확인" if change in ("NEW_OPEN", "CHANGED") else "", "", _row_get(latest, "점검메모"),
        ] + tokens
        rows.append(row)
        rf = {"NEW_OPEN": xlsx_io.FILL_NEW_OPEN, "CHANGED": xlsx_io.FILL_CHANGED, "CLOSED": xlsx_io.FILL_CLOSED}.get(change, xlsx_io.FILL_KEEP)
        row_fills.append(rf)
        cf = [None] * (len(headers) - len(timepoints)) + fills
        if _row_get(latest, "위험도") == "상":
            cf[11] = xlsx_io.FILL_RISK_HIGH
        cell_fills.append(cf)
    return {"name": "02_시간축히트맵", "headers": headers, "rows": rows, "row_fills": row_fills, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [22, 15, 12, 14, 22, 10, 8, 10, 18, 14, 12, 8, 12, 10, 10, 16, 12, 12, 14, 32] + [18] * len(timepoints)}


def _build_sheet_tracking_final(snapshots):
    per_tp = _build_snapshot_maps(snapshots)
    baseline = snapshots[-2][0] if len(snapshots) >= 2 else ""
    current = snapshots[-1][0]
    headers = ["관리ID", "변경유형", "심각도", "비교기준시점", "current_scan_id", "baseline_scan_id", "IP", "IP_3옥텟", "호스트", "프로토콜", "포트", "포트번호정수", "확인서비스", "포트상태", "위험도", "changed_state", "changed_service", "changed_detail", "changed_nse", "원본XML", "원본LOG", "담당자", "처리상태", "처리기한", "승인/변경티켓", "확인근거", "점검/조치메모"]
    rows, row_fills, cell_fills = [], [], []
    idx = 1
    for key in _all_observed_open_keys(per_tp):
        change = _change_type_for_key(per_tp, key)
        if change in ("KEEP", "UNOBSERVED"):
            continue
        ip, proto, port = _split_key(key)
        latest = _latest_row_for_key(per_tp, key)
        current_row = per_tp[-1][1].get(key, {}) if per_tp else {}
        base_row = per_tp[-2][1].get(key, {}) if len(per_tp) >= 2 else {}
        row = [
            f"TRK-{idx:04d}", change, _row_get(latest, "위험도"), baseline, current, baseline, ip, _ip_3octet(ip), _row_get(latest, "호스트"), proto, port, port,
            _row_service(latest), _state_for_row(latest), _row_get(latest, "위험도"),
            "1" if _state_for_row(current_row) != _state_for_row(base_row) else "0",
            "1" if _row_service(current_row) != _row_service(base_row) else "0",
            "1" if _row_get(current_row, "상세(제품/버전)") != _row_get(base_row, "상세(제품/버전)") else "0",
            "1" if _row_get(current_row, "NSE추출") != _row_get(base_row, "NSE추출") else "0",
            current + ".xml", current + ".log", "", "미확인" if change in ("NEW_OPEN", "CHANGED") else "종결", "", "", "", _row_get(latest, "점검메모"),
        ]
        rows.append(row)
        row_fills.append({"NEW_OPEN": xlsx_io.FILL_NEW_OPEN, "CHANGED": xlsx_io.FILL_CHANGED, "CLOSED": xlsx_io.FILL_CLOSED}.get(change, xlsx_io.FILL_NONE))
        cf = [None] * len(headers)
        if _row_get(latest, "위험도") == "상":
            cf[2] = cf[14] = xlsx_io.FILL_RISK_HIGH
        cell_fills.append(cf)
        idx += 1
    return {"name": "03_변경추적대장", "headers": headers, "rows": rows, "row_fills": row_fills, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [14, 14, 8, 18, 22, 22, 15, 12, 14, 10, 8, 10, 18, 10, 8, 12, 14, 14, 12, 28, 28, 12, 12, 14, 18, 30, 48]}


def _build_sheet_action_history_final():
    headers = ["관리ID", "기록일", "기록시각", "기록자", "이전상태", "변경상태", "조치분류", "조치/확인 내용", "근거자료", "다음 액션"]
    return {"name": "04_조치이력", "headers": headers, "rows": [], "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [18, 12, 12, 12, 12, 12, 14, 48, 28, 34]}


def _build_sheet_current_ports_final(latest_label, latest_rows):
    base_headers = ["scan_id", "IP_3옥텟", "포트번호정수"] + CSV_HEADERS_KO
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
        row = [latest_label, _ip_3octet(ip), port] + [_row_get(r, h, h.upper()) for h in CSV_HEADERS_KO] + [nse.get(k, "") for k in nse_keys]
        rows.append(row)
        cf = [None] * len(headers)
        if _row_get(r, "위험도") == "상":
            try:
                cf[headers.index("위험도")] = xlsx_io.FILL_RISK_HIGH
            except ValueError:
                pass
        cell_fills.append(cf)
    return {"name": "05_현재포트현황", "headers": headers, "rows": rows, "cell_fills": cell_fills,
            "header_fill": xlsx_io.FILL_HEADER, "col_widths": [22, 12, 10] + [14] * len(CSV_HEADERS_KO) + [18] * len(nse_keys)}


def _build_sheet_nse_rows_final(latest_label, latest_rows):
    headers = ["scan_id", "IP", "호스트", "프로토콜", "포트", "서비스", "추출키", "추출값", "비고"]
    rows = []
    for r in latest_rows:
        data = _parse_nse_summary(_row_get(r, "NSE추출"))
        for k, v in data.items():
            rows.append([latest_label, _row_get(r, "IP"), _row_get(r, "호스트"), _row_get(r, "프로토콜"), _row_get(r, "포트"), _row_service(r), k, v, ""])
    return {"name": "06_NSE분해", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [22, 15, 14, 10, 8, 18, 22, 38, 24]}


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
    return {"name": "07_증적파일목록", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [12, 24, 36, 10, 16, 20, 10, 66, 36, 12, 28]}


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
    return {"name": "08_서비스별확인설정", "headers": headers, "rows": rows, "header_fill": xlsx_io.FILL_HEADER,
            "col_widths": [10, 24, 10, 16, 48, 48, 48, 28]}


def _build_final_report_sheets(snapshots, csv_folder, file_meta=None):
    latest_label, latest_rows = snapshots[-1]
    return [
        _build_sheet_summary_final(snapshots, csv_folder),
        _build_sheet_scan_evidence_final(snapshots, csv_folder, file_meta),
        _build_sheet_heatmap_final(snapshots),
        _build_sheet_tracking_final(snapshots),
        _build_sheet_action_history_final(),
        _build_sheet_current_ports_final(latest_label, latest_rows),
        _build_sheet_nse_rows_final(latest_label, latest_rows),
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
                "header_fill": xlsx_io.FILL_HEADER, "col_widths": [24, 34, 34, 34, 34, 34, 12, 8]}
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
    for path, label in files:
        rows, enc = _read_csv_rows(path)
        snapshots.append((label, rows))
        file_meta.append((label, os.path.basename(path), enc))

    if not snapshots:
        raise ValueError("읽을 수 있는 CSV 가 없습니다.")
    valid_row_count = sum(1 for _label, rows in snapshots for r in rows if _key_for_row(r))
    if valid_row_count == 0:
        raise ValueError("유효한 nmapParser CSV 행이 없습니다: IP/프로토콜/포트 컬럼 확인")

    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(csv_folder, f"report_{ts}.xlsx")

    xlsx_io.write_xlsx_multi(out_path, _build_final_report_sheets(snapshots, csv_folder, file_meta))
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
