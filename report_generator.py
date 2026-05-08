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
                last_service = svc or last_service
                if prev_open:
                    cells.append("유지")
                    cell_fills.append(xlsx_io.FILL_KEEP)
                else:
                    cells.append("신규")
                    cell_fills.append(xlsx_io.FILL_NEW_OPEN)
                prev_open = True
            elif state in ("closed", "filtered"):
                if prev_open:
                    cells.append("닫힘")
                    cell_fills.append(xlsx_io.FILL_CLOSED)
                else:
                    cells.append("")
                    cell_fills.append(xlsx_io.FILL_NONE)
                prev_open = False
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


def _build_sheet_meta(snapshots, csv_folder):
    """메타 시트 — 입력 폴더, CSV 파일 목록, 시점."""
    headers = ["index", "timestamp", "filename", "행 수"]
    rows = []
    for i, (label, snap_rows) in enumerate(snapshots, start=1):
        # 파일명 복원 — _build_snapshots 가 (label, rows, filename) 안 주므로 별도 path 매칭 필요
        rows.append([str(i), label, "", str(len(snap_rows))])
    # csv_folder 정보 한 줄 추가
    if csv_folder:
        rows.insert(0, ["", "csv_folder", csv_folder, ""])
        rows.insert(1, ["", "report_generated_at",
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""])
    return {
        "name": "메타",
        "headers": headers,
        "rows": rows,
        "header_fill": xlsx_io.FILL_HEADER,
        "col_widths": [8, 24, 50, 10],
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


def generate_report(csv_folder, out_path=None):
    """csv_folder 의 모든 CSV 를 5(or 6) 시트 xlsx 로 통합. 경로 반환.

    out_path 가 None 이면 csv_folder/report_<timestamp>.xlsx.
    """
    files = collect_csv_files(csv_folder)
    if not files:
        raise ValueError(f"CSV 파일이 없습니다: {csv_folder}")

    snapshots = []  # [(label, rows_dict_list), ...]
    file_meta = []  # [(label, filename, encoding), ...]
    for path, label in files:
        rows, enc = _read_csv_rows(path)
        snapshots.append((label, rows))
        file_meta.append((label, os.path.basename(path), enc))

    if not snapshots:
        raise ValueError("읽을 수 있는 CSV 가 없습니다.")

    latest_label, latest_rows = snapshots[-1]

    sheets = []
    sheets.append(_build_sheet_status(latest_rows))
    sheets.append(_build_sheet_heatmap(snapshots))
    if len(snapshots) >= 2:
        sheets.append(_build_sheet_change_history(snapshots))
    sheets.append(_build_sheet_risk_trend(snapshots))

    # 메타: 파일명 채우기
    meta = _build_sheet_meta(snapshots, csv_folder)
    # rows 첫 2줄 (csv_folder + generated_at) 다음에 인덱스 행 ; 파일명 매칭.
    meta_rows_with_files = list(meta["rows"])
    # 인덱스 행이 csv_folder/generated_at 다음 위치에 있다고 가정
    file_idx_offset = 2 if csv_folder else 0
    for i, (label, fname, enc) in enumerate(file_meta):
        idx = file_idx_offset + i
        if idx < len(meta_rows_with_files):
            meta_rows_with_files[idx][2] = fname  # filename 컬럼
    meta["rows"] = meta_rows_with_files
    sheets.append(meta)

    nse_sheet = _build_sheet_nse_detail(latest_rows)
    if nse_sheet:
        sheets.append(nse_sheet)

    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(csv_folder, f"report_{ts}.xlsx")

    xlsx_io.write_xlsx_multi(out_path, sheets)
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
    print(f"[report] OK: {result}")
    return 0
