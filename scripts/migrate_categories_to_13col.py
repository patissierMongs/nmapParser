#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
categories.xlsx 를 현재 권장 schema 로 마이그레이션 (사용자 추가 컬럼 보존).

현재 권장 순서:
  nmap서비스명 / 표준포트 / 프로토콜 / 분류 / 용도 / 위험도 /
  노출위험 / 공격표면 / 출처 / 설명 / 점검메모

특징:
  - 헤더 이름 기반 — 기존 파일이 어떤 순서/컬럼이든 인식.
  - 사용자가 추가한 비표준 컬럼 (예: '담당자', '점검일자') 도 그대로 보존.
  - 누락된 표준 컬럼은 권장 위치에 추가.
  - 사용자 데이터 (편집한 분류·설명·점검메모 등) 손실 0.
  - 원본은 `<파일>.bak.YYYYMMDD-HHMMSS` 백업.

사용법:
  python scripts/migrate_categories_to_13col.py [path/to/categories.xlsx]
"""

import os
import sys
import shutil
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import xlsx_io  # noqa: E402
import nmapParser  # noqa: E402


# 현재 권장 순서
STD_COLUMNS = list(nmapParser.CATEGORIES_STD_COLUMNS)
DISPLAY_COLUMNS = list(nmapParser.CATEGORIES_DISPLAY_COLUMNS)
LEGACY_DROP_COLUMNS = {"암호화", "인증"}


def migrate_path(path):
    """주어진 categories.xlsx 를 13컬럼 schema 로 마이그레이션.

    Returns:
        dict { 'status': 'ok'|'created'|'no_header'|'empty', 'backup': str|None,
               'total': int, 'added': int, 'user_extra': list[str] }
    """
    if not os.path.isfile(path):
        # 없으면 기본값으로 새로 만듦
        nmapParser.write_default_categories_xlsx(path)
        return {"status": "created", "backup": None, "total": len(nmapParser.DEFAULT_CATEGORIES),
                "added": len(nmapParser.DEFAULT_CATEGORIES), "user_extra": []}

    raw_rows = xlsx_io.read_xlsx(path)
    if not raw_rows:
        nmapParser.write_default_categories_xlsx(path)
        return {"status": "empty", "backup": None, "total": len(nmapParser.DEFAULT_CATEGORIES),
                "added": len(nmapParser.DEFAULT_CATEGORIES), "user_extra": []}

    raw_header = [(c or "").strip() for c in raw_rows[0]]
    raw_data = raw_rows[1:]
    col_idx, _normalized_header, header_errors = nmapParser._build_header_index(
        raw_header, ["서비스명"], "categories.xlsx", allowed=nmapParser.CATEGORIES_STD_COLUMNS
    )

    if header_errors:
        return {"status": "no_header", "backup": None, "total": 0, "added": 0,
                "user_extra": [], "current_header": raw_header}

    # 2) 새 헤더 = 사용자가 편집한 현재 헤더 그대로.
    #    열 이동/추가/삭제를 사용자의 양식으로 간주한다.
    standard_aliases = set(STD_COLUMNS) | {"nmap서비스명"} | LEGACY_DROP_COLUMNS
    user_extra = [h for h in raw_header if h and nmapParser._canonical_header_name(h, set(STD_COLUMNS)) not in standard_aliases]
    new_header = list(raw_header)

    # 3) 백업
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{path}.bak.{ts}"
    shutil.copy2(path, backup)

    # 4) 기존 데이터 → 새 헤더 순서로 재배열. 표준 컬럼 빈 칸은 코드 dict 에서 보충.
    def get_cell(row, col_name):
        i = col_idx.get(col_name)
        if i is None or i >= len(row):
            return ""
        v = row[i]
        return (v or "").strip() if v is not None else ""

    def get_raw_cell(row, index):
        if index >= len(row):
            return ""
        v = row[index]
        return (v or "").strip() if v is not None else ""

    seen_keys = set()
    new_rows = [new_header]
    for row in raw_data:
        if not row or all(not (c or "").strip() for c in row):
            continue
        name = get_cell(row, "서비스명")
        if not name:
            continue
        key = name.lower()

        # 코드 dict 보충값
        guide_risk, guide_exposure, guide_surface, guide_source = nmapParser._exposure_guide_for(key)
        guide_port, guide_proto, _guide_encryption, _guide_auth = nmapParser._protocol_guide_for(key)
        # DEFAULT_CATEGORIES 에서 분류/용도/설명 보충
        guide_cat = guide_usage = guide_desc = ""
        for tup in nmapParser.DEFAULT_CATEGORIES:
            if len(tup) >= 4 and (tup[0] or "").strip().lower() == key:
                guide_cat, guide_usage, guide_desc = tup[1], tup[2], tup[3]
                break

        # 표준 컬럼 값 (사용자 입력 우선, 빈 칸이면 guide 값 보충)
        std_values = {
            "서비스명": name,
            "표준포트": get_cell(row, "표준포트") or guide_port,
            "프로토콜": get_cell(row, "프로토콜") or guide_proto,
            "분류": get_cell(row, "분류") or guide_cat,
            "용도": get_cell(row, "용도") or guide_usage,
            "위험도": get_cell(row, "위험도") or guide_risk,
            "노출위험": get_cell(row, "노출위험") or guide_exposure,
            "공격표면": get_cell(row, "공격표면") or guide_surface,
            "출처": get_cell(row, "출처") or guide_source,
            "설명": get_cell(row, "설명") or guide_desc,
            "점검메모": get_cell(row, "점검메모"),  # 사용자 입력 only — 빈 칸 보존
        }
        port_key = ((std_values.get("표준포트") or "").strip(), (std_values.get("프로토콜") or "").strip().upper())
        dedupe_key = port_key if port_key[0] and port_key[1] else ("service", key)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        out_row = []
        for idx, header_name in enumerate(new_header):
            if not header_name:
                out_row.append("")
                continue
            canonical = nmapParser._canonical_header_name(header_name, set(STD_COLUMNS))
            if canonical in std_values:
                out_row.append(std_values[canonical])
            else:
                out_row.append(get_raw_cell(row, idx))
        new_rows.append(out_row)

    # 5) DEFAULT_CATEGORIES 에서 새로 추가된 항목 append (기존 파일에 없던 service)
    added = 0
    for tup in nmapParser._iter_default_categories_dedup_port():
        name, category, usage, desc = tup[0], tup[1], tup[2], tup[3]
        key = (name or "").strip().lower()
        port, proto, _enc, _auth = nmapParser._protocol_guide_for(key)
        port_key = ((port or "").strip(), (proto or "").strip().upper())
        dedupe_key = port_key if port_key[0] and port_key[1] else ("service", key)
        if not key or dedupe_key in seen_keys:
            continue
        values = nmapParser._default_category_values(name, category, usage, desc)
        out_row = nmapParser._row_for_header(new_header, list(STD_COLUMNS) + ["nmap서비스명"], values)
        new_rows.append(out_row)
        seen_keys.add(dedupe_key)
        added += 1

    # 6) atomic write (xlsx_io 의 내부 atomic 패턴)
    col_widths_std = {
        "서비스명": 20, "nmap서비스명": 20, "표준포트": 9, "프로토콜": 11,
        "분류": 14, "용도": 12, "위험도": 8, "노출위험": 38,
        "공격표면": 38, "출처": 36, "설명": 38, "점검메모": 26,
    }
    col_widths = nmapParser._header_widths(new_header, col_widths_std)
    xlsx_io.write_xlsx(path, new_rows, col_widths=col_widths, numeric_columns=["표준포트"])
    return {
        "status": "ok",
        "backup": backup,
        "total": len(new_rows) - 1,
        "added": added,
        "user_extra": user_extra,
    }


def main():
    if len(sys.argv) >= 2:
        path = os.path.abspath(sys.argv[1])
    else:
        path = os.path.join(_ROOT, "categories.xlsx")

    result = migrate_path(path)
    status = result["status"]
    if status == "no_header":
        print(f"[migrate] 필수 헤더 'nmap서비스명' 또는 '서비스명' 없음. 현재 헤더: {result.get('current_header')}")
        print("[migrate] 사용자 파일을 보존하려면 수동으로 'nmap서비스명' 컬럼을 만든 뒤 다시 실행.")
        return 1
    if status == "created":
        print(f"[migrate] 파일 없음 — 기본값으로 새로 생성: {path}")
        return 0
    if status == "empty":
        print(f"[migrate] 파일이 비어 있음 — 기본값으로 새로 생성: {path}")
        return 0
    if status == "ok":
        if result["backup"]:
            print(f"[migrate] 백업: {result['backup']}")
        print(f"[migrate] 현재 권장 schema 로 저장: {path}")
        print(f"[migrate] 총 {result['total']}행 (새로 추가 {result['added']}개).")
        if result["user_extra"]:
            print(f"[migrate] 사용자 추가 컬럼 보존: {result['user_extra']}")
        return 0
    print(f"[migrate] 예상치 못한 상태: {status}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
