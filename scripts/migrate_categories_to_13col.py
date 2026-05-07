#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
categories.xlsx 를 13컬럼 권장 schema 로 마이그레이션 (사용자 추가 컬럼 보존).

13컬럼 권장 순서:
  서비스명 / 표준포트 / 프로토콜 / 분류 / 용도 / 위험도 /
  암호화 / 인증 / 노출위험 / 공격표면 / 출처 / 설명 / 점검메모

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


# 13컬럼 권장 순서
STD_COLUMNS = [
    "서비스명", "표준포트", "프로토콜", "분류", "용도", "위험도",
    "암호화", "인증", "노출위험", "공격표면", "출처", "설명", "점검메모",
]


def main():
    if len(sys.argv) >= 2:
        path = os.path.abspath(sys.argv[1])
    else:
        path = os.path.join(_ROOT, "categories.xlsx")

    if not os.path.isfile(path):
        # 없으면 기본값으로 새로 만듦
        print(f"[migrate] 파일 없음 — 기본값으로 새로 생성: {path}")
        nmapParser.write_default_categories_xlsx(path)
        return 0

    # 1) 원본 raw 읽기 (xlsx_io 직접) — 사용자 컬럼 보존을 위해.
    try:
        raw_rows = xlsx_io.read_xlsx(path)
    except Exception as e:
        print(f"[migrate] 읽기 실패: {e}")
        return 1
    if not raw_rows:
        print("[migrate] 파일이 비어 있음 — 기본값으로 새로 생성")
        nmapParser.write_default_categories_xlsx(path)
        return 0

    raw_header = [(c or "").strip() for c in raw_rows[0]]
    raw_data = raw_rows[1:]
    raw_col_idx = {h: i for i, h in enumerate(raw_header) if h}

    if "서비스명" not in raw_col_idx:
        print(f"[migrate] 필수 헤더 '서비스명' 없음. 현재 헤더: {raw_header}")
        print("[migrate] 사용자 파일을 보존하려면 수동으로 '서비스명' 컬럼을 만든 뒤 다시 실행.")
        return 1

    # 2) 새 헤더 = 권장 13컬럼 + 사용자가 추가한 비표준 컬럼 (순서 보존).
    user_extra = [h for h in raw_header if h and h not in STD_COLUMNS]
    new_header = list(STD_COLUMNS) + user_extra

    # 3) 백업
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{path}.bak.{ts}"
    shutil.copy2(path, backup)
    print(f"[migrate] 백업: {backup}")

    # 4) 기존 데이터 → 새 헤더 순서로 재배열. 표준 컬럼 빈 칸은 코드 dict 에서 보충.
    def get_cell(row, col_name):
        i = raw_col_idx.get(col_name)
        if i is None or i >= len(row):
            return ""
        v = row[i]
        return (v or "").strip() if v is not None else ""

    seen = set()
    new_rows = [new_header]
    for row in raw_data:
        if not row or all(not (c or "").strip() for c in row):
            continue
        name = get_cell(row, "서비스명")
        if not name:
            continue
        key = name.lower()
        seen.add(key)

        # 코드 dict 보충값
        guide_risk, guide_exposure, guide_surface, guide_source = nmapParser._exposure_guide_for(key)
        guide_port, guide_proto, guide_encryption, guide_auth = nmapParser._protocol_guide_for(key)
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
            "암호화": get_cell(row, "암호화") or guide_encryption,
            "인증": get_cell(row, "인증") or guide_auth,
            "노출위험": get_cell(row, "노출위험") or guide_exposure,
            "공격표면": get_cell(row, "공격표면") or guide_surface,
            "출처": get_cell(row, "출처") or guide_source,
            "설명": get_cell(row, "설명") or guide_desc,
            "점검메모": get_cell(row, "점검메모"),  # 사용자 입력 only — 빈 칸 보존
        }
        # 사용자 추가 컬럼은 원본 값 그대로
        out_row = [std_values[c] for c in STD_COLUMNS] + [get_cell(row, c) for c in user_extra]
        new_rows.append(out_row)

    # 5) DEFAULT_CATEGORIES 에서 새로 추가된 항목 append (기존 파일에 없던 service)
    added = 0
    for tup in nmapParser.DEFAULT_CATEGORIES:
        if len(tup) < 4:
            continue
        name, category, usage, desc = tup[0], tup[1], tup[2], tup[3]
        key = (name or "").strip().lower()
        if not key or key in seen:
            continue
        std_row = nmapParser._build_default_category_row(name, category, usage, desc)
        # 사용자 추가 컬럼은 빈 값
        out_row = std_row + [""] * len(user_extra)
        new_rows.append(out_row)
        seen.add(key)
        added += 1

    # 6) atomic write (xlsx_io 의 내부 atomic 패턴)
    col_widths_std = [20, 9, 11, 14, 12, 8, 22, 22, 38, 38, 36, 38, 26]
    col_widths = col_widths_std + [20] * len(user_extra)
    xlsx_io.write_xlsx(path, new_rows, col_widths=col_widths)
    print(f"[migrate] 13컬럼 schema 로 저장: {path}")
    print(f"[migrate] 총 {len(new_rows)-1}행 (기존 {len(seen)-added}개 + 새로 추가 {added}개).")
    if user_extra:
        print(f"[migrate] 사용자 추가 컬럼 보존: {user_extra}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
