#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
categories.xlsx 를 8컬럼 schema 로 마이그레이션.

기존 schema (자동 감지):
  - 3컬럼: 서비스명 / 분류 / 설명
  - 4컬럼: 서비스명 / 분류 / 용도 / 설명
  - 6컬럼: 서비스명 / 분류 / 용도 / 설명 / 노출위험 / 공격표면

→ 새 8컬럼: 서비스명 / 분류 / 용도 / 위험도 / 노출위험 / 공격표면 / 출처 / 설명

원본은 `<파일>.bak.YYYYMMDD-HHMMSS` 로 백업.

사용법:
  python scripts/migrate_categories_to_8col.py [path/to/categories.xlsx]
  (인자 생략 시 nmapParser 실행 폴더의 categories.xlsx 를 찾음)
"""

import os
import sys
import shutil
import time

# nmapParser 루트 경로 sys.path 에 추가
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import xlsx_io  # noqa: E402
import nmapParser  # noqa: E402


def main():
    if len(sys.argv) >= 2:
        path = os.path.abspath(sys.argv[1])
    else:
        path = os.path.join(_ROOT, "categories.xlsx")

    if not os.path.isfile(path):
        print(f"[migrate] 파일 없음: {path}")
        return 1

    # 1) 기존 데이터 read
    catmap, errors = nmapParser.load_categories_xlsx(path)
    if errors:
        print("[migrate] 경고:")
        for e in errors:
            print(f"  - {e}")
    print(f"[migrate] 기존 항목 {len(catmap)}개 로드.")

    # 2) 백업
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{path}.bak.{ts}"
    shutil.copy2(path, backup)
    print(f"[migrate] 백업: {backup}")

    # 3) 8컬럼 schema 로 재작성 — 기존 항목 + DEFAULT_CATEGORIES 의 새 항목 추가
    rows = [["서비스명", "분류", "용도", "위험도", "노출위험", "공격표면", "출처", "설명"]]
    seen = set()

    # 기존 항목 우선 (사용자 편집 보존)
    for name, info in catmap.items():
        rows.append([
            name,
            info.get("category", ""),
            info.get("usage", ""),
            info.get("risk", ""),
            info.get("exposure_risk", ""),
            info.get("attack_surface", ""),
            info.get("source", ""),
            info.get("desc", ""),
        ])
        seen.add(name)

    # DEFAULT_CATEGORIES 에서 새로 추가된 항목 append
    added = 0
    for tup in nmapParser.DEFAULT_CATEGORIES:
        if len(tup) < 4:
            continue
        name, category, usage, desc = tup[0], tup[1], tup[2], tup[3]
        key = (name or "").strip().lower()
        if not key or key in seen:
            continue
        risk, exposure, surface, source = nmapParser._exposure_guide_for(key)
        rows.append([name, category, usage, risk, exposure, surface, source, desc])
        seen.add(key)
        added += 1

    # 4) write
    xlsx_io.write_xlsx(path, rows, col_widths=[20, 14, 12, 8, 38, 38, 36, 38])
    print(f"[migrate] 8컬럼 schema 로 저장: {path}")
    print(f"[migrate] 총 {len(rows)-1}행 (기존 {len(catmap)}개 보존 + 새로 추가 {added}개).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
