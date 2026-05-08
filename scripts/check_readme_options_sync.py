#!/usr/bin/env python3
"""README와 DEFAULT_OPTIONS의 옵션 개수 동기화 점검 스크립트."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY_FILE = ROOT / "nmapParser.py"
# 한국어 README.md 가 메인. 영어는 README.en.md.
README_KO = ROOT / "README.md"
README_EN = ROOT / "README.en.md"


def extract_default_options_count(src: str) -> int:
    m = re.search(r"DEFAULT_OPTIONS\s*=\s*\[(.*?)\n\]\n", src, re.S)
    if not m:
        raise RuntimeError("DEFAULT_OPTIONS 블록을 찾을 수 없습니다.")
    block = m.group(1)
    # 각 옵션 row는 ("라벨", "옵션", ... ) 형태의 튜플 시작으로 카운트
    return len(re.findall(r"^\s*\(\"", block, re.M))


def extract_first_option_count_mention(text: str) -> int | None:
    m = re.search(r"(\d+)\s*options", text, re.I)
    if m:
        return int(m.group(1))
    m = re.search(r"(\d+)\s*개", text)
    if m:
        return int(m.group(1))
    return None


def main() -> int:
    src = PY_FILE.read_text(encoding="utf-8")
    default_count = extract_default_options_count(src)

    failures = []
    for p in (README_EN, README_KO):
        text = p.read_text(encoding="utf-8")
        mentioned = extract_first_option_count_mention(text)
        if mentioned is None:
            print(f"[WARN] {p.name}: 옵션 개수 언급을 찾지 못했습니다.")
            continue
        if mentioned != default_count:
            failures.append((p.name, mentioned, default_count))

    if failures:
        for name, mentioned, actual in failures:
            print(f"[FAIL] {name}: 문서 언급={mentioned}, DEFAULT_OPTIONS={actual}")
        return 1

    print(f"[OK] DEFAULT_OPTIONS={default_count}, README 옵션 개수 언급과 일치")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
