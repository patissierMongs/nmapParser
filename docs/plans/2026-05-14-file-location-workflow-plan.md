# nmapParser 파일 위치/산출물 관리 정리 계획

> **For Hermes:** 구현 시에는 과한 구조 변경 없이 이 계획을 task-by-task로 적용한다. DB/웹/스케줄러/매크로/외부 패키지 추가 금지.

**Goal:** 비숙련 최종 사용자가 “어디에 무엇이 생성됐는지” 헷갈리지 않도록 nmap 원본 증적, CSV 취합본, 최종 XLSX 리포트를 일관된 위치에 생성한다.

**Architecture:** 현재 파일 기반 workflow(`nmap -oA → XML → CSV → XLSX`)는 유지한다. 단, 산출물의 역할별 기본 위치를 `scans/`, `collected/`, `reports/`로 나누고, 통합 리포트는 자동으로 `collected/latest`를 읽어 `reports/`에 생성한다.

**Tech Stack:** Python stdlib, Tkinter GUI, 기존 `xlsx_io.py`, 기존 `report_generator.py`, 기존 `nmapParser.py`.

---

## 1. 현재 문제 요약

현재 구현은 기능적으로는 동작하지만 산출 위치가 역할별로 정리되어 있지 않다.

### 1.1 스캔 실행 결과

현재 기본 출력 폴더는 대략 다음 중 하나다.

```text
<data_dir>/<timestamp>/
<NMAPPARSER_OUTPUT_DIR>/<timestamp>/
%TEMP%/nmapParser/<timestamp>/
```

그 안에 다음 파일이 같이 생성된다.

```text
<target>_<timestamp>.nmap
<target>_<timestamp>.xml
<target>_<timestamp>.gnmap
<target>_<timestamp>.log
<target>_<timestamp>.csv
<target>_<timestamp>.xlsx
```

문제:
- 원본 증적, 정규화 CSV, 개별 XLSX가 한 폴더에 섞인다.
- 개별 XLSX가 “최종 보고서”인지 “보조 산출물”인지 애매하다.
- 여러 번 스캔하면 timestamp 폴더가 늘어나며, 사용자가 어느 폴더를 기준으로 리포트를 만들어야 하는지 헷갈린다.

### 1.2 XML 수동 변환

현재는 사용자가 출력 폴더를 직접 선택하고, 그 폴더에 CSV와 개별 XLSX가 생성된다.

문제:
- 사용자가 임의 위치를 선택하면 산출물이 기본 결과 구조 밖으로 흩어진다.
- 나중에 통합 리포트 대상 CSV를 다시 찾아야 한다.

### 1.3 CSV 취합

현재는 사용자가 선택한 상위 폴더 내부에 다음 폴더를 만든다.

```text
<사용자가_선택한_폴더>/_collected_<timestamp>/
```

문제:
- 취합 위치가 workspace 기준이 아니라 사용자가 선택한 폴더 기준이다.
- 여러 위치에서 취합하면 `_collected_*` 폴더가 여기저기 흩어진다.
- “최신 취합본”을 가리키는 안정된 위치가 없다.

### 1.4 통합 리포트 생성

현재는 CSV 입력 폴더 안에 다음 파일을 만든다.

```text
<csv_folder>/report_<timestamp>.xlsx
```

문제:
- 리포트가 CSV 입력 폴더 안에 섞인다.
- 리포트만 모아둔 위치가 없다.
- 리포트를 재생성하면 같은 CSV 폴더 안에 `report_*.xlsx`가 누적된다.
- `07_증적파일목록`이 해당 폴더의 `*.xlsx`까지 읽으면서 이전 report 파일이 증적처럼 들어갈 수 있다.

---

## 2. 목표 구조

사용자는 다음 3개 폴더만 이해하면 된다.

```text
workspace/
  scans/       # 원본 nmap 증적 + CSV
  collected/   # 통합 리포트 입력용 CSV 묶음
  reports/     # 최종 Excel 보고서
```

권장 세부 구조:

```text
workspace/
  scans/
    20260514_123000_192.168.0.10/
      scan.nmap
      scan.xml
      scan.gnmap
      scan.log
      scan.csv

  collected/
    latest/
      20260501_100000_192.168.0.10.csv
      20260507_100000_192.168.0.10.csv
      20260514_100000_192.168.0.10.csv

    20260514_130000/
      20260501_100000_192.168.0.10.csv
      20260507_100000_192.168.0.10.csv
      20260514_100000_192.168.0.10.csv

  reports/
    report_20260514_130000.xlsx
    report_20260521_130000.xlsx
```

설정 파일(`options.xlsx`, `categories.xlsx`)은 현재 app directory / `%APPDATA%\nmapParser` fallback 구조가 있으므로 이번 변경의 1차 범위에서는 옮기지 않는다.

---

## 3. 사용자 workflow

### 3.1 스캔 실행

사용자가 GUI에서 스캔을 실행한다.

기본 생성 위치:

```text
workspace/scans/<scan_id>/
```

생성 파일:

```text
scan.nmap
scan.xml
scan.gnmap
scan.log
scan.csv
```

원칙:
- 스캔 폴더는 원본 증적 보관소다.
- CSV는 XML을 정규화한 리포트 입력 후보로 같이 둔다.
- 개별 XLSX는 기본 생성하지 않는다.

개별 XLSX 자동 생성은 현재 관점에서 기본값으로는 과하다. 필요하면 나중에 “개별 XLSX 만들기” 버튼이나 옵션으로 추가한다.

### 3.2 CSV 취합

사용자가 “CSV 취합”을 누르면 상위 폴더를 선택한다.

동작:
1. 선택한 폴더 하위의 CSV를 recursive 탐색한다.
2. 기존 `collected/`, `reports/`, `_collected_*` 내부 파일은 제외한다.
3. 내용 hash 중복을 제거한다.
4. 다음 위치에 CSV를 복사한다.

```text
workspace/collected/<timestamp>/
```

5. 동시에 다음 폴더를 최신 취합본으로 갱신한다.

```text
workspace/collected/latest/
```

`latest` 갱신 방식:
- 기존 `latest` 폴더를 비우고 새 취합 CSV를 복사한다.
- 삭제 실패 가능성을 고려해 파일 단위로 제거한다.
- 실패 파일은 popup에 “실패 목록”으로 표시한다.

사용자에게 보여줄 완료 메시지:

```text
CSV 취합 완료

취합 폴더: <workspace>/collected/<timestamp>
최신 취합: <workspace>/collected/latest
수집된 CSV: N개
중복 제외: M개

이제 통합 리포트 버튼을 누르면 latest 기준으로 보고서를 생성합니다.
```

### 3.3 통합 리포트 생성

사용자가 “통합 리포트”를 누른다.

입력 우선순위:
1. `workspace/collected/latest/`에 CSV가 있으면 자동 사용
2. 없으면 현재 출력 폴더에 CSV가 있는지 확인
3. 그래도 없으면 사용자에게 CSV 폴더 선택 요청

출력 위치:

```text
workspace/reports/report_<timestamp>.xlsx
```

원칙:
- report 파일은 CSV 입력 폴더에 만들지 않는다.
- 모든 최종 보고서는 `reports/`에 모은다.
- 생성 후 XLSX 파일을 자동으로 연다.
- 파일 열기 실패 시 `reports/` 폴더를 연다.
- 폴더 열기도 실패하면 경로를 popup에 보여준다.

### 3.4 XML 수동 변환

1차 변경에서는 기존 동작을 크게 바꾸지 않는다.

단, 기본 출력 폴더 initialdir만 다음으로 유도한다.

```text
workspace/scans/
```

장기적으로는 XML 수동 변환도 다음 구조로 통일할 수 있다.

```text
workspace/scans/manual_<timestamp>_<xml_stem>/scan.csv
```

하지만 지금은 사용자가 직접 XML을 변환하는 예외 workflow이므로, 먼저 스캔/취합/리포트 기본 workflow를 안정화한다.

---

## 4. 구현 원칙

1. 새 DB, 새 설정 시스템, 새 외부 패키지를 만들지 않는다.
2. 사용자에게 폴더 선택을 반복해서 요구하지 않는다.
3. 기본 위치가 없거나 입력 CSV가 없을 때만 폴더 선택 dialog를 띄운다.
4. 최종 사용자가 기억해야 할 위치는 3개로 제한한다.
   - `scans/`
   - `collected/latest/`
   - `reports/`
5. 리포트 생성은 취합본을 자동으로 읽는 것이 기본이다.
6. 개별 XLSX 자동 생성은 기본 OFF로 본다.
7. 기존 CLI 호환은 깨지지 않게 한다.
   - `--report --csv-folder <folder> --out <report.xlsx>`는 그대로 동작해야 한다.
   - GUI 기본 동작만 더 일관된 위치를 사용한다.

---

## 5. 구체 구현 계획

### Task 1: workspace 경로 helper 추가

**Objective:** 산출 위치 계산을 한 곳에서 처리한다.

**Files:**
- Modify: `nmapParser.py`
- Test: `tests/test_file_location_workflow.py`

**추가할 helper 후보:**

```python
def get_workspace_root(data_dir=None):
    env_out = os.environ.get("NMAPPARSER_OUTPUT_DIR", "").strip()
    if env_out:
        return os.path.abspath(env_out)
    if data_dir:
        return os.path.abspath(data_dir)
    return os.path.join(tempfile.gettempdir(), "nmapParser")


def get_scans_dir(workspace_root):
    return os.path.join(workspace_root, "scans")


def get_collected_dir(workspace_root):
    return os.path.join(workspace_root, "collected")


def get_collected_latest_dir(workspace_root):
    return os.path.join(get_collected_dir(workspace_root), "latest")


def get_reports_dir(workspace_root):
    return os.path.join(workspace_root, "reports")
```

**주의:** helper 이름은 기존 코드 스타일에 맞춰 `_workspace_root`처럼 private로 바꿔도 된다. 중요한 것은 경로 계산을 GUI method 안에 흩뿌리지 않는 것이다.

**테스트:**
- 환경변수 `NMAPPARSER_OUTPUT_DIR`가 있으면 workspace root로 사용한다.
- data_dir가 있으면 data_dir를 workspace root로 사용한다.
- 둘 다 없으면 temp fallback을 사용한다.

---

### Task 2: 기본 출력 폴더를 `scans/<timestamp>`로 변경

**Objective:** 새 스캔 산출물이 항상 증적 폴더 아래에 생성되도록 한다.

**Files:**
- Modify: `nmapParser.py:2226-2238`
- Test: `tests/test_file_location_workflow.py`

**현재:**

```python
output_default = os.path.join(self.data_dir, ts)
```

**변경 방향:**

```python
workspace = get_workspace_root(self.data_dir)
output_default = os.path.join(get_scans_dir(workspace), ts)
```

**검증:**
- GUI 초기 `self.output_folder` 기본값이 `<workspace>/scans/<timestamp>` 형태인지 확인한다.
- 사용자가 “출력 폴더 변경”으로 직접 바꾸는 기능은 유지한다.

---

### Task 3: scan_id 폴더명 개선

**Objective:** timestamp만 있는 폴더보다 사용자가 식별하기 쉬운 스캔 폴더명을 만든다.

**Files:**
- Modify: `nmapParser.py:_build_output_prefix`
- Test: `tests/test_file_location_workflow.py`

**현재:**
- `output_folder`가 이미 timestamp 폴더이고, 파일 prefix가 `<target>_<timestamp>`이다.

**권장:**
- 기본 output folder가 `workspace/scans/<timestamp>`이면 일단 유지 가능하다.
- 더 나은 구조는 `_build_output_prefix`에서 첫 target을 포함한 폴더를 만드는 것이다.

단, 변화 폭을 줄이려면 1차에서는 다음만 적용한다.

```text
workspace/scans/<timestamp>/
  <target>_<timestamp>.xml
  <target>_<timestamp>.csv
```

2차에서 다음으로 정리한다.

```text
workspace/scans/<timestamp>_<target>/
  scan.xml
  scan.csv
```

**결정:** 1차 구현에서는 변화 폭을 줄이기 위해 기존 파일명 prefix는 유지한다. 폴더 위치만 `scans/` 아래로 옮긴다.

---

### Task 4: 개별 XLSX 자동 생성을 기본 중단

**Objective:** CSV 옆에 XLSX가 계속 생겨 최종 보고서와 혼동되는 문제를 줄인다.

**Files:**
- Modify: `nmapParser.py:_scan_done`
- Modify: `nmapParser.py:_convert_xml_file_dialog`
- Modify: `nmapParser.py:_convert_xml_folder_dialog`
- Modify: `nmapParser.py:run_cli_xml2csv`
- Test: 기존 XLSX 생성 테스트 조정 또는 별도 함수 테스트 유지

**변경 방향:**
- 스캔 완료 후 자동 생성 파일은 기본적으로 `.csv`까지만 둔다.
- `report_generator.generate_individual_xlsx` 함수는 삭제하지 않는다.
- CLI에서 기존 동작을 갑자기 깨지 않으려면 옵션 추가를 고려한다.

추천 최소 변경:
- GUI 스캔 완료: 개별 XLSX 생성 제거
- GUI XML 변환: 개별 XLSX 생성 제거
- CLI `xml2csv`: 일단 CSV만 생성하도록 변경하거나, 호환성을 위해 현재 유지

**주의:** 사용자에게 중요한 최종 산출물은 `reports/report_*.xlsx`이다.

---

### Task 5: CSV 취합 위치를 `workspace/collected/<timestamp>`로 고정

**Objective:** `_collected_*` 폴더가 사용자가 고른 폴더마다 생기지 않게 한다.

**Files:**
- Modify: `nmapParser.py:_collect_csv_dialog`
- Modify: `nmapParser.py:collect_csv_candidates`
- Test: `tests/test_file_location_workflow.py`

**현재:**

```python
dst_dir = os.path.join(src, f"_collected_{ts}")
```

**변경:**

```python
workspace = get_workspace_root(self.data_dir)
dst_dir = os.path.join(get_collected_dir(workspace), ts)
latest_dir = get_collected_latest_dir(workspace)
```

**추가 helper 후보:**

```python
def refresh_latest_collected(src_dir, latest_dir):
    os.makedirs(latest_dir, exist_ok=True)
    for name in os.listdir(latest_dir):
        path = os.path.join(latest_dir, name)
        if os.path.isfile(path):
            os.remove(path)
    for name in os.listdir(src_dir):
        if name.lower().endswith(".csv"):
            shutil.copy2(os.path.join(src_dir, name), os.path.join(latest_dir, name))
```

**검증:**
- 취합 결과가 `workspace/collected/<timestamp>`에 생성된다.
- `workspace/collected/latest`가 같은 CSV 목록으로 갱신된다.
- 중복 CSV는 기존처럼 hash 기반으로 제외된다.

---

### Task 6: 취합 후보에서 workspace 산출 폴더 제외

**Objective:** reports/collected 내부 파일이 다시 취합되는 순환을 막는다.

**Files:**
- Modify: `nmapParser.py:collect_csv_candidates`
- Test: `tests/test_file_location_workflow.py`

**현재 제외:**
- destination 하위
- `_collected_*` 하위

**추가 제외:**
- `workspace/collected/` 하위
- `workspace/reports/` 하위
- 가능하면 `workspace/config/` 하위

함수 signature 변경 후보:

```python
def collect_csv_candidates(src_dir, dst_dir, exclude_dirs=None):
```

**테스트:**
- `src/scans/a.csv`는 포함
- `src/collected/latest/a.csv`는 제외
- `src/reports/report_input.csv`는 제외
- `_collected_20260101/a.csv`는 제외

---

### Task 7: 통합 리포트 기본 입력을 `collected/latest`로 변경

**Objective:** 사용자가 폴더를 다시 고르지 않아도 최신 취합본으로 리포트를 만들 수 있게 한다.

**Files:**
- Modify: `nmapParser.py:_generate_report_dialog`
- Test: `tests/test_file_location_workflow.py`

**입력 선택 순서:**

```python
workspace = get_workspace_root(self.data_dir)
latest = get_collected_latest_dir(workspace)
folder = latest if report_generator.collect_csv_files(latest) else self.output_folder.get()
if no csv:
    askdirectory(...)
```

**popup 문구:**

```text
Excel 통합 리포트가 생성되었습니다.

입력 CSV 폴더: <workspace>/collected/latest
입력 CSV: N개
출력: <workspace>/reports/report_<timestamp>.xlsx
```

---

### Task 8: 통합 리포트 출력 위치를 `reports/`로 변경

**Objective:** 최종 보고서를 한 위치에 모은다.

**Files:**
- Modify: `nmapParser.py:_generate_report_dialog`
- Test: `tests/test_file_location_workflow.py`

**현재:**

```python
out_path = os.path.join(folder, f"report_{ts}.xlsx")
```

**변경:**

```python
reports_dir = get_reports_dir(workspace)
os.makedirs(reports_dir, exist_ok=True)
out_path = os.path.join(reports_dir, f"report_{ts}.xlsx")
```

**주의:** `report_generator.generate_report(csv_folder, out_path)`는 이미 out_path를 받을 수 있으므로 큰 변경이 필요 없다.

---

### Task 9: `07_증적파일목록`에서 report 파일 제외

**Objective:** 최종 report 파일이 원본 증적처럼 목록에 들어가지 않게 한다.

**Files:**
- Modify: `report_generator.py:_build_sheet_file_list_final`
- Test: `tests/test_report_generator.py`

**변경 방향:**
- CSV 입력 폴더 내 `report_*.xlsx`는 제외한다.
- 가능하면 개별 XLSX도 종류를 명확히 한다.

최소 변경:

```python
if ext == ".xlsx" and os.path.basename(p).lower().startswith("report_"):
    continue
```

더 좋은 방향:
- 입력 증적 목록은 `.xml`, `.nmap`, `.gnmap`, `.log`, `.csv`만 포함한다.
- XLSX는 최종 산출물이므로 증적 목록에서 제외한다.

추천:
- `07_증적파일목록`에서는 `*.xlsx` 패턴을 제거한다.

---

### Task 10: README workflow 문구 갱신

**Objective:** 사용자가 세 폴더 의미를 바로 이해하게 한다.

**Files:**
- Modify: `README.md`

**추가할 짧은 설명:**

```markdown
## 결과 폴더 구조

nmapParser는 결과물을 역할별로 나눠 저장합니다.

- `scans/` — nmap 원본 증적(`.xml`, `.nmap`, `.gnmap`, `.log`)과 정규화 CSV
- `collected/latest/` — 통합 리포트가 읽는 최신 CSV 묶음
- `reports/` — 최종 Excel 통합 보고서

일반 사용자는 스캔 후 `CSV 취합` → `통합 리포트` 순서로 누르면 됩니다.
```

README를 길게 늘리지 않는다. 핵심 경로와 버튼 순서만 쓴다.

---

## 6. 테스트 계획

### 6.1 경로 helper 테스트

파일:

```text
tests/test_file_location_workflow.py
```

검증:
- workspace root 선택 우선순위
- scans/collected/latest/reports 경로 생성
- 환경변수 우선순위

### 6.2 CSV 취합 테스트

검증:
- recursive CSV 탐색
- `_collected_*` 제외
- `collected/latest` 제외
- `reports` 제외
- hash 중복 제거 유지
- latest 갱신 결과 확인

### 6.3 report 출력 위치 테스트

검증:
- `generate_report` 자체는 out_path 지정 시 지정 위치에 쓴다.
- GUI wrapper는 reports_dir에 out_path를 만든다.
- 입력 폴더는 collected/latest를 우선한다.

### 6.4 증적 목록 테스트

검증:
- `.xml`, `.nmap`, `.gnmap`, `.log`, `.csv`는 포함
- `report_*.xlsx`는 제외
- 가능하면 모든 `.xlsx` 제외

### 6.5 전체 회귀 테스트

실행:

```bash
python3 -m compileall -q nmapParser.py report_generator.py tests
python3 -m unittest -v
```

기대:

```text
OK
```

---

## 7. 완료 기준

이 변경은 다음 조건을 만족하면 완료로 본다.

1. 새 스캔 기본 위치가 `workspace/scans/<timestamp>` 아래다.
2. CSV 취합 결과가 `workspace/collected/<timestamp>`와 `workspace/collected/latest`에 생성된다.
3. 통합 리포트는 기본적으로 `workspace/collected/latest`를 읽는다.
4. 통합 리포트 출력은 항상 `workspace/reports/report_<timestamp>.xlsx`다.
5. 리포트가 CSV 입력 폴더에 섞이지 않는다.
6. `07_증적파일목록`에 최종 report 파일이 증적으로 들어가지 않는다.
7. 개별 XLSX 자동 생성은 기본 workflow에서 제거되거나 명확히 옵션화된다.
8. 전체 테스트가 통과한다.
9. README에 `scans / collected/latest / reports` 개념이 짧게 설명되어 있다.

---

## 8. 구현하지 않을 것

이번 변경에서 다음은 하지 않는다.

- DB 도입
- 웹 대시보드 도입
- 백그라운드 스케줄러 도입
- Excel 매크로 도입
- 파일 감시 daemon 도입
- 사용자별 프로젝트 관리 시스템 도입
- 리포트 버전 관리 DB 도입
- 복잡한 설정 UI 추가
- 자동 피벗/차트 추가

이번 변경은 “기능 확장”이 아니라 “파일 위치 규칙 정리”다.

---

## 9. 최종 사용자에게 설명할 문장

구현 후 GUI/README에서 사용할 수 있는 짧은 설명:

```text
결과물은 역할별로 자동 정리됩니다.

scans: 원본 스캔 증적
collected/latest: 통합 리포트 입력 CSV 묶음
reports: 최종 Excel 보고서

일반적으로 스캔 후 CSV 취합을 누르고, 통합 리포트를 누르면 됩니다.
```
