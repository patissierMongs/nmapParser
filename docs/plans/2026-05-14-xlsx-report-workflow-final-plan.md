# XLSX 중심 스캔 결과 추적/보고 Workflow 최종 구현 계획

> **For Hermes:** 구현 전 이 계획서를 기준으로 작업한다. 범위는 파일 기반 workflow 정리와 XLSX 리포트 개선이며, DB/웹/서버/스케줄러는 추가하지 않는다.

**Goal:** `포트스캔 → -oA 원본 저장 → CSV 변환 → XLSX 변환 → 기본 결과 디렉터리 기반 통합 리포트 생성` 흐름을 유지하면서, 최종 사용자가 Excel 필터/정렬/메모/추적 기능으로 내부망 포트스캔 결과를 관리할 수 있게 한다.

**Architecture:** nmap 원본 증적은 `-oA` 산출물(XML/NMAP/GNMAP)과 log로 보존하고, XML에서 CSV/XLSX를 생성한다. 통합 리포트는 기본 결과 디렉터리 내 CSV/XLSX/XML/LOG/NMAP 파일을 읽어 생성하며, 사용자는 에러나 기본 디렉터리 미존재 시에만 폴더를 직접 지정한다. XLSX 시트는 필터 활용을 위해 복합 값을 최대한 분해한다.

**Tech Stack:** Python 표준 라이브러리, tkinter GUI, 기존 `xlsx_io.py`, 기존 `report_generator.py`, unittest.

---

## 0. 확정 제품 방향

### 유지할 핵심 흐름

1. GUI에서 포트스캔 실행.
2. nmap은 `-oA <prefix>`로 원본 결과 저장.
   - `<prefix>.xml`
   - `<prefix>.nmap`
   - `<prefix>.gnmap`
   - 별도 `<prefix>.log`
3. XML을 CSV로 변환.
4. 같은 정규화 데이터를 XLSX로 변환.
5. 기본 결과 디렉터리에 산출물을 누적.
6. 통합 리포트 버튼은 기본 결과 디렉터리를 자동 사용.
7. 실패/미존재/CSV 없음 등 예외 상황에서만 사용자가 폴더를 직접 선택.
8. 리포트 생성 성공 시 생성된 XLSX 파일을 자동으로 연다.
9. 파일 열기에 실패하면 해당 파일이 있는 폴더를 연다.
10. 폴더 열기도 실패하면 경로를 메시지로 보여준다.

### 하지 않을 것

- DB 도입 금지.
- 웹 대시보드 금지.
- 백그라운드 에이전트/스케줄러 금지.
- Excel 매크로 금지.
- openpyxl 같은 외부 의존성 추가 금지.
- 복잡한 피벗/차트 자동 생성 금지.
- nmap 세부 NSE 스크립트명을 최종 사용자 UI 전면에 노출하지 않기.

---

## 1. 최종 XLSX 산출물 설계

### 1.1 개별 스캔 XLSX

XML 하나를 변환하면 CSV와 함께 동일 prefix의 XLSX를 생성한다.

예:

```text
scan_20260514_110032/
  phase1_20260514_110032.xml
  phase1_20260514_110032.nmap
  phase1_20260514_110032.gnmap
  phase1_20260514_110032.log
  phase1_20260514_110032.csv
  phase1_20260514_110032.xlsx
```

개별 XLSX 시트:

1. `포트현황`
   - 현재 CSV 24컬럼 기반.
   - 단, XLSX에서는 필터 편의성을 위해 일부 복합값을 분해한 컬럼을 추가한다.
2. `스캔증적`
   - scan_id, 시작/종료시각, 대상, 실행자, nmap 경로, 명령요약, 원본 파일명, 해시.
3. `서비스별확인`
   - 사용자 표시명과 내부 NSE 묶음 기록.

### 1.2 통합 리포트 XLSX

기본 결과 디렉터리의 여러 시점 파일을 읽어 생성한다.

권장 시트 순서:

1. `00_보고요약`
2. `01_스캔증적`
3. `02_시간축히트맵`
4. `03_변경추적대장`
5. `04_조치이력`
6. `05_현재포트현황`
7. `06_증적파일목록`
8. `07_서비스별확인설정`

### 1.3 데이터 분해 원칙

Excel 필터/정렬을 쉽게 하기 위해 복합값을 한 셀에 몰아넣지 않는다.

#### 기존에 피해야 할 형태

```text
키 = 10.10.20.15:443/tcp
NSE추출 = TLS_CN=portal.local; HTTP_Title=사내 포털; TLS_NotAfter=2026-12-31
증적 = XML: phase1.xml / LOG: phase1.log / hash: abcd...
```

#### 목표 형태

```text
IP = 10.10.20.15
포트 = 443
프로토콜 = tcp
서비스 = https
TLS_CN = portal.local
HTTP_Title = 사내 포털
TLS_NotAfter = 2026-12-31
XML파일 = phase1.xml
LOG파일 = phase1.log
XML_SHA256 = abcd...
```

### 1.4 시간축 히트맵 컬럼 설계

현재 히트맵의 `IP:port/proto` 같은 복합 키는 분리한다.

`02_시간축히트맵` 권장 컬럼:

```text
자산키
IP
호스트
OS
프로토콜
포트
확인서비스
분류
용도
위험도
최초관측시각
최근관측시각
현재상태
연속관측횟수
관측횟수
변경횟수
마지막변경유형
담당자
처리상태
처리기한
점검메모
2026-04-23 09:55
2026-04-30 10:15
2026-05-07 10:30
2026-05-14 11:00
```

시간축 셀 값:

```text
NEW_OPEN
KEEP
CHANGED
CLOSED
UNOBSERVED
```

색상:

- NEW_OPEN: 연한 빨강
- KEEP: 연한 하늘
- CHANGED: 연한 노랑
- CLOSED: 연한 자주
- UNOBSERVED: 회색
- 위험도 상: 위험도 셀 진한 빨강

### 1.5 변경추적대장 컬럼 설계

`03_변경추적대장`은 관리 업무 중심 시트다. 히트맵이 관측 흐름이라면, 변경추적대장은 담당/상태/기한/근거를 관리한다.

권장 컬럼:

```text
관리ID
변경유형
심각도
최초관측시각
최근관측시각
미해결일수
비교기준시각
current_scan_id
baseline_scan_id
IP
호스트
프로토콜
포트
확인서비스
포트상태
위험도
changed_state
changed_service
changed_detail
changed_nse
원본XML
원본LOG
XML_SHA256
담당자
처리상태
처리기한
승인/변경티켓
확인근거
다음확인일
종결시각
점검/조치메모
```

`changed_fields`는 필터 편의를 위해 boolean 컬럼으로 분해한다.

예:

```text
changed_fields = state,service,nse_or_script
```

대신:

```text
changed_state = 1
changed_service = 1
changed_detail = 0
changed_nse = 1
```

---

## 2. 기본 디렉터리 동작 설계

### 2.1 기본 결과 디렉터리

앱은 기존 `self.output_folder`를 기본 결과 디렉터리로 사용한다.

초기값은 기존 로직 유지:

1. `NMAPPARSER_OUTPUT_DIR` 환경변수 있으면 해당 경로 하위 timestamp 폴더.
2. 설정 data_dir이 있으면 `data_dir/<timestamp>`.
3. data_dir이 없으면 temp 하위 `nmapParser/<timestamp>`.

단, 통합 리포트는 “현재 스캔 1회 폴더”보다 누적 결과 상위 폴더가 필요하다. 따라서 다음을 추가한다.

### 2.2 리포트 기본 입력 디렉터리

새 helper를 둔다.

```python
def _default_report_input_dir(self):
    """통합 리포트 입력 기본 폴더.

    우선순위:
    1. NMAPPARSER_REPORT_DIR 환경변수
    2. self.data_dir
    3. self.output_folder 현재값
    4. os.getcwd()
    """
```

기본 동작:

- `📊 시간축 보고서` 클릭 시 폴더 선택창을 먼저 띄우지 않는다.
- `_default_report_input_dir()`를 사용해 바로 리포트 생성을 시도한다.
- 해당 폴더가 없거나 CSV/XLSX/XML이 없거나 리포트 생성 실패 시에만 “직접 폴더 선택” 안내를 띄운다.

### 2.3 수동 선택은 예외 상황에서만

사용자 경험:

1. 사용자가 `📊 시간축 보고서` 클릭.
2. 앱이 기본 디렉터리에서 리포트 생성 시도.
3. 성공:
   - 보고서 XLSX 생성.
   - 생성된 XLSX 자동 열기.
4. 실패:
   - 메시지: “기본 결과 디렉터리에서 리포트 생성 실패. 직접 폴더를 선택하시겠습니까?”
   - 사용자가 Yes 선택 시 폴더 선택창 표시.
   - 선택한 폴더로 리포트 생성 재시도.

---

## 3. 자동 열기 동작 설계

### 3.1 공통 helper 추가

`nmapParser.py`에 공통 helper를 추가한다.

```python
def _open_file_or_folder(path):
    """파일을 먼저 열고, 실패하면 부모 폴더를 열고, 그것도 실패하면 False 반환."""
```

Windows 우선 구현:

```python
try:
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore
        return True
except OSError:
    pass

folder = path if os.path.isdir(path) else os.path.dirname(path)
try:
    if sys.platform == "win32":
        os.startfile(folder)  # type: ignore
        return True
    if sys.platform == "darwin":
        subprocess.Popen(["open", folder])
        return True
    subprocess.Popen(["xdg-open", folder])
    return True
except (OSError, FileNotFoundError):
    return False
```

### 3.2 적용 대상

자동 열기 적용:

- 스캔 완료 후 생성된 개별 XLSX.
- XML 파일 단일 변환 후 생성된 XLSX.
- XML 폴더 일괄 변환 후 출력 폴더.
- Diff 생성 후 diff XLSX.
- 통합 리포트 생성 후 report XLSX.

우선순위:

1. 최종 XLSX 파일 열기.
2. 실패 시 XLSX가 있는 폴더 열기.
3. 실패 시 메시지에 경로 표시.

---

## 4. 구현 작업 목록

### Task 1: 공통 파일/폴더 열기 helper 추가

**Objective:** 생성된 XLSX를 자동으로 열고 실패 시 폴더를 열 수 있게 한다.

**Files:**
- Modify: `nmapParser.py`
- Test: `tests/test_open_helpers.py`

**Steps:**

1. `nmapParser.py` module-level에 `_open_file_or_folder(path)` 추가.
2. platform별 분기 구현.
3. `path`가 비어 있거나 존재하지 않아도 부모 폴더 열기를 시도하게 한다.
4. unittest에서 `os.startfile`이 없는 Linux 환경을 고려해 `subprocess.Popen` mock으로 검증한다.

**Test cases:**

- 파일 경로 입력 시 파일 열기를 먼저 시도.
- 파일 열기 실패 시 부모 폴더 열기 시도.
- 폴더 경로 입력 시 폴더 열기 시도.
- 모두 실패 시 False 반환.

**Verification:**

```bash
python3 -m unittest tests.test_open_helpers -v
python3 -m unittest discover -v
```

---

### Task 2: 기본 리포트 입력 디렉터리 helper 추가

**Objective:** 리포트 생성 시 매번 폴더를 묻지 않고 기본 디렉터리를 사용한다.

**Files:**
- Modify: `nmapParser.py`
- Test: `tests/test_report_default_dir.py`

**Steps:**

1. `NmapParserApp`에 `_default_report_input_dir(self)` 추가.
2. 우선순위 구현:
   - `NMAPPARSER_REPORT_DIR`
   - `self.data_dir`
   - `self.output_folder.get()`
   - `os.getcwd()`
3. 존재하지 않는 경로는 다음 후보로 넘어가게 한다.
4. 테스트는 `object.__new__(NmapParserApp)`로 인스턴스 생성 후 필드만 주입한다.

**Verification:**

```bash
python3 -m unittest tests.test_report_default_dir -v
python3 -m unittest discover -v
```

---

### Task 3: GUI 리포트 생성 flow 변경

**Objective:** `📊 시간축 보고서` 버튼 클릭 시 기본 디렉터리로 바로 생성하고 실패 시에만 폴더 선택창을 띄운다.

**Files:**
- Modify: `nmapParser.py:4261-4307`
- Test: 가능하면 helper 단위 테스트. GUI dialog는 수동 검증.

**Current behavior:**

- 항상 `filedialog.askdirectory()` 호출.
- 항상 `filedialog.asksaveasfilename()` 호출.
- 생성 후 폴더만 자동 open.

**Target behavior:**

- 기본 디렉터리로 `report_<timestamp>.xlsx` 생성.
- 저장 위치를 묻지 않음.
- 성공 시 생성된 XLSX 파일 자동 열기.
- 실패 시에만 직접 폴더 선택.
- 직접 선택 후에도 저장 위치는 묻지 않고 선택 폴더 안에 자동 생성.

**Implementation sketch:**

```python
def _generate_report_dialog(self):
    try:
        import report_generator
    except Exception as e:
        messagebox.showerror(...)
        return

    folder = self._default_report_input_dir()
    result = self._try_generate_report_from_folder(report_generator, folder, interactive_fallback=True)
    if result:
        return
```

새 helper:

```python
def _try_generate_report_from_folder(self, report_generator, folder):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(folder, f"report_{ts}.xlsx")
    result = report_generator.generate_report(folder, out_path)
    return result
```

실패 처리:

```python
except Exception as e:
    ask = messagebox.askyesno(
        "기본 폴더 리포트 실패",
        f"기본 결과 폴더에서 리포트를 만들지 못했습니다.\n\n폴더: {folder}\n원인: {e}\n\n직접 폴더를 선택하시겠습니까?"
    )
```

**Manual verification:**

1. 기본 폴더에 CSV가 있을 때 버튼 클릭 → 폴더 선택 없이 report 생성.
2. 생성된 report XLSX 자동 열림.
3. 기본 폴더에 CSV가 없을 때 버튼 클릭 → 직접 선택 여부 질문.
4. 직접 폴더 선택 후 report 생성.

---

### Task 4: XML→CSV 변환 결과로 XLSX도 생성

**Objective:** 개별 스캔/오프라인 변환 결과가 CSV뿐 아니라 XLSX로도 남게 한다.

**Files:**
- Modify: `nmapParser.py:1614-1807`, `nmapParser.py:4378-4513`
- Test: `tests/test_xml2xlsx_output.py`

**Implementation approach:**

중복 방지를 위해 CSV row 생성 로직을 분리한다.

새 helper 후보:

```python
CSV_HEADERS = [...]

def build_rows_from_nmap_xml(xml_path, *, open_only, categories, services_table):
    return rows

def write_scan_csv(csv_path, rows):
    ...

def write_scan_xlsx(xlsx_path, rows, scan_meta=None):
    ...
```

최소 변경으로 갈 경우:

- 기존 `convert_xml_to_csv_standalone` 안에서 header/rows를 만든 뒤 CSV 쓰기 후 `xlsx_io.write_xlsx_multi` 호출.
- 함수명은 당장 유지하되 return을 확장하지 않는다.
- GUI `_convert_to_csv`는 CSV path를 반환하므로, XLSX path도 함께 반환하도록 새 함수로 전환한다.

권장 return:

```python
@dataclass
class ConversionResult:
    csv_path: str
    xlsx_path: str | None
    row_count: int
```

단, Python 3.8 호환이 필요하면 `typing.Optional` 사용.

**XLSX 개별 시트:**

- `포트현황`
- `스캔증적`
- `서비스별확인`

**Verification:**

```bash
python3 -m unittest tests.test_xml2xlsx_output -v
python3 -m unittest discover -v
```

---

### Task 5: report_generator 입력 수집 확장

**Objective:** 통합 리포트 생성 시 CSV뿐 아니라 XLSX/XML/LOG/NMAP 증적도 읽어 메타/증적 시트에 반영한다.

**Files:**
- Modify: `report_generator.py`
- Test: `tests/test_report_generator.py`

**Current behavior:**

- `collect_csv_files(csv_folder)`가 현재 폴더의 `*.csv`만 읽음.
- diff/snapshot/summary CSV 제외.
- 리포트는 CSV 기반.

**Target behavior:**

- 기존 CSV 기반 리포트는 유지.
- 새 `collect_report_inputs(folder)` 추가.
- 하위 폴더까지 볼지는 과도해질 수 있으므로 1차는 현재 폴더만 유지하거나, 기존 `CSV 취합` 기능과 충돌하지 않게 옵션 없이 현재 폴더만 유지한다.
- 증적 파일 목록은 같은 폴더 내 `.xml`, `.nmap`, `.gnmap`, `.log`, `.csv`, `.xlsx`를 수집한다.
- 기존 `report_*.xlsx`, `diff_*.xlsx`는 입력 증적에서 제외하거나 종류를 `generated_report`로 분류한다.

**New helper:**

```python
def collect_evidence_files(folder):
    """보고서 증적파일목록 시트용 파일 수집."""
```

파일별 기록:

```text
파일명
종류
생성시각
수정시각
크기
SHA256
보관위치
scan_id 추정값
비고
```

**SHA256:**

- 보고 증적에는 중요하므로 계산한다.
- 큰 파일도 있을 수 있으므로 chunk 단위 계산.

**Verification:**

- 증적 파일 목록에 XML/LOG/NMAP/CSV/XLSX가 포함되는지.
- report_*.xlsx는 입력 보고서로 중복 포함되지 않는지.
- SHA256이 안정적으로 생성되는지.

---

### Task 6: 히트맵 key 분해

**Objective:** `IP:port/proto` 같은 복합 셀을 분해해 Excel 필터를 쉽게 한다.

**Files:**
- Modify: `report_generator.py:_build_sheet_heatmap`
- Test: `tests/test_report_generator.py`

**Current likely behavior:**

- key를 한 셀로 표현.
- 시간축 상태 셀은 색상 중심.

**Target columns:**

```text
자산키
IP
호스트
OS
프로토콜
포트
확인서비스
분류
용도
위험도
최초관측시각
최근관측시각
현재상태
연속관측횟수
관측횟수
변경횟수
마지막변경유형
담당자
처리상태
처리기한
점검메모
<timestamp columns...>
```

**Rules:**

- `자산키`는 내부 추적용으로 유지 가능하나 필터용 주 컬럼은 IP/프로토콜/포트 분해 컬럼이다.
- `포트`는 숫자 문자열만 유지.
- `프로토콜`은 `tcp`/`udp` 별도 컬럼.
- `확인서비스`는 latest row 기준.
- `위험도`는 latest row 기준.
- `최초관측시각`은 해당 key가 최초로 open 관측된 스냅샷 label.
- `최근관측시각`은 해당 key가 가장 최근 open/changed/keep 관측된 스냅샷 label.
- `관측횟수`는 open/keep/changed/new 카운트.
- `변경횟수`는 CHANGED 카운트.

**Verification:**

- 테스트 CSV 2~3개로 히트맵 생성.
- 헤더에 IP/프로토콜/포트가 분리되어 있는지 확인.
- 상태 셀 색상이 기존대로 유지되는지 확인.

---

### Task 7: 변경추적대장 시트 추가/강화

**Objective:** 리포트가 단순 변경 목록이 아니라 담당자/상태/기한/근거를 관리할 수 있는 대장이 되게 한다.

**Files:**
- Modify: `report_generator.py`
- Test: `tests/test_report_generator.py`

**Implementation:**

기존 `_build_sheet_change_history`를 다음 중 하나로 변경한다.

Option A: 함수명 유지, 출력 컬럼 확장.
Option B: `_build_sheet_tracking_register`를 새로 만들고 기존 변경이력은 제거 또는 보조로 유지.

YAGNI 관점에서는 Option A가 낫다. 단 시트명은 `변경추적대장`으로 변경한다.

**Columns:**

```text
관리ID
변경유형
심각도
최초관측시각
최근관측시각
미해결일수
비교기준시각
current_scan_id
baseline_scan_id
IP
호스트
프로토콜
포트
확인서비스
포트상태
위험도
changed_state
changed_service
changed_detail
changed_nse
원본XML
원본LOG
XML_SHA256
담당자
처리상태
처리기한
승인/변경티켓
확인근거
다음확인일
종결시각
점검/조치메모
```

자동 채움:

- 관리ID: `TRK-<latest_label>-<sequence>` 형태.
- 담당자/처리상태/처리기한 등은 빈 칸 또는 기존 XLSX에서 병합하는 후속 단계로 둔다.
- 1차 구현에서는 빈 칸으로 제공해 사용자가 Excel에서 채운다.

후속 가능하지만 이번 범위에서는 보류:

- 이전 리포트 XLSX에서 담당자/처리상태 자동 병합.

**Verification:**

- NEW_OPEN/CHANGED/CLOSED가 각각 행으로 생성되는지.
- changed_fields가 boolean 컬럼으로 분해되는지.
- IP/프로토콜/포트가 분리되어 필터 가능한지.

---

### Task 8: 스캔증적/증적파일목록 시트 추가

**Objective:** 보고서에 “언제/어떻게 생성됐는지”를 증명할 수 있는 데이터를 포함한다.

**Files:**
- Modify: `report_generator.py`
- Test: `tests/test_report_generator.py`

**스캔증적 시트:**

CSV 파일명/메타에서 가능한 값부터 채운다.

```text
scan_id
관측시각
CSV파일
XML파일
NMAP파일
GNMAP파일
LOG파일
CSV_SHA256
XML_SHA256
LOG_SHA256
입력폴더
비고
```

1차 구현에서 nmap 실행 명령까지 정확히 복원하기 어렵다면 LOG 파일 존재 여부와 파일 해시만 우선 기록한다.

**증적파일목록 시트:**

폴더 내 관련 파일 전부 기록.

```text
파일명
종류
생성시각
수정시각
크기
SHA256
보관위치
scan_id 추정값
비고
```

**Verification:**

- 샘플 폴더에 `.xml/.nmap/.gnmap/.log/.csv/.xlsx`를 넣고 리포트 생성.
- 두 시트에 파일들이 분리 기록되는지 확인.

---

### Task 9: 서비스별 스크립트 UI 명칭 정리

**Objective:** 최종 사용자가 NSE 세부 스크립트가 아니라 서비스별 확인 묶음으로 이해하게 한다.

**Files:**
- Modify: `nmapParser.py`
- Modify: `options.xlsx` 생성 기본값 관련 함수
- Test: `tests/test_config_loading.py` 영향 확인

**Changes:**

- GUI 패널 제목:
  - 기존: `NSE 식별 스크립트`
  - 변경: `서비스별 추가 확인`
- 옵션 라벨 예:
  - `HTTP 식별` → `웹/HTTP 확인`
  - `TLS 인증서 식별` → `TLS/인증서 확인`
  - `SMB 식별` → `Windows/SMB 확인`
  - `UDP 응용 식별` → `UDP 주요 서비스 확인`
  - `raw 응답 캡처` → `미식별 응답 확인`
- 상세설명에는 내부 NSE 이름 유지.

**Verification:**

- 새 options.xlsx 생성 시 라벨이 서비스별로 보이는지.
- 기존 options.xlsx 사용자는 그대로 동작하는지.

---

### Task 10: 문서/README 최소 갱신

**Objective:** 사용자에게 새 workflow를 짧고 명확하게 설명한다.

**Files:**
- Modify: `README.md`
- Modify: `README.en.md` 가능하면 최소 반영

**Content:**

- “권장 workflow” 섹션 추가.

```text
1. 스캔 실행: nmap -oA 원본 저장
2. 자동 변환: CSV + XLSX 생성
3. 누적 보관: 기본 결과 디렉터리에 결과 유지
4. 리포트 생성: 버튼 클릭만으로 기본 디렉터리에서 통합 XLSX 생성
5. 실패 시에만 폴더 직접 선택
```

- XLSX 시트 설명:
  - 보고요약
  - 스캔증적
  - 시간축히트맵
  - 변경추적대장
  - 조치이력
  - 현재포트현황
  - 증적파일목록
  - 서비스별확인설정

**주의:** README를 과하게 늘리지 않는다. 상세 스키마는 별도 문서 또는 코드 주석으로 충분하다.

---

## 5. 테스트 계획

### 5.1 필수 자동 테스트

```bash
python3 -m compileall -q .
python3 -m unittest discover -v
python3 nmapParser.py --check-config --options options.xlsx --categories categories.xlsx
```

### 5.2 추가할 테스트 파일

```text
tests/test_open_helpers.py
tests/test_report_default_dir.py
tests/test_xml2xlsx_output.py
```

### 5.3 기존 테스트 보강

`tests/test_report_generator.py`에 추가:

- 히트맵 헤더가 IP/프로토콜/포트 분해 컬럼을 포함하는지.
- 변경추적대장 시트가 생성되는지.
- 증적파일목록 시트가 생성되는지.
- 파일 SHA256이 계산되는지.
- report_*.xlsx 자체가 입력 증적으로 중복 처리되지 않는지.

### 5.4 수동 검증

Windows GUI에서 확인:

1. 앱 실행.
2. 기본 출력 폴더 그대로 스캔 실행.
3. `.xml/.nmap/.gnmap/.log/.csv/.xlsx` 생성 확인.
4. 개별 XLSX 자동 열림 확인.
5. `📊 시간축 보고서` 클릭.
6. 폴더 선택 없이 기본 디렉터리에서 리포트 생성 확인.
7. 리포트 XLSX 자동 열림 확인.
8. 기본 디렉터리에 CSV가 없는 상태에서 버튼 클릭.
9. 실패 메시지 후 직접 폴더 선택 flow 확인.

---

## 6. 구현 순서 추천

1. Task 1: 자동 열기 helper.
2. Task 2: 기본 리포트 입력 디렉터리 helper.
3. Task 3: GUI 리포트 생성 flow 변경.
4. Task 4: XML→CSV 변환 시 XLSX도 생성.
5. Task 5: report_generator 입력/증적 수집 확장.
6. Task 6: 히트맵 key 분해.
7. Task 7: 변경추적대장 강화.
8. Task 8: 스캔증적/증적파일목록 추가.
9. Task 9: 서비스별 스크립트 UI 명칭 정리.
10. Task 10: README 최소 갱신.
11. 전체 테스트.
12. Windows GUI 수동 검증.

---

## 7. 완료 기준

구현 완료는 아래를 모두 만족해야 한다.

- 스캔 완료 시 원본 `-oA` 결과와 log가 남는다.
- XML 변환 후 CSV와 XLSX가 모두 생성된다.
- 개별 XLSX가 자동으로 열린다.
- 열기 실패 시 폴더가 열린다.
- 폴더 열기 실패 시 경로가 메시지로 표시된다.
- 리포트 생성 버튼은 기본 디렉터리를 먼저 사용한다.
- 기본 디렉터리 실패 시에만 직접 폴더 선택을 요구한다.
- 통합 리포트 XLSX에 `시간축히트맵`이 포함된다.
- 히트맵에서 IP/프로토콜/포트가 분리 컬럼으로 제공된다.
- 변경추적대장에 담당자/처리상태/처리기한/확인근거/다음확인일 컬럼이 있다.
- 스캔증적/증적파일목록에 파일명, 시각, 해시가 남는다.
- `python3 -m unittest discover -v` 통과.
- `python3 -m compileall -q .` 통과.
- `--check-config` 통과.

---

## 8. 핵심 판단

현재 구조는 충분히 좋다. 바꿀 것은 pipeline이 아니라 사용자의 반복 작업이다.

- 폴더를 매번 묻지 않는다.
- 결과 파일을 자동으로 열어준다.
- 최종 사용자는 XLSX에서 필터/정렬/메모/상태관리한다.
- 보고서에는 시간과 증적을 명확히 남긴다.
- 히트맵은 유지하되, 복합값을 분해해 Excel 필터에 최적화한다.

이 방향은 overengineering이 아니라 기존 파일 기반 구조를 최종 사용자 업무 흐름에 맞게 정리하는 것이다.
