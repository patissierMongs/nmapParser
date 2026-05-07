# 개발 명세서: XML2CSV 단독 변환 + 스캔 결과 버전관리(Diff)

작성일: 2026-05-07  
대상 프로젝트: nmapParser

## 1. 목적

본 명세는 다음 2가지 기능을 단계적으로 추가하기 위한 구현 기준을 정의한다.

1) **스캔 없이 XML→CSV 변환** (단일/일괄)  
2) **버전관리형 비교(Diff) 기능**
   - i) 새로 열린 포트
   - ii) 닫힌 포트
   - iii) 내용 변경 포트

핵심 원칙은 Git의 변경 추적 철학(기준점 대비 변경분 관리)을 데이터 스냅샷에 적용하는 것이다.

---

## 2. 범위

### 포함(In Scope)
- GUI에서 XML 파일(또는 폴더) 입력 후 CSV 생성
- CSV↔CSV 비교
- XML↔XML, XML↔CSV 비교(내부 정규화 후 동일 엔진 사용)
- 비교 결과를 CSV(필수) 및 XLSX(권장)로 출력
- 자산 그룹/대역 식별자(`asset_id`) 기반 관리

### 제외(Out of Scope, 1차)
- DB 서버 도입(PostgreSQL 등)
- 실시간 대시보드 웹앱
- 자동 스케줄러/에이전트 배포

---

## 3. 용어 정의

- **Snapshot**: 특정 시점 스캔 결과를 정규화한 데이터 집합
- **Baseline**: 비교 기준 스냅샷
- **Current**: 최신 스냅샷
- **Diff**: Baseline 대비 Current 변경분
- **Natural Key**: `asset_id + ip + proto + port`

---

## 4. 데이터 스키마

## 4.1 정규화 스냅샷 CSV (`snapshot_*.csv`)

필수 컬럼:
- `asset_id` : 관리 대역/그룹 식별자 (예: HQ-ServerZone)
- `snapshot_id` : 시점 식별자 (`YYYYMMDD_HHMMSS`)
- `source_file` : 입력 파일명
- `ip`
- `proto` : tcp/udp
- `port` : 정수
- `state`
- `guessed_service`
- `probed_service_short`
- `identification`
- `category`
- `usage`
- `detail`
- `nse_script_names` : `,` join
- `nse_output_digest` : 정규화 후 SHA-256

선택 컬럼:
- `raw_nse_compact` (길이 제한)
- `parser_version`

## 4.2 Diff CSV (`diff_<base>_vs_<curr>.csv`)

필수 컬럼:
- `change_type` : `NEW_OPEN` | `CLOSED` | `CHANGED` | `UNCHANGED`
- `asset_id`
- `key_ip`
- `key_proto`
- `key_port`
- `base_state`, `curr_state`
- `base_service`, `curr_service`
- `base_detail`, `curr_detail`
- `base_digest`, `curr_digest`
- `changed_fields` : 예 `state,service,detail`
- `baseline_snapshot_id`, `current_snapshot_id`

## 4.3 Summary CSV (`summary_<base>_vs_<curr>.csv`)

- `asset_id`
- `new_open_count`
- `closed_count`
- `changed_count`
- `unchanged_count`
- `total_keys_base`
- `total_keys_curr`

---

## 5. 비교 규칙 (검증된 운영 규칙)

## 5.1 사전 정규화
- 문자열 trim
- 서비스명 소문자화
- `detail` 다중 공백 축소
- NSE 출력 줄바꿈/제어문자 제거 후 digest 계산

## 5.2 키 매칭
- 동일 키(`asset_id, ip, proto, port`)를 같은 포트로 간주

## 5.3 change_type 판정
1. `NEW_OPEN`
   - base에 키 없음 AND curr.state == open
2. `CLOSED`
   - base.state == open AND (curr에 키 없음 OR curr.state != open)
3. `CHANGED`
   - 키 존재 AND 비교 필드 집합 중 하나 이상 상이
4. `UNCHANGED`
   - 키 존재 AND 비교 필드 동일

기본 비교 필드:
- `state`
- `probed_service_short`
- `detail`
- `nse_output_digest`

---

## 6. 아키텍처

## 6.1 공통 정규화 파이프라인
- `parse_input(file_path)`
  - xml이면 기존 XML 파서 경유
  - csv면 컬럼 매핑 파서 경유
- `to_normalized_rows(...)`
- `run_diff(base_rows, curr_rows)`
- `write_diff_outputs(...)`

## 6.2 기존 코드 재사용 포인트
- 기존 `_convert_to_csv(xml_path)` 로직의 서비스 식별/분류 계산 재사용
- 기존 categories/options 파일 체계 유지

---

## 7. UI/UX 명세

## 7.1 탭/섹션 추가
A) `XML2CSV 변환`
- [파일 선택] [폴더 선택]
- [단일 변환] [일괄 변환]
- `open 포트만 포함` 체크

B) `비교(Diff)`
- 기준 파일 선택 (XML/CSV)
- 현재 파일 선택 (XML/CSV)
- `asset_id` 입력
- [비교 실행]

## 7.2 결과 안내
- 생성 파일 경로 표시
- 요약 카운트 팝업
- 실패 파일 목록(있을 때)

---

## 8. 엑셀 친화 출력 전략

CSV는 색 정보를 담지 못하므로, 아래 중 1개 이상 제공한다.

1) `change_type` 컬럼 기반 조건부서식 템플릿 안내(README)
2) XLSX 병행 출력(권장)
   - `NEW_OPEN`: 연한 빨강
   - `CLOSED`: 회색/파랑
   - `CHANGED`: 노랑

XLSX 출력은 기존 `xlsx_io.py`를 확장해 적용한다.

---

## 9. CLI 명세(선택)

향후 자동화를 위해 GUI 외 CLI를 제공한다.

- `python nmapParser.py --xml2csv <input.xml> --out <dir>`
- `python nmapParser.py --diff --base <fileA> --curr <fileB> --asset <id> --out <dir>`

---

## 10. 단계별 구현 계획

### Phase 1 (소규모/빠른 가치)
- XML2CSV 단독 변환(파일/폴더)
- 에러 리포트 CSV

### Phase 2 (핵심)
- CSV↔CSV Diff 엔진
- Diff/Summary CSV 생성

### Phase 3 (확장)
- XML↔XML, XML↔CSV 통합 비교
- `asset_id` 기반 누적 관리

### Phase 4 (완성도)
- XLSX 색상 리포트
- 필터 프리셋/피벗 친화 컬럼 고정

---

## 11. 테스트/검증 기준

## 11.1 기능 테스트
- 동일 파일 비교 시 `UNCHANGED` 100%
- 신규 open 추가 케이스 검출
- open→closed 전환 검출
- service/detail 변경 검출
- XML↔CSV 교차 비교 일치

## 11.2 품질 테스트
- 1만~10만 행 성능 측정
- 잘못된 XML/CSV 입력 내구성
- 한글/특수문자 인코딩 점검

## 11.3 회귀 테스트
- 기존 스캔→CSV 플로우 동작 유지

---

## 12. 리스크 및 대응

- 리스크: NSE raw 비교 노이즈 과다
  - 대응: digest 기반 + 비교 필드 옵션화
- 리스크: CSV 스키마 변경 호환성
  - 대응: 버전 컬럼 + 매핑 테이블
- 리스크: 대용량 성능
  - 대응: 키 인덱싱(dict), 스트리밍 처리 검토

---

## 13. 수용 기준 (Definition of Done)

- 사용자가 스캔 없이 XML을 CSV로 변환 가능
- 사용자가 두 파일(XML/CSV)을 선택해 Diff 결과를 즉시 확인 가능
- 산출물 최소 2종(`diff`, `summary`) 생성
- README에 사용법과 해석 가이드 반영

