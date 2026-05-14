# nmapParser

> **비기술 점검자/관리자용 nmap GUI** — 한국어 라벨, Excel 로 옵션 관리, CSV 결과는 분류·식별·비고가 자동 채워져 그대로 보고서 베이스로 쓸 수 있습니다.

🇬🇧 *English version: [README.en.md](./README.en.md)*

![nmapParser GUI](./screenshot_readme.png)

---

## 30초 요약

1. **타깃 입력 → ▶ 스캔 시작.** GUI default 가 사용자 점검 표준 (`phase1`) 명령을 그대로 조립합니다.
2. **결과 CSV 24컬럼.** 호스트/OS/프로토콜·표준포트·식별·**위험도(상/중/하)**·암호화·인증·분류·용도·노출위험·공격표면·**출처(KISA/국정원/CIS/MITRE)**·**NSE추출(TLS_CN/SMB_OS/NTLM_Computer 등 핵심 필드 한 줄)**·점검메모 까지 한 행에 — Excel 로 열어 `위험도=상` 필터 한 번에 우선순위 추림.
3. **옵션은 Excel 로 관리.** `options.xlsx` / `categories.xlsx` 행 추가만 하면 GUI 가 바로 반영.

![CSV 결과 예시](./screenshot_csv_sample.png)

## 빠른 시작

**Option A — Windows 실행 파일 (Python 불필요)**

Releases 페이지에 두 가지 형식이 함께 올라옵니다 (둘 다 x86 — 32/64-bit Windows 모두 실행).

| 파일 | 첫 실행 속도 | 배포 편의 | 추천 환경 |
|---|---|---|---|
| `nmapParser-x86.zip` (**권장**) | **즉시** | zip 풀기 1회 | AV 가 엄격한 환경, 기업 PC, OneDrive 동기 폴더, 네트워크 드라이브 |
| `nmapParser.exe` (단일 GUI 파일) | 5–30초 (첫 실행만) | 파일 1개 | 개인 PC / 빠른 한 번 사용 |
| `nmapParser-cli.exe` (콘솔) | CLI 즉시 출력 | 파일 1개 | `--check-config`/자동화/장애 진단 |

1. nmap 설치: <https://nmap.org/download.html>
2. [Releases](https://github.com/patissierMongs/nmapParser/releases/latest) 에서 위 표의 파일 중 하나 다운로드.
3. 실행:
   - zip → 적당한 폴더에 풀고 `nmapParser.exe` 더블클릭.
   - 단일 .exe → 그대로 더블클릭. 첫 실행 시 PyInstaller 압축 해제 + Defender 스캔 사이에 잠깐 멈춰 보일 수 있음 (정상 — 두 번째 실행부터 즉시 시작).
4. 첫 실행 시 `options.xlsx` / `categories.xlsx` 자동 생성.
   - 설치 위치가 read-only(예: `C:\Program Files\…`) 이면 설정 파일은 `%APPDATA%\nmapParser\` 로 자동 fallback. **"설정 폴더 변경..."** 또는 **xlsx 파일 직접 지정** 으로 직접 위치 지정도 가능.

**Option B — 소스에서**
```
git clone https://github.com/patissierMongs/nmapParser.git
cd nmapParser
python nmapParser.py    # 또는 nmapParser.bat
```

## 핵심 기능

- **한국어 GUI + 옵션마다 hover 툴팁.**
- **체크박스 + 라디오 그룹** (TCP 스캔 타입 / 속도 — 같은 그룹 = 택1).
- **`phase1` 표준 명령 default.** SYN+버전식별+UDP 26포트+NSE 27개 한 번에.
- **NSE 추출.** 19개 NSE 스크립트 (ssl-cert, smb-os-discovery, rdp-ntlm-info, http-server-header 등) 의 핵심 필드 (TLS_CN, SMB_OS, NTLM_Computer, SSH_FP_SHA256 …) 를 CSV `NSE추출` 컬럼에 자동 추출.
- **시간축 보고서.** `📊 시간축 보고서` 버튼 — CSV 폴더의 여러 시점 결과를 5(또는 6)시트 xlsx (현황/히트맵/변경이력/위험도추이/메타/NSE상세) 로 합치고 셀 색칠 (신규=빨강, 유지=하늘, 닫힘=자주, 미관측=회색).
- **다중 `-p` 자동 합치기.** TCP 풀 + UDP 행 둘 다 켜도 단일 `-p T:...,U:...`.
- **실시간 로그** (최근 275줄 화면 / 전체는 `.log` 파일) + `--stats-every 1m` 자동 추가로 buffer 멈춤 방지.
- **창 닫기 시 nmap 자동 종료** (좀비 프로세스 방지).

## CSV 24컬럼

| # | 컬럼 | 의미 |
|---|---|---|
| 1–3 | **IP / 호스트 / OS** | nmap 기본 + DNS PTR + osmatch |
| 4–6 | **프로토콜 / 포트 / 표준포트** | nmap 결과 + categories.xlsx 의 표준 well-known 포트 (비교용) |
| 7 | **포트상태** | `open` / `closed` / `filtered` |
| 8–9 | **추측서비스 / 확인서비스(short)** | nmap-services 룩업 vs XML `<service>@name` |
| 10 | **식별** | `확인` / `추측` / `tcpwrapped` / `미확인` |
| 11–12 | **분류 / 용도** | `웹` / `원격접속` / ... + `관리` / `사용자` / `시스템` / `모니터링` / ... |
| 13 | **위험도** | `상` / `중` / `하` (KISA 한국식) |
| 14–15 | **암호화 / 인증** | `평문` / `TLS` / `암호화` / `선택` + `익명가능` / `사용자` / `키` / `Kerberos` 등 |
| 16–17 | **노출위험 / 공격표면** | 한 줄 사실 (예: "평문 인증으로 자격증명 노출", "EternalBlue (MS17-010), NTLM relay") |
| 18 | **출처** | `KISA U-21, 국정원 정보보안기본지침 제32조, CIS 4.5, MITRE T1040` 등 4종 매핑 |
| 19 | **상세(제품/버전)** | `OpenSSH 9.6p1 Ubuntu...` verbose |
| 20 | **비고** | 자동 요약 한 줄 — detail + NSE 핵심 (CN, OS, hostname, title) |
| 21 | **NSE스크립트명** | 적용된 script id 들 (콤마, 한 포트 한 행) |
| 22 | **스크립트출력** | `[id] output` 블록 줄바꿈 join |
| 23 | **NSE추출** | `TLS_CN=foo; SMB_OS=Windows 10; NTLM_Computer=WIN01` 같은 핵심 필드 한 줄 — 19개 NSE 스크립트 출력에서 자동 추출 |
| 24 | **점검메모** | 빈 칸 — 점검자가 Excel 에서 손으로 채우는 용도 (자동 보존) |

### 위험도·노출위험·공격표면·출처 — 데이터 출처 우선순위

`categories.xlsx` 의 4 컬럼은 **객관적 관찰 사실**입니다 (조치/판단 X). 데이터 매핑 우선순위:

1. **KISA** — "주요정보통신기반시설 취약점 분석·평가 상세 가이드" UNIX/Linux (U-01~U-72), Windows (W-01~W-72), ISMS-P 인증 기준, 행안부 전자정부 진단 기준, 금융보안원 시행세칙.
2. **국정원 (NIS)** — "정보보안기본지침" / "기술적 보호조치 지침" / "암호모듈 정책(KCMVP)". 한국 환경에서 흔한 telnet/ftp/SMB1/SNMP v1·v2/RDP/원격 자격증명 노출 등에 명시.
3. **CIS Critical Security Controls v8** — Control 4 (Secure Configuration), 4.5/4.6/4.8/4.10 등.
4. **MITRE ATT&CK** — T1021.001 (RDP) / T1021.002 (SMB) / T1190 (Exploit Public-Facing App) / T1133 (External Remote Services) 등 Technique ID.

기본 제공 105 서비스 모두 KISA U/W 항목 + CIS Control + MITRE Technique ID 매핑 완료.

> **이 도구는 관찰까지.** 우선순위·노출 평가·권고 같은 판단은 의도적으로 생성하지 않습니다 — 사람의 영역.

### 두 컬럼 비교가 핵심
- 22000번 포트 추측서비스 = `snapenetio` 인데 확인서비스(short) = `ssh` 라면 → 추측이 틀렸음.
- 확인서비스(short) 가 `microsoft-ds?` 처럼 `?` 로 끝나면 → probe 시도했지만 실패. **추측만 가지고 판단 금지** 의 신호.

## Excel 로 옵션 관리

GUI 의 `options.xlsx 열기 (Excel)` → 행 추가/편집 → 저장 → `옵션 다시 불러오기` 클릭.

| 파일 | 컬럼 | 용도 |
|---|---|---|
| `options.xlsx` | 스캔 옵션 / 옵션 / 활성화 / 그룹 / 상세설명 | 체크박스/라디오/툴팁 |
| `categories.xlsx` | 13컬럼 권장: 서비스명 / 표준포트 / 프로토콜 / 분류 / 용도 / 위험도 / 암호화 / 인증 / 노출위험 / 공격표면 / 출처 / 설명 / 점검메모 | CSV 의 표준포트·암호화·인증·분류·용도·위험도·노출위험·공격표면·출처·점검메모 자동 채움 (105 항목 KISA+CIS+MITRE 매핑 동봉). |

### 컬럼 위치 자유 + 사용자 컬럼 추가 가능

`options.xlsx` / `categories.xlsx` 둘 다 **헤더 이름 기반** 으로 동작합니다 — Excel 에서 컬럼을 자유롭게 옮기거나, 본인 작업용 컬럼 (예: `담당자`, `점검일자`, `자산ID`) 을 추가해도 GUI 가 그대로 인식·동작합니다.

- **필수 헤더**: `categories.xlsx` 는 `서비스명`, `options.xlsx` 는 `스캔 옵션`/`옵션`/`활성화`. 누락 시 친절한 한국어 popup 또는 `--check-config` 실패 메시지.
- **흔한 헤더 별칭 허용**: `스캔옵션`, `옵션명`, `사용여부`, `설명`, `service`, `port`, `risk`, `memo` 등은 표준 헤더로 자동 인식합니다.
- **중복 헤더 진단**: `스캔 옵션` + `옵션명`처럼 같은 의미의 헤더가 둘 이상 있으면 조용히 무시하지 않고 오류로 알려줍니다.
- **선택 헤더**: 나머지 모두. 누락된 표준 컬럼은 코드 내장 dict (105 services) 에서 자동 보충.
- **사용자 추가 컬럼**: GUI 동작에는 영향 없음. 마이그레이션 시 그대로 보존.
- **구버전 호환**: 3/4/6/8 컬럼 categories.xlsx 도 자동 인식. 13 컬럼으로 강제 변환은 `python scripts/migrate_categories_to_13col.py` (사용자 편집·추가 컬럼 모두 보존, 백업 자동).

### 설정 파일 사전 검사 (GUI 없이)

현장 배포 전/점검 당일에는 GUI를 켜기 전에 설정 파일만 먼저 검사할 수 있습니다.

```bash
# 현재 폴더의 options.xlsx / categories.xlsx 검사
python nmapParser.py --check-config

# 파일 경로를 직접 지정해서 검사
python nmapParser.py --check-config --options options.xlsx --categories categories.xlsx
```

정상 예시:
```text
[check-config] OK options.xlsx: 37 rows — options.xlsx
[check-config] OK categories.xlsx: 105 services — categories.xlsx
```
오류가 있으면 `[check-config] FAIL ...` 과 함께 non-zero exit code 를 반환하므로 배포 스크립트/체크리스트에 넣기 좋습니다.


## 오프라인 XML→CSV / 기준-현재 Diff (신규)

스캔 없이도 기존 nmap XML 산출물로 바로 CSV 변환/비교가 가능합니다.

### GUI
- `결과 CSV 변환` 영역에서:
  - `XML 파일→CSV`
  - `XML 폴더 일괄→CSV`
  - `XML 취합→CSV`: 선택한 상위 폴더의 XML을 하위 폴더까지 찾아 `collected/<timestamp>`에 XML 증적+CSV로 묶고 `collected/latest` 갱신
  - `CSV 취합`: 선택한 상위 폴더의 CSV를 `collected/<timestamp>`로 모으고 `collected/latest`도 갱신
  - `📊 시간축 보고서`: 기본적으로 `collected/latest`를 읽어 `reports/report_<timestamp>.xlsx` 생성
  - `기준/현재 비교(Diff)`
- Diff는 `Diff 변경행만` 옵션으로 UNCHANGED 행을 제외할 수 있습니다 (자산은 IP 로 자연스럽게 구분).
- 장시간 작업 중에는(Windows) 앱이 자동으로 절전을 억제해 스캔/변환/비교가 중단되지 않도록 시도합니다.

### CLI
```bash
# XML 1개 또는 폴더 -> CSV
python nmapParser.py --xml2csv <input.xml_or_dir> --out <output_dir> --open-only

# 기준/현재 비교 (xml/csv 혼합 가능)
python nmapParser.py --diff --base <base.xml_or_csv> --curr <curr.xml_or_csv> \
                     --out <output_dir> --only-changes --out-format both

# 여러 CSV를 시간축 Excel 보고서로 생성
python nmapParser.py --report --csv-folder <csv_folder> --out <report.xlsx>

# 설정 파일 사전 검사
python nmapParser.py --check-config --options <options.xlsx> --categories <categories.xlsx>

# (선택) categories.xlsx 직접 지정
python nmapParser.py --xml2csv <input.xml_or_dir> --categories <categories.xlsx> --out <output_dir>
```

### 생성 파일
- GUI 기본 workspace: `NMAPPARSER_OUTPUT_DIR`가 있으면 그 폴더, 없으면 설정 폴더(`data_dir`), 그것도 없으면 임시폴더 `nmapParser`.
- 새 스캔 기본 위치: `<workspace>/scans/<timestamp>/` — nmap 원본(`.xml/.nmap/.gnmap`)과 변환 CSV를 같은 스캔 폴더에 둡니다.
- CSV 취합 위치: `<workspace>/collected/<timestamp>/`, 최신 취합 복사본은 `<workspace>/collected/latest/`.
- XML 취합은 하위 폴더까지 `.xml`을 찾아 같은 취합 폴더에 XML 증적과 변환 CSV를 함께 둡니다.
- 통합 보고서 위치: `<workspace>/reports/report_<timestamp>.xlsx`.
- XML→CSV 변환은 CSV만 생성합니다. 개별 CSV별 XLSX를 자동으로 만들지 않습니다.
- `diff_<base>_vs_<curr>_<timestamp>.csv` — 변경 상세. `changed_fields` 는 `state/service/detail/nse_or_script` 로 표시.
- `summary_<base>_vs_<curr>_<timestamp>.csv` — NEW_OPEN/CLOSED/CHANGED/UNCHANGED 집계.
- `snapshot_<curr>_<timestamp>.csv` — 현재 파일 기준 스냅샷.
- `diff_<base>_vs_<curr>_<timestamp>.xlsx` — `--out-format xlsx|both` 일 때 생성되는 색칠 Excel.

CLI 실행 후 콘솔에도 `[diff] SUMMARY: NEW_OPEN=... CLOSED=... CHANGED=...` 요약이 출력됩니다.

### 노출위험/공격표면 컬럼
- CSV 결과에 `노출위험`, `공격표면` 컬럼이 포함됩니다.
- `categories.xlsx`는 13컬럼 권장 schema를 사용하며, 기존 3~8컬럼 파일도 하위호환으로 읽습니다.

### 서비스 커버리지 점검
요청 서비스군이 매핑에 반영됐는지 점검하려면:
```bash
PYTHONPATH=. python scripts/generate_service_checklist.py
```
실행 후 `service_checklist.csv`가 생성됩니다.

### 릴리즈 전 점검(권장)
```bash
python scripts/preflight_checks.py
```
README/CLI 동기화, 정적 컴파일 검사, diff 테스트를 한 번에 실행합니다.

## 기준 명령 (`phase1`)

GUI default 만으로 정확히 이 명령이 조립됩니다 — 타깃 입력 후 ▶ 클릭:

```
nmap -Pn -n -sS -sU -sV --version-all \
     -p T:1-65535,U:7,53,67,68,69,88,123,135,137,138,139,161,162,389,400,500,514,520,623,1900,2049,4500,5060,5353,5355,11211 \
     --min-hostgroup 64 --max-parallelism 100 \
     --script 'http-headers,http-server-header,http-title,ssh-hostkey,
               ssl-cert,ssl-enum-ciphers,tls-alpn,
               ms-sql-info,oracle-tns-version,rdp-ntlm-info,
               snmp-info,ike-version,sip-methods,ntp-info,ntp-monlist,
               nbstat,smb-os-discovery,smb-protocols,rpcinfo,
               dns-nsid,dns-recursion,
               ftp-anon,ftp-syst,
               telnet-encryption,
               vnc-info,vnc-title,
               fingerprint-strings' \
     -T4 --max-retries 2 --reason --open --defeat-rst-ratelimit \
     -oA phase1 <대역>
```

## 변경 이력

<details open>
<summary><b>v0.4.0 — 시간축 보고서 + NSE 추출 (작업 중)</b></summary>

- **CSV 24컬럼** — 23번째 `NSE추출` 추가. ssl-cert/smb-os-discovery/rdp-ntlm-info/http-server-header 등 19개 NSE 출력에서 핵심 필드 (TLS_CN / TLS_SAN / TLS_Issuer / TLS_NotAfter / TLS_SelfSigned / SMB_OS / SMB_Computer / SMB_Domain / SMB_HasV1 / NTLM_Hostname / NTLM_Computer / NTLM_OS_Build / SSH_FP_SHA256 / SSH_KeyTypes / HTTP_Server / HTTP_Title / NetBIOS_Computer / NetBIOS_MAC / SNMP_sysDescr / IKE_Version / NTP_Stratum / MSSQL_Version / Oracle_Version / SIP_Methods / RPC_Programs / Raw_FirstLine) 자동 추출.
- **5(또는 6)시트 xlsx 보고서** — `📊 시간축 보고서` 버튼 / `--report --csv-folder <폴더>` CLI. 시트: 현황 / 히트맵 (셀 색칠) / 변경이력 / 위험도추이 / 메타 / NSE상세.
- **diff 색칠 xlsx** — `--out-format xlsx|csv|both` (default both). NEW_OPEN 빨강 / CLOSED 자주 / CHANGED 노랑 / UNCHANGED 흰색 자동 색칠. CSV 결과는 그대로 유지.
- **categories.xlsx 13컬럼 마이그레이션 prompt** — 시작 시 헤더 검사 → 부족하면 popup. Yes 면 사용자 편집·추가 컬럼 모두 보존하면서 13컬럼 schema 로 변환. 백업 자동 (.bak.<timestamp>).
- **options.xlsx 새 옵션 자동 추가 prompt** — DEFAULT_OPTIONS 와 비교, 누락된 옵션이면 popup. Yes 면 활성=0 으로 추가 (사용자 결정 보존). 사용자 추가 행/컬럼 100% 보존.
- **국정원 (NIS) 출처 매핑** — `SERVICE_EXPOSURE_GUIDE` 의 출처 컬럼에 한국 환경 흔한 항목 (telnet/ftp/SMB1/SNMP/RDP/SSH/HTTPS/MSSQL 등) 에 국정원 정보보안기본지침·기술적보호조치·암호모듈 정책(KCMVP) 인용 추가. 출처 4종 매핑 (KISA + 국정원 + CIS + MITRE).
- **설정 진단 CLI** — `--check-config --options <options.xlsx> --categories <categories.xlsx>` 로 Excel 헤더 alias/중복/필수컬럼을 GUI 없이 검사.
- **Diff/보고서 운영성 강화** — diff CLI 요약 출력, `changed_fields=nse_or_script` 라벨, 보고서 메타에 입력 파일명/인코딩 기록, 히트맵에서 서비스 시그니처 변경을 `변경`으로 표시.
- **다음 정도 보강**: GUI override + GUI targets 자동 합치기 (override 박스에 `-iL`/IP 명시 안 되면 GUI 타겟 append). CSV 취합 dedup (hash + 이전 `_collected_` 폴더 제외). preflight 강화 (xlsx_io / nse_extract / report_generator / 설정검사 추가). `_relocate_config_dir` None-safety.
- **파일 위치 workflow 정리** — 새 스캔은 `scans/<timestamp>`, CSV/XML 취합은 `collected/<timestamp>` 및 `collected/latest`, 통합 보고서는 `reports/report_<timestamp>.xlsx`. XML→CSV는 CSV만 생성하고 개별 XLSX 자동 생성을 중단해 최종 사용자의 파일/Excel 흐름을 단순화.
- 테스트 75개 통과.
</details>

<details>
<summary><b>v0.3.1 — 회사 환경 호환 + 회귀 fix</b></summary>

- **회귀 fix** (`fix(scan): regression — restore bufsize=0 + conditional cwd, raise watchdog thresholds`):
  - `bufsize=0` 으로 복귀 (v0.2 기본값). `bufsize=-1` 은 OS full-buffer 로 nmap stdout 이 갇혀 GUI 가 수십 초 무응답 + watchdog 헛 경보.
  - `cwd` 기본 `None` (parent inherit). UNC 경로(`\\server\share`) 가 cmd 안에 있을 때만 tempdir 폴백. 무조건 tempdir 강제는 일부 환경에서 권한·접근 이슈로 회귀 유발.
  - Watchdog hint 5초→30초, warn 30초→90초, tick 5초→15초 — nmap 의 정상 phase 전환·NSE 로딩 30초+ 무출력 케이스 흡수.
- **BEL/control char strip** — `_LOG_CTRL_CHAR_RE` 로 nmap stdout 의 `\x07` (BEL) / 기타 invalid control char 제거. tk Text 의 system sound 폭주 방지.
- **atomic xlsx write** — tempfile + os.replace 로 쓰기 도중 UNC 끊김 / 디스크 가득참 / Excel 잠금에서 원본 손상 방지.
- **shutil.which** 로 nmap 자동 검색 5단계 (env var → 등록 path → PROGRAMFILES → which → C:\Program Files\Nmap).
- **빨간 배너** — 비관리자 모드에서 `-sS` / `-O` 사용 시 화면 상단 빨간 배너로 명시 (IsUserAnAdmin).
- **📂 CSV 취합 버튼** — recursive `*.csv` 수집, `_collected_<ts>/` 새 폴더, hash dedup.
- **UPX=False** — AV 시그니처 회피.
</details>

<details>
<summary><b>v0.3.0 — KISA-first 데이터 + diff CLI/GUI</b></summary>

- **CSV 19컬럼 → 23컬럼** (식별/분류/용도/위험도/암호화/인증/노출위험/공격표면/출처/상세/비고/NSE/출력/점검메모).
- **위험도 (상/중/하)** 한국식 enum.
- **categories.xlsx 13컬럼** (서비스명/표준포트/프로토콜/분류/용도/위험도/암호화/인증/노출위험/공격표면/출처/설명/점검메모). 헤더 이름 기반 reader — 사용자 컬럼 자유 reorder + 추가 컬럼 보존.
- **`--diff` CLI + `기준/현재 비교` GUI 버튼** — base/curr CSV(또는 XML) → diff/summary/snapshot 3개 CSV. UNCHANGED 필터 옵션.
- **`--xml2csv` CLI** — 일괄 XML → CSV 변환.
- **override 모드** — 직접 nmap 명령 입력. 다른 GUI 옵션 무시 (단 `-oA` 는 우리 prefix 강제).
- **UDP 마스터 토글** — 한 번에 `-sU` / `U:` 옵션 일괄 활성/비활성.
- **NSE 마스터 토글** — `[✓ 스크립트 사용]` / `[전부 해제]`.
</details>

<details>
<summary><b>v0.2 — 안정성</b></summary>

- 좀비 nmap 방지 (창 닫기 시 자식 프로세스 정리).
- 스캔 중지 시 친절 popup (XML ParseError 안 뜸).
- 다중 `-p` 자동 합치기.
- xlsx XML invalid control char sanitize.
- IP octet 검증 (`192.168.1.999` 거부).
- styles.xml OOXML strict 준수 (openpyxl 경고 0).
- CSV 에 식별/비고 컬럼 추가 (12컬럼).
</details>

<details>
<summary><b>v0.1 — 첫 릴리즈</b></summary>

- Windows 단독 실행 `.exe` (PyInstaller, ~10.7 MB).
- 10컬럼 CSV (IP/PORT/포트상태/추측·확인서비스/분류/용도/상세/NSE).
- options.xlsx 5컬럼 + categories.xlsx 4컬럼 Excel 편집.
- 라디오 그룹 + 체크박스 grid + 한국어 툴팁.
</details>

## 회사 보안 환경 / 네트워크 드라이브 / AppLocker

폐쇄적 환경에서 막힐 수 있는 지점과 회피 방법:

- **AppLocker / SRP 가 `.exe` 차단**: zip 빌드 안의 `nmapParser.exe` 도 막히면
  Option B (Python 소스) 로 전환 — `python nmapParser.py` 또는 `nmapParser.bat`.
- **`%APPDATA%` 가 GPO 로 redirect / read-only**: 앱이 자동으로 `%TEMP%\nmapParser`
  로 fallback. 그것도 막히면 **메모리-only 모드**로 동작 (옵션 변경은 세션 한정).
- **수동 위치 강제**: 환경 변수로 GUI 조작 없이 강제 가능.
  - `NMAPPARSER_DATA_DIR=D:\nmapParser` — 설정 파일 폴더
  - `NMAPPARSER_OUTPUT_DIR=D:\scans` — 스캔 결과 폴더
  - `NMAPPARSER_NMAP_EXE=C:\Tools\Nmap\nmap.exe` — nmap 비표준 위치
- **GUI 에서 직접 변경**: 옵션 관리 줄의 `설정 폴더 변경...` 버튼 — 폴더 픽
  실패 시 자동으로 xlsx 파일 직접 지정 흐름으로 fallback.
- **네트워크 드라이브 느림**: 가능하면 zip 을 로컬 SSD 에 풀어 사용 권장.

## 고급 기능

- **NSE 패널 우측 상단**: `[✓ 스크립트 사용]` 마스터 토글, `[전부 해제]` 버튼.
- **기본 옵션 패널 우측 상단**: `[✓ UDP 스캔 사용]` 토글 — `-sU` / `U:` 포함
  옵션을 일괄 활성/비활성 (라디오 포함 모든 위젯 disabled).
- **고급 입력 — `직접 입력 명령 (override)`**: 옆 `override 사용` 체크박스를
  켜면 **다른 모든 옵션 무시**하고 `nmap -sS ...` 풀 명령어를 그대로 실행.
  출력 플래그(`-oA` 등)는 자동 제거 후 우리 CSV 파이프라인용 `-oA` 로 보강.

## CSV 취합 (시간축 누적 점검)

매번 점검할 때마다 CSV 가 출력 폴더에 쌓이면 점점 폴더가 흩어집니다. **`📂 CSV 취합`** 버튼으로 한 폴더에 모음:

1. GUI 의 `결과 CSV 변환` 영역에서 **`📂 CSV 취합`** 클릭
2. CSV 들이 들어 있는 상위 폴더 선택 (recursive)
3. `<선택폴더>/_collected_<yyyyMMdd_HHmmss>/` 자동 생성, 모든 `*.csv` 복사 (원본 보존, 충돌 시 `_2`, `_3` suffix)
4. 완료 popup: 수집 개수, 가장 오래된/최근 파일 timestamp, 실패 목록
5. Windows 에서 자동으로 그 폴더 열기

수집된 폴더를 통째로 보고 / 외부 분석 도구로 보내거나, 같은 자산의 시간축 비교 (Diff 기능) 의 입력으로 사용하세요.

## 회사 환경 호환

기업 PC / 보안 정책 엄격 환경에서 자주 마주치는 이슈와 해결:

| 증상 | 원인 | 해결 |
|---|---|---|
| 첫 실행 시 SmartScreen "알 수 없는 게시자" | 미서명 .exe (개인 빌드) | "추가 정보 → 실행". 또는 `--onedir` zip (`nmapParser-x86.zip`) 권장 — Windows 가 archive 안 파일은 일반적으로 차단 안 함 |
| AV 가 .exe 격리 | UPX 압축 시그니처 / PyInstaller 휴리스틱 | v0.3.1+ 는 UPX 비활성. 그래도 막히면 `--onedir` zip 사용 |
| `Starting Nmap` 안 보이고 멈춰 보임 | Python 버전 차이로 stdout `read1` 없음 | v0.2 `a045f58` 에서 fix. 최신 .exe 사용 |
| AppLocker / GPO 가 사용자 폴더 .exe 차단 | 정책 | IT 에 화이트리스트 요청. 또는 PowerShell 으로 `python nmapParser.py` 실행 |
| 한국어 사용자명 폴더 (`C:\Users\홍길동\`) + `--onefile` | PyInstaller _MEI 임시 풀기 시 한글 path 일부 버전 이슈 | `--onedir` zip 사용 권장 |
| UNC / 네트워크 드라이브 위에서 실행 시 nmap 출력 stall | nmap 의 cwd 가 UNC 면 IO 차단 가능 | v0.3.1+ 는 cwd 기본 `None` (부모 inherit, v0.2 동작), 명령에 UNC (`\\server\share`) 가 들어 있을 때만 자동으로 `tempdir` 폴백. 무조건 tempdir 강제는 일부 환경 권한 이슈로 회귀 유발해서 v0.3.1 에서 조건부로 변경 |
| DLP 가 옵션 xlsx 차단 | 정책 | `NMAPPARSER_DATA_DIR` 환경변수로 허용된 폴더 강제 지정 |

## 한계

- `-sS` / `-O` 는 관리자 권한 필요. 일반 사용자는 라디오에서 `Connect` 선택.
- 구버전 nmap 에 없는 NSE 는 nmap 이 무시 또는 경고만.
- IPv6-only 호스트는 CSV `IP` 컬럼에 IPv6 주소 그대로.
- override 모드 사용 시 IP 검증 / 옵션 충돌 검사는 동작하지 않음 — 사용자 책임.

## 라이선스 / 만든 사람

MIT — [LICENSE](./LICENSE) · [@patissierMongs](https://github.com/patissierMongs)
