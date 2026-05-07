# nmapParser

> **비기술 점검자/관리자용 nmap GUI** — 한국어 라벨, Excel 로 옵션 관리, CSV 결과는 분류·식별·비고가 자동 채워져 그대로 보고서 베이스로 쓸 수 있습니다.

🇬🇧 *English version: [README.en.md](./README.en.md)*

![nmapParser GUI](./screenshot_readme.png)

---

## 30초 요약

1. **타깃 입력 → ▶ 스캔 시작.** GUI default 가 사용자 점검 표준 (`phase1`) 명령을 그대로 조립합니다.
2. **결과 CSV 19컬럼.** 호스트/OS/프로토콜·식별·**위험도(상/중/하)**·분류·용도·노출위험·공격표면·**출처(KISA/CIS/MITRE)** 까지 한 행에 — Excel 로 열어 `위험도=상` 필터 한 번에 우선순위 추림.
3. **옵션은 Excel 로 관리.** `options.xlsx` / `categories.xlsx` 행 추가만 하면 GUI 가 바로 반영.

![CSV 결과 예시](./screenshot_csv_sample.png)

## 빠른 시작

**Option A — Windows 실행 파일 (Python 불필요)**

Releases 페이지에 두 가지 형식이 함께 올라옵니다 (둘 다 x86 — 32/64-bit Windows 모두 실행).

| 파일 | 첫 실행 속도 | 배포 편의 | 추천 환경 |
|---|---|---|---|
| `nmapParser-x86.zip` (**권장**) | **즉시** | zip 풀기 1회 | AV 가 엄격한 환경, 기업 PC, OneDrive 동기 폴더, 네트워크 드라이브 |
| `nmapParser.exe` (단일 파일) | 5–30초 (첫 실행만) | 파일 1개 | 개인 PC / 빠른 한 번 사용 |

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
- **`phase1` 표준 명령 default.** SYN+버전식별+UDP 26포트+NSE 19개 한 번에.
- **다중 `-p` 자동 합치기.** TCP 풀 + UDP 행 둘 다 켜도 단일 `-p T:...,U:...`.
- **실시간 로그** (최근 275줄 화면 / 전체는 `.log` 파일) + `--stats-every 1m` 자동 추가로 buffer 멈춤 방지.
- **창 닫기 시 nmap 자동 종료** (좀비 프로세스 방지).

## CSV 19컬럼

| 컬럼 | 의미 |
|---|---|
| **IP** | 호스트 IP |
| **호스트** | DNS PTR / 입력 호스트명. `-n` 또는 결과 없으면 빈 값 |
| **OS** | nmap `-O` osmatch best (`Linux 5.X (95%)` 형태) |
| **PORT** / **프로토콜** / **포트상태** | nmap 기본 |
| **추측서비스** | 포트번호 룩업 (`nmap-services`) |
| **확인서비스(short)** | XML `<service>@name`. probe 실패 시 `?` |
| **식별** | `확인` / `추측` / `tcpwrapped` / `미확인` 4값 |
| **분류** | `웹` / `원격접속` / `DBMS` / `RPC` / ... (categories.xlsx) |
| **용도** | `관리` / `사용자` / `시스템` / `모니터링` / ... |
| **위험도** | `상` / `중` / `하` (KISA 한국식 enum) |
| **노출위험** | 외부 노출 시 발생 가능한 위험 한 줄 (예: "평문 인증으로 자격증명 노출") |
| **공격표면** | 알려진 공격 기법/CVE 한 줄 (예: "EternalBlue (MS17-010), NTLM relay") |
| **출처** | 근거가 되는 표준 — `KISA U-21, CIS 4.5, MITRE T1040` 등 |
| **상세(제품/버전)** | `OpenSSH 9.6p1 Ubuntu...` 등 verbose |
| **비고** | 자동 요약 한 줄 — detail + NSE 핵심 (CN, OS, hostname, title) |
| **NSE스크립트명** | 적용된 script id 들 (콤마 구분, 한 포트 한 행) |
| **스크립트출력** | `[id] output` 블록을 줄바꿈으로 누적. Excel "셀 자동 줄바꿈" 켜면 가독 |

### 위험도·노출위험·공격표면·출처 — 데이터 출처 우선순위

`categories.xlsx` 의 4 컬럼은 **객관적 관찰 사실**입니다 (조치/판단 X). 데이터 매핑 우선순위:

1. **KISA** — "주요정보통신기반시설 취약점 분석·평가 상세 가이드" UNIX/Linux (U-01~U-72), Windows (W-01~W-72), ISMS-P 인증 기준, 행안부 전자정부 진단 기준, 금융보안원 시행세칙.
2. **CIS Critical Security Controls v8** — Control 4 (Secure Configuration), 4.5/4.6/4.8/4.10 등.
3. **MITRE ATT&CK** — T1021.001 (RDP) / T1021.002 (SMB) / T1190 (Exploit Public-Facing App) / T1133 (External Remote Services) 등 Technique ID.

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
| `categories.xlsx` | 서비스명 / 분류 / 용도 / 위험도 / 노출위험 / 공격표면 / 출처 / 설명 (8컬럼) | CSV 의 분류·용도·위험도·노출위험·공격표면·출처 자동 채움 (105 항목 KISA+CIS+MITRE 매핑 동봉). 구버전 3/4/6 컬럼 파일도 호환 — 자동 감지 + 빠진 필드 코드 dict 에서 보충. 8컬럼으로 강제 변환은 `python scripts/migrate_categories_to_8col.py` |

## 오프라인 XML→CSV / 기준-현재 Diff (신규)

스캔 없이도 기존 nmap XML 산출물로 바로 CSV 변환/비교가 가능합니다.

### GUI
- `결과 CSV 변환` 영역에서:
  - `XML 파일→CSV`
  - `XML 폴더 일괄→CSV`
  - `기준/현재 비교(Diff)`
- Diff는 `asset_id`와 `Diff 변경행만` 옵션을 사용해 결과를 필터링할 수 있습니다.
- 장시간 작업 중에는(Windows) 앱이 자동으로 절전을 억제해 스캔/변환/비교가 중단되지 않도록 시도합니다.

### CLI
```bash
# XML 1개 또는 폴더 -> CSV
python nmapParser.py --xml2csv <input.xml_or_dir> --out <output_dir> --open-only

# 기준/현재 비교 (xml/csv 혼합 가능)
python nmapParser.py --diff --base <base.xml_or_csv> --curr <curr.xml_or_csv> \
                     --asset <asset_id> --out <output_dir> --only-changes

# (선택) categories.xlsx 직접 지정
python nmapParser.py --xml2csv <input.xml_or_dir> --categories <categories.xlsx> --out <output_dir>
```

### 생성 파일
- `diff_<base>_vs_<curr>_<timestamp>.csv`
- `summary_<base>_vs_<curr>_<timestamp>.csv`
- `snapshot_<curr>_<timestamp>.csv`

### 노출위험/공격표면 컬럼
- CSV 결과에 `노출위험`, `공격표면` 컬럼이 포함됩니다.
- `categories.xlsx`는 이제 기본 6컬럼(`서비스명/분류/용도/설명/노출위험/공격표면`)으로 생성되며,
  기존 3~4컬럼 파일도 하위호환으로 읽습니다.

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
               snmp-info,ike-version,sip-methods,ntp-info,
               nbstat,smb-os-discovery,smb-protocols,rpcinfo,
               fingerprint-strings' \
     -T4 --max-retries 2 --reason --open --defeat-rst-ratelimit \
     -oA phase1 <대역>
```

## 변경 이력

<details>
<summary><b>v0.2 — 안정성 (현재)</b></summary>

- 좀비 nmap 방지 (창 닫기 시 자식 프로세스 정리)
- 스캔 중지 시 친절 popup (XML ParseError 안 뜸)
- 다중 `-p` 자동 합치기
- xlsx XML invalid control char sanitize
- IP octet 검증 (`192.168.1.999` 거부)
- styles.xml OOXML strict 준수 (openpyxl 경고 0)
- CSV 에 식별/비고 컬럼 추가 (12컬럼)
</details>

<details>
<summary><b>v0.1 — 첫 릴리즈</b></summary>

- Windows 단독 실행 `.exe` (PyInstaller, ~10.7 MB)
- 10컬럼 CSV (IP/PORT/포트상태/추측·확인서비스/분류/용도/상세/NSE)
- options.xlsx 5컬럼 + categories.xlsx 4컬럼 Excel 편집
- 라디오 그룹 + 체크박스 grid + 한국어 툴팁
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

## 한계

- `-sS` / `-O` 는 관리자 권한 필요. 일반 사용자는 라디오에서 `Connect` 선택.
- 구버전 nmap 에 없는 NSE 는 nmap 이 무시 또는 경고만.
- IPv6-only 호스트는 CSV `IP` 컬럼에 IPv6 주소 그대로.
- override 모드 사용 시 IP 검증 / 옵션 충돌 검사는 동작하지 않음 — 사용자 책임.

## 라이선스 / 만든 사람

MIT — [LICENSE](./LICENSE) · [@patissierMongs](https://github.com/patissierMongs)
