# nmapParser

> 비기술 사용자를 위한 한국어 nmap GUI — Excel 로 옵션 관리, 실시간 스캔 진행 표시, 그리고 "추측한 서비스" 와 "실제로 probe 한 서비스" 를 구분해서 보여주는 CSV 출력.

🇬🇧 **English version**: [README.md](./README.md)

![nmapParser GUI](./screenshot_readme.png)

---

## 왜 만들었나

대부분의 nmap GUI (Zenmap 등) 는 CLI 와 똑같이 영어 플래그를 그대로 노출합니다. `-sS`, `--version-all`, `--script smb-os-discovery` 같은 표기에 익숙하지 않은 사용자에게는 진입장벽이 높습니다. nmapParser 는 그 반대 방향을 노렸습니다:

- 모든 옵션에 **한국어 라벨과 상세설명 툴팁**. 실제 nmap 플래그도 같이 표기.
- **Excel 로 관리되는 옵션 리스트** — 코드 수정 없이 옵션 추가/제거/라벨 변경 가능.
- **CSV 에서 "nmap이 추측한 것" 과 "실제로 probe 한 것" 분리** — probe 실패 시 `?` 접미사 (예: `microsoft-ds?`) 로 즉시 인지.
- **Python 표준 라이브러리만** 사용 — `pip install` 불필요. Python 3.x 와 nmap 만 깔린 Windows PC 에 폴더 통째로 옮겨 `.bat` 더블클릭하면 끝.

## 기능

| 영역 | 내용 |
|---|---|
| **GUI** | tkinter, 모든 라벨 한국어, 옵션마다 상세설명 hover 툴팁 |
| **Excel 옵션 관리** | `options.xlsx` 5컬럼 — `스캔 옵션`(라벨) / `옵션`(nmap 인자) / `활성화`(0/1) / `그룹`(라디오 그룹명) / `상세설명`(툴팁) |
| **라디오 그룹** | 같은 `그룹` 값 → 택 1 라디오. 기본 제공: `TCP 스캔 타입`(SYN/Connect/Null/FIN/Xmas/ACK), `속도`(T0~T5) |
| **자동 분류** | 옵션이 `--script` 로 시작 → NSE 패널(우측) 자동 배치, 그 외 → 기본 옵션 패널(좌측) |
| **자동 창 크기** | 옵션 수에 따라 창 height 가 화면 한계까지 자동 확장. 한계 도달 후에야 패널 스크롤바 의미 |
| **타겟 입력** | 여러 줄 텍스트박스 (IP, CIDR, 호스트명 자유). `📁 파일에서 불러오기` 로 `.txt` 한 줄 한 타겟 읽기 |
| **실시간 진행** | `--stats-every 1m` 자동 추가 — nmap 이 1분마다 진행 stats 를 강제로 출력해서 GUI 로그창이 buffer 때문에 비어 보이는 문제 회피 |
| **로그 buffer** | 화면 로그창은 최근 275줄 (rolling). **전체** stdout 은 `<출력경로>/<타겟>_<시각>.log` 파일에 저장, `전체 로그 보기 (.log)` 버튼으로 열람 |
| **CSV 변환** | 9컬럼 CSV: IP / PORT / 포트상태 / 추측서비스 / 확인서비스(short) / **분류** / 상세(제품/버전) / NSE스크립트명 / 스크립트출력. 분류는 `categories.xlsx` (~95 항목, Excel 편집 가능) 기반 |
| **nmap 자동 탐지** | `C:\Program Files (x86)\Nmap\nmap.exe` → `C:\Program Files\Nmap\nmap.exe` → 같은 폴더의 `nmap.exe` 순서로 탐색. 못 찾으면 빨간 버튼 클릭해 직접 지정 |
| **마이그레이션** | 구버전 `options.csv` 가 있으면 첫 실행 시 자동으로 `options.xlsx` 변환, 원본은 `options.csv.bak` 으로 백업 |
| **Excel 호환성** | 모든 셀이 shared-string 으로 저장돼 `-Pn`, `--version-all`, `=SUM(...)`, `+x`, `@y` 같은 값도 절대 수식으로 해석 안 됨 (`#NAME?` 안 뜨고 "복구됨" 메시지도 없음) |

## 빠른 시작

### 방법 A — 단독 실행 .exe (Python 설치 불필요)

1. **nmap** 설치: <https://nmap.org/download.html>.
2. [Releases 페이지](https://github.com/patissierMongs/nmapParser/releases/latest) 에서 `nmapParser.exe` 다운로드.
3. 더블클릭. 첫 실행 시 `options.xlsx` 가 .exe 옆 폴더에 자동 생성됨.

### 방법 B — 소스에서 (Python 사용)

1. **Python 3.x** 설치 (`pythonw` 포함 — Windows 인스톨러 기본값).
2. **nmap** 설치: <https://nmap.org/download.html>.
3. clone:
   ```
   git clone https://github.com/patissierMongs/nmapParser.git
   cd nmapParser
   ```
4. **`nmapParser.bat`** 더블클릭 (또는 `python nmapParser.py`).

처음 실행하면 `options.xlsx` 가 기본 옵션 셋으로 자동 생성됩니다 (라디오 그룹 포함 37개). 추가 설정 불필요.

## Excel 로 옵션 관리

GUI 의 `options.xlsx 열기 (Excel)` 버튼 → 편집 → 저장 → `옵션 다시 불러오기` 클릭. 옵션 수에 맞춰 창 크기도 자동 재조정.

| 컬럼 | 의미 |
|---|---|
| `스캔 옵션` | 체크박스/라디오에 표시되는 한국어 라벨 |
| `옵션` | 실제 nmap 인자 (예: `-Pn`, `--max-retries 2`, `--script ssh-hostkey`) |
| `활성화` | `1` = GUI 시작 시 기본 체크, `0` = 해제 |
| `그룹` | 비어 있으면 독립 체크박스. 같은 값을 가진 행끼리 라디오 그룹(택 1) |
| `상세설명` | hover 시 툴팁으로 표시될 텍스트. 비우면 툴팁 안 뜸 |

`옵션` 컬럼이 `--script` 로 시작하면 자동으로 NSE 패널에 들어갑니다. `-oA / -oX / -oN / -oG` 같은 출력 플래그는 적어도 무시됩니다 (출력 경로는 GUI 가 항상 자동 관리).

### 새 옵션 추가 예시

1. `options.xlsx 열기 (Excel)` 클릭.
2. 행 추가 — 예: `["Aggressive scan", "-A", "0", "", "OS 식별 + 버전 + 기본 NSE + traceroute 묶음 (-A). 빠르게 정보 모음."]`.
3. 저장. 앱으로 돌아와 `옵션 다시 불러오기`. 새 체크박스 즉시 표시.

## CSV 출력

스캔이 끝나면 CSV 가 12컬럼 — **객관적 관찰 사실만, 판단은 외부**:

`IP, PORT, 포트상태, 추측서비스, 확인서비스(short), 식별, 분류, 용도, 상세(제품/버전), 비고, NSE스크립트명, 스크립트출력`

| 컬럼 | 출처 | 의미 |
|---|---|---|
| **추측서비스** | `nmap-services` 파일 룩업 | 포트→이름 정적 매핑. 항상 채움. |
| **확인서비스(short)** | XML `<service>@name` 만 | nmap 이 실제 식별한 서비스명. probe 실패 시 `?` suffix. 미식별 시 빈 칸. |
| **식별** | XML `<service>@method` 분석 | 4값 (아래 표). |
| **분류** | `categories.xlsx` 룩업 | 한국어 분류 — `웹` / `원격접속` / `DBMS` / `파일공유` 등. |
| **용도** | `categories.xlsx` 룩업 | 관찰적 역할 — `관리` / `사용자` / `시스템` / `모니터링` 등. |
| **상세(제품/버전)** | XML `<service>` 의 `@product` + `@version` + `@extrainfo` + `@ostype` | verbose 정보. |
| **비고** | 자동 요약 한 줄 | detail + NSE 핵심 키 1~2개 콤마 join. **항상 한 줄 (멀티라인 X)**. |
| NSE스크립트명 | XML `<script>@id` | 매칭된 NSE 스크립트 ID. |
| 스크립트출력 | XML `<script>@output` | NSE raw 출력 (개행은 ` \| ` 치환). |

### 식별 컬럼 — 4값

| 값 | 의미 |
|---|---|
| `확인` | `<service @method="probed">` — nmap probe 가 product/version 까지 식별 |
| `추측` | `<service @method="table">` — 포트번호 룩업만 (probe 시도했지만 실패; 보통 확인서비스(short) 에 `?`) |
| `tcpwrapped` | `<service @name="tcpwrapped">` — handshake 는 되지만 probe 거부 |
| `미확인` | `<service>` 요소 없음 또는 `name="unknown"` |

### 비고 컬럼 — 자동 요약 한 줄

포트 단위로 빌드 (NSE 다중 행이면 같은 비고 값 반복):
1. **먼저**: `상세(제품/버전)` 값 (예: `Apache httpd 2.4.58`).
2. **그 다음**: NSE 결과에서 핵심 1~2 줄, 스크립트 ID 별 패턴:
   - `ssl-cert` → `CN=...`
   - `smb-os-discovery` → `OS=...` 또는 `host=...`
   - `rdp-ntlm-info` → `DNS_Computer_Name=...` 또는 `Target_Name=...`
   - `nbstat` → `host=...`
   - `http-title` → `title=...`
3. **둘 다 없으면 빈 칸**.

`, ` 로 join. 각 부분 80자 초과 시 잘림. **개행 없음** — Excel 행 한 줄 높이 유지.

> **이 도구의 역할 — 관찰까지.** CSV 는 nmap 이 본 사실만 기입. 판단(우선순위, 노출 평가, 권고 조치) 은 **외부**(점검자/리뷰어/후속 도구) 의 영역으로 둡니다. `분류` / `용도` 는 위험도 점수가 아니라 관찰 라벨.

**확인서비스(short)** 와 **상세(제품/버전)** 분리가 핵심: short 컬럼이 Excel 필터/정렬 키, detail 컬럼은 verbose 정보 분리. **분류** + **용도** 로 "웹만" / "DBMS만" / "관리 용도만" Excel 한 클릭 필터.

### categories.xlsx — 관찰적 분류 (4컬럼)

| 서비스명 | 분류 | 용도 | 설명 |
|---|---|---|---|
| ssh | 원격접속 | 관리 | SSH 원격 셸/관리 접속 |
| http | 웹 | 사용자 | HTTP 웹 서버 |
| mysql | DBMS | 시스템 | MySQL/MariaDB |
| snmp | 모니터링 | 모니터링 | SNMP |
| amqp | 메시지큐 | 내부통신 | RabbitMQ AMQP |
| ipmi | 관리 | 관리 | IPMI BMC 관리 |
| ... | ... | ... | ... |

기본 95개 항목 자동 동봉. Excel 로 `categories.xlsx` 편집 후 `분류 다시 불러오기` 클릭하면 즉시 반영. 4 컬럼 모두 관찰적 — 위험/우선순위/권고 컬럼은 의도적으로 두지 않음.

### "추측 vs 확정" 의도는 그대로 유지
- 22000번 포트 추측서비스가 `snapenetio` 인데 확인서비스(short) 가 비거나 다르다면 "추측 부정확" 즉시 인지.
- 확인서비스(short) 가 `?` 로 끝나면 "probe 했지만 식별 실패" — `microsoft-ds?` 같은 경우.

### 실제 localhost 스캔 사례

| PORT | 확인서비스(short) | 식별 | 분류 | 용도 | 비고 |
|---|---|---|---|---|---|
| 22 | `ssh` | 확인 | 원격접속 | 관리 | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 Ubuntu Linux` |
| 135 | `msrpc` | 확인 | RPC | 시스템 | `Microsoft Windows RPC Windows` |
| 445 | `microsoft-ds?` | 추측 | 파일공유 | 시스템 | (빈 칸) |
| 3389 | `ms-wbt-server?` | 추측 | 원격접속 | 관리 | `DNS_Computer_Name=yuyu, CN=yuyu` |
| 5040 | (빈 칸) | 미확인 | 미분류 | (빈 칸) | (빈 칸) |

### 기준 스캔 명령 (`phase1`)

GUI 가 default 옵션만으로 이 명령을 정확히 조립합니다 — 타겟 입력 후 ▶ 스캔 시작 클릭:

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

GUI 가 여러 `-p` 행을 자동으로 합칩니다 — "TCP 모든 포트 (1-65535)" + "UDP 주요 포트 스캔" 둘 다 ON 이면 단일 `-p T:...,U:...` 로 출력. NSE 행들도 단일 `--script` 인자로 dedup 후 합쳐짐.

## 기술 스택

Python 표준 라이브러리만:

`tkinter`(GUI) · `subprocess` + `threading`(nmap 프로세스 실시간 출력) · `xml.etree.ElementTree`(nmap XML 파싱) · `csv`(CSV 출력) · `zipfile` + `xml.etree`(`xlsx_io.py` 에서 자체 구현 xlsx 리더/라이터 — `pip` 의존성 회피 + Excel 의 CSV 수식 해석 함정 회피) · `shlex`(옵션 문자열 파싱) · `os.startfile`(파일 기본 앱으로 열기)

`pip install` 어디에도 없음.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `nmapParser.py` | 메인 GUI 본체 |
| `xlsx_io.py` | stdlib 만 사용한 xlsx 리더/라이터 (shared-string 셀) |
| `options.xlsx` | 편집 가능한 옵션 리스트 (첫 실행 시 자동 생성) |
| `nmapParser.bat` | 더블클릭 런처 (`pythonw` 우선, 없으면 `python`) |
| `README.md` / `README.ko.md` | 이 문서 |

## 알려진 한계

- `-sS` (TCP SYN 스캔) 는 관리자 권한 필요. 일반 사용자라면 `TCP 스캔 타입` 그룹에서 `Connect (-sT)` 라디오 선택.
- 일부 NSE 스크립트는 구버전 nmap 에 없을 수 있음. nmap 이 무시하거나 경고만 띄움.
- IPv6 전용 호스트는 CSV 의 `IP` 컬럼에 IPv6 주소가 그대로 들어감.

## 변경 이력

### v0.2 — 안정성 + 안전성
- **H-1** 스캔 중 GUI 닫기 → 좀비 `nmap.exe` 더 이상 남지 않음. 확인 popup 후 `terminate()` → `wait(3초)` → `kill()` cascade.
- **H-2** ■ 중지 버튼 → CSV 변환 skip + 친절한 "스캔 중지" popup (부분 파일 목록 포함). XML ParseError 다이얼로그 더 이상 안 뜸.
- **H-3** 다중 `-p` 행 (TCP / UDP / 사용자 입력) 이 단일 `-p T:...,U:...` 로 자동 합쳐짐.
- **M-1** `xlsx_io` 가 write 시점에 XML-1.0 invalid control char (`\x00`-`\x08`, `\x0b\x0c`, `\x0e`-`\x1f`) 제거 — NSE raw 바이트 출력이 read 시 ParseError 일으키지 않음.
- **M-2** `styles.xml` 을 OOXML strict spec 에 맞춤 — openpyxl 로 열어도 경고 0건.
- **M-6** 타깃 검증이 octet/prefix 범위 벗어난 IP (예: `192.168.1.999`, `/40`) 를 hostname 으로 잘못 통과시키지 않음.
- 사용 안 하는 `_clear_group` 메서드 제거, "inline string" docstring 을 "shared string" 으로 정정.

### v0.1 — 첫 릴리즈
- Windows 단독 실행 `.exe` (PyInstaller onefile, ~10.7 MB)
- 12컬럼 CSV (IP/PORT/포트상태/추측서비스/확인서비스(short)/식별/분류/용도/상세/비고/NSE/출력)
- `options.xlsx` (5컬럼: 라벨/옵션/활성화/그룹/상세설명) + `categories.xlsx` (4컬럼: 서비스명/분류/용도/설명) Excel 편집 가능
- 라디오 그룹 (TCP 스캔 타입, 속도) + 체크박스 grid 레이아웃
- 모든 옵션에 한국어 툴팁

## 라이선스

MIT — [LICENSE](./LICENSE) 참조.

## 만든 사람

[@patissierMongs](https://github.com/patissierMongs)
