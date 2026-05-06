# nmapParser

> A Korean-friendly nmap GUI for non-technical users — manage scan options through Excel, see real-time scan progress, and get parseable CSV output that distinguishes guessed services from probed ones.

🇰🇷 **한국어 버전**: [README.ko.md](./README.ko.md)

![nmapParser GUI](./screenshot_readme.png)

---

## Why this exists

Most nmap GUIs (Zenmap, etc.) expose the same English flags as the CLI. For someone who isn't already comfortable with `-sS`, `--version-all`, `--script smb-os-discovery`, that's a tall wall. nmapParser was built for the opposite end of the spectrum:

- **Korean labels and tooltips** for every option, rendered alongside the actual nmap flag.
- **Excel-managed option list** so end users can add, remove, or re-label scan options without touching code.
- **CSV output that separates "what nmap guessed" from "what nmap actually probed"** — a `?` suffix flags every port where probe failed (e.g. `microsoft-ds?`), so the user immediately knows the result is unverified.
- **Pure Python standard library** — no `pip install` required. Drop the folder on any Windows machine with Python 3.x and nmap, double-click the `.bat`, you're scanning.

## Features

| Area | Detail |
|---|---|
| **GUI** | tkinter, all labels in Korean, hover tooltips with detailed Korean explanations of every option |
| **Options via Excel** | `options.xlsx` with 5 columns: `스캔 옵션`(label) / `옵션`(nmap arg) / `활성화`(0/1) / `그룹`(radio group name) / `상세설명`(tooltip text) |
| **Radio groups** | Same `그룹` value → mutually-exclusive radio buttons. Built-in: `TCP 스캔 타입` (SYN/Connect/Null/FIN/Xmas/ACK), `속도` (T0–T5) |
| **Scan options auto-classify** | Rows whose option starts with `--script` → NSE panel (right). Other options → basic panel (left) |
| **Auto window sizing** | Window height grows with the option count up to your screen limit; only past that does the panel scrollbar matter |
| **Targets** | Multi-line text box (free-form IPs, CIDRs, hostnames). `📁 파일에서 불러오기` button reads `.txt` (one target per line) |
| **Real-time progress** | `--stats-every 1m` is added by default — nmap forces a progress line every minute, so the GUI log never appears stuck even when stdout is buffered |
| **Log buffer** | The on-screen log keeps the most recent 275 lines (rolling); the **complete** stdout is saved to `<output>/<target>_<timestamp>.log`, openable from the `전체 로그 보기 (.log)` button |
| **CSV export** | 9-column CSV: IP / PORT / 포트상태 / 추측서비스 / 확인서비스(short) / **분류** / 상세(제품/버전) / NSE스크립트명 / 스크립트출력. Categories driven by editable `categories.xlsx` (~95 entries) |
| **Auto nmap detection** | Looks for `C:\Program Files (x86)\Nmap\nmap.exe`, then `C:\Program Files\Nmap\nmap.exe`, then a sibling `nmap.exe`. Manual selection (red button) if not found |
| **Migration** | Old `options.csv` is auto-migrated to `options.xlsx` on first run; original is kept as `options.csv.bak` |
| **Excel safety** | All cells use shared-string encoding so values like `-Pn`, `--version-all`, `=SUM(...)`, `+x`, `@y` are never interpreted as formulas (no `#NAME?` errors, no recovery prompt) |

## Quick start

### Option A — Standalone .exe (no Python required)

1. Install **nmap**: <https://nmap.org/download.html>.
2. Download `nmapParser.exe` from the [Releases page](https://github.com/patissierMongs/nmapParser/releases/latest).
3. Double-click. `options.xlsx` is auto-created next to the .exe on first run.

### Option B — From source (Python)

1. Install **Python 3.x** (with `pythonw` — the Windows installer enables it by default).
2. Install **nmap**: <https://nmap.org/download.html>.
3. Clone:
   ```
   git clone https://github.com/patissierMongs/nmapParser.git
   cd nmapParser
   ```
4. Double-click **`nmapParser.bat`** (or run `python nmapParser.py`).

On the first launch, `options.xlsx` is auto-created with sensible defaults (37 options including the radio groups). No further setup is needed.

## Configuration via Excel

Open `options.xlsx` from the `options.xlsx 열기 (Excel)` button inside the app, edit, save, click `옵션 다시 불러오기`. The window resizes itself to fit the new option count.

| Column | Meaning |
|---|---|
| `스캔 옵션` | Label shown on the checkbox/radio |
| `옵션` | The actual nmap argument (e.g. `-Pn`, `--max-retries 2`, `--script ssh-hostkey`) |
| `활성화` | `1` = checked by default, `0` = unchecked |
| `그룹` | Empty → standalone checkbox. Same value → radio group (one selection) |
| `상세설명` | Tooltip text shown on hover. Empty → no tooltip |

A row whose `옵션` starts with `--script` is automatically placed in the NSE panel. `-oA / -oX / -oN / -oG` output flags are ignored if you write them — the app always manages output paths itself.

### Adding a new option

1. Click `options.xlsx 열기 (Excel)`.
2. Append a new row, e.g. `["Aggressive scan", "-A", "0", "", "OS detection + version + default NSE + traceroute combo"]`.
3. Save. Back in the app, click `옵션 다시 불러오기`. The new checkbox appears immediately.

## CSV output

The CSV that comes out of a scan has these 9 columns:

`IP, PORT, 포트상태, 추측서비스, 확인서비스(short), 분류, 상세(제품/버전), NSE스크립트명, 스크립트출력`

| Column | Source | Meaning |
|---|---|---|
| **추측서비스** | `nmap-services` file lookup by port number | Static port→name mapping (e.g. `ssh`, `http`, `microsoft-ds`). Always populated. |
| **확인서비스(short)** | XML `<service>@name` only | Just the service name nmap actually identified — `ssh`, `http`, `msrpc`. With `?` suffix when probe failed (`microsoft-ds?`). Empty when nothing detected. |
| **분류** | `categories.xlsx` lookup | Korean category — `웹` / `원격접속` / `DBMS` / `파일공유` / `메일` / `RPC` / etc. Falls back to lookup by 추측서비스 if the probed name isn't in the table; finally `미분류`. |
| **상세(제품/버전)** | XML `<service>` `@product` + `@version` + `@extrainfo` + `@ostype` joined | Detail row used only when you need to drill in (e.g. `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 Ubuntu Linux`). |
| NSE스크립트명 | XML `<script>@id` | Matched NSE script ID. Multiple matches → multiple rows for the same port. |
| 스크립트출력 | XML `<script>@output` | NSE script raw output (newlines replaced with ` \| `). |

The split between **확인서비스(short)** and **상세(제품/버전)** is the key change: the short column is the Excel filter/sort key, the detail column carries the verbose product/version string. With the **분류** column you can filter the CSV to "웹 only" or "DBMS only" with one click in Excel.

### Why 분류
Most scans return enough ports that you spend the next minute mentally categorizing — "what's a web server, what's a DB, what's just RPC noise." `categories.xlsx` does that for you:

| 서비스명 | 분류 | 설명 |
|---|---|---|
| ssh | 원격접속 | SSH 원격 셸/관리 접속 |
| http | 웹 | HTTP 웹 서버 |
| mysql | DBMS | MySQL/MariaDB |
| ldap | 디렉토리 | LDAP 디렉토리 |
| ... | ... | ... |

About 95 entries auto-shipped. Edit `categories.xlsx` in Excel and click `분류 다시 불러오기` to add your own.

### Two-column "guess vs probe" intent
The `추측서비스` and `확인서비스(short)` columns together preserve the original intent: when port `22000` shows `snapenetio` (table guess) but `확인서비스(short)` is empty/different, you know the table was wrong. When `확인서비스(short)` ends in `?`, you know nmap probed but couldn't identify — `microsoft-ds?` means "we tried, failed, and the table guess is all you have."

### Real-world example from a localhost scan

| PORT | 추측서비스 | 확인서비스(short) | 분류 | 상세(제품/버전) |
|---|---|---|---|---|
| 22 | ssh | `ssh` | 원격접속 | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 Ubuntu Linux` |
| 135 | msrpc | `msrpc` | RPC | `Microsoft Windows RPC Windows` |
| 445 | microsoft-ds | `microsoft-ds?` | 파일공유 | (empty — probe failed) |
| 902 | iss-realsecure | `vmware-auth` | 관리 | `VMware Authentication Daemon 1.10 Uses VNC, SOAP` |
| 3389 | ms-wbt-server | `ms-wbt-server?` | 원격접속 | (empty — probe failed) |
| 5040 | unknown | (empty) | 미분류 | (empty) |

## Tech stack

Pure Python standard library:

`tkinter` (GUI) · `subprocess` + `threading` (live nmap process) · `xml.etree.ElementTree` (parsing nmap XML) · `csv` (CSV export) · `zipfile` + `xml.etree` (custom xlsx reader/writer in `xlsx_io.py` to avoid any pip dependency and to dodge Excel's CSV formula-interpretation pitfall) · `shlex` (option string parsing) · `os.startfile` (open files in their default Windows app)

No `pip install` anywhere.

## Files

| File | Purpose |
|---|---|
| `nmapParser.py` | Main GUI app |
| `xlsx_io.py` | stdlib-only xlsx reader/writer (shared-string cells) |
| `options.xlsx` | Editable option list (auto-created on first run) |
| `nmapParser.bat` | Double-click launcher (`pythonw` preferred, falls back to `python`) |
| `README.md` / `README.ko.md` | This document |

## Known limits

- `-sS` (TCP SYN scan) needs administrator privileges. As an unprivileged user, pick the `Connect (-sT)` radio in the `TCP 스캔 타입` group instead.
- Some NSE scripts may not exist in older nmap versions; nmap silently ignores or warns and continues.
- IPv6-only hosts will appear in the CSV `IP` column with their IPv6 address.

## License

MIT — see [LICENSE](./LICENSE).

## Author

Made by [@patissierMongs](https://github.com/patissierMongs).
