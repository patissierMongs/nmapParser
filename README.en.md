# nmapParser

> **Korean-friendly nmap GUI for non-technical reviewers/managers** — Korean labels, Excel-driven options, CSV output with auto-filled category/identification/note columns ready to drop into a report.

🇰🇷 *한국어: [README.md](./README.md)*

![nmapParser GUI](./screenshot_readme.png)

---

## 30-second pitch

1. **Type a target → ▶ Scan.** GUI defaults assemble the user's standard `phase1` command end-to-end.
2. **23-column CSV.** host/OS/proto·standard-port·식별·**위험도(상/중/하)**·encryption·auth·분류·용도·노출위험·공격표면·**출처(KISA/CIS/MITRE)**·점검메모 — filter `위험도=상` in Excel for instant prioritization.
3. **Excel-managed options.** Add rows to `options.xlsx` / `categories.xlsx`, click reload, GUI picks them up.

![Sample CSV](./screenshot_csv_sample.png)

## Quick start

**Option A — Windows binaries (no Python)**

Two formats ship together on the Releases page (both x86 — run on 32-bit and 64-bit Windows alike).

| File | First-launch speed | Deployment | Best for |
|---|---|---|---|
| `nmapParser-x86.zip` (**recommended**) | **instant** | extract once | strict-AV / corporate machines, OneDrive-synced folders, network drives |
| `nmapParser.exe` (single file) | 5–30s on first run | one file | personal PCs / one-shot use |

1. Install nmap: <https://nmap.org/download.html>
2. Grab one of the files above from [Releases](https://github.com/patissierMongs/nmapParser/releases/latest).
3. Run:
   - zip → extract to a folder, double-click `nmapParser.exe` inside.
   - single `.exe` → double-click. First launch may appear frozen for a few seconds while PyInstaller unpacks to `%TEMP%` and Defender scans the binary (normal — subsequent launches are instant).
4. `options.xlsx` / `categories.xlsx` are auto-created on first run.
   - If the install location is read-only (e.g., `C:\Program Files\…`) the config files automatically fall back to `%APPDATA%\nmapParser\`. You can also pin a custom folder via **"설정 폴더 변경..."** or pin individual xlsx files directly.

**Option B — from source**
```
git clone https://github.com/patissierMongs/nmapParser.git
cd nmapParser
python nmapParser.py    # or nmapParser.bat
```

## Features

- **Korean GUI + hover tooltip** on every option.
- **Checkboxes + radio groups** (TCP scan type / speed — same group = pick one).
- **`phase1` standard default.** SYN + version detect + 26 UDP ports + 19 NSE in one command.
- **Auto `-p` merge.** Both TCP-full and UDP rows ON → single `-p T:...,U:...`.
- **Live log** (last 275 lines on screen, full output to `.log` file) + auto `--stats-every 1m` to defeat stdout buffering.
- **Window-close kills nmap** — no zombie processes.

## CSV — 23 columns

| # | Column | Meaning |
|---|---|---|
| 1–3 | IP / 호스트 / OS | nmap basics + DNS PTR + osmatch |
| 4–6 | 프로토콜 / 포트 / 표준포트 | nmap result + standard well-known port (from categories.xlsx, for comparison) |
| 7 | 포트상태 | open / closed / filtered |
| 8–9 | 추측서비스 / 확인서비스(short) | nmap-services lookup vs XML `<service>@name` |
| 10 | 식별 | `확인` / `추측` / `tcpwrapped` / `미확인` |
| 11–12 | 분류 / 용도 | `웹` / `원격접속` / ... + `관리` / `사용자` / `시스템` / ... |
| 13 | 위험도 | `상` / `중` / `하` (KISA-style) |
| 14–15 | 암호화 / 인증 | `평문` / `TLS` / `암호화` / `선택` + `익명가능` / `사용자` / `키` / `Kerberos` etc. |
| 16–17 | 노출위험 / 공격표면 | one-line facts |
| 18 | 출처 | `KISA U-21, CIS 4.5, MITRE T1040` style reference |
| 19 | 상세(제품/버전) | verbose — `OpenSSH 9.6p1 Ubuntu...` |
| 20 | 비고 | one-line summary — detail + NSE key (CN, OS, hostname, title) |
| 21 | NSE스크립트명 | comma-joined script ids (one row per port) |
| 22 | 스크립트출력 | `[id] output` blocks newline-joined |
| 23 | 점검메모 | empty — for the reviewer to fill in Excel (preserved across runs) |

### Risk / exposure / attack-surface / source — data priority

The 4 columns are **observational facts only** (no judgment / remediation). Mapping priority:

1. **KISA** — Korea Internet & Security Agency "취약점 분석·평가 상세 가이드" UNIX/Linux (U-01~U-72), Windows (W-01~W-72), ISMS-P, MOIS e-Government, KFSI rules.
2. **CIS Critical Security Controls v8** — Control 4 (Secure Configuration), 4.5/4.6/4.8/4.10 etc.
3. **MITRE ATT&CK** — Technique IDs (T1021.001 RDP / T1021.002 SMB / T1190 / T1133 etc).

105 services shipped with full KISA-U/W + CIS Control + MITRE Technique ID mapping.

> **Observation only.** Priority, exposure assessment, recommendations are intentionally not generated — that's the human's call.

### Why two service columns
- Port 22000 with 추측서비스 = `snapenetio` but 확인서비스(short) = `ssh` → table guess was wrong.
- 확인서비스(short) ending in `?` (e.g. `microsoft-ds?`) → probe attempted, failed. Don't trust the table guess alone.

## Excel-managed options

Click `options.xlsx 열기 (Excel)` → edit → save → click `옵션 다시 불러오기`.

| File | Columns | Purpose |
|---|---|---|
| `options.xlsx` | label / option / enable / group / desc | checkbox/radio/tooltip |
| `categories.xlsx` | 13-col recommended: 서비스명/표준포트/프로토콜/분류/용도/위험도/암호화/인증/노출위험/공격표면/출처/설명/점검메모 | auto-fills CSV's 표준포트·암호화·인증·분류·용도·위험도·노출위험·공격표면·출처·점검메모 (105 services with KISA+CIS+MITRE). |

### Free column reordering + custom user columns

Both `options.xlsx` and `categories.xlsx` are read **by header name** — you can freely reorder columns or add your own (`담당자`, `점검일자`, `자산ID`, etc.) and the GUI keeps working.

- **Required headers**: `서비스명` (categories), `스캔 옵션`/`옵션`/`활성화` (options). Missing → friendly Korean popup.
- **Optional headers**: everything else. Missing standard columns are auto-filled from the in-code 105-service dict.
- **Custom user columns**: ignored by GUI, preserved by the migration script.
- **Backward compat**: 3/4/6/8-col `categories.xlsx` auto-detected. To force 13-col upgrade run `python scripts/migrate_categories_to_13col.py` (preserves user edits and custom columns, auto-backup).

## Reference command (`phase1`)

GUI defaults assemble exactly this — type target, click ▶:

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
     -oA phase1 <TARGET>
```

## Changelog

<details>
<summary><b>v0.2 — stability (current)</b></summary>

- No more zombie nmap on window close
- Stop-button shows a friendly popup (no XML ParseError)
- Multi `-p` auto-merge
- xlsx XML-invalid control-char sanitize
- IP octet validation (`192.168.1.999` rejected)
- styles.xml OOXML-strict (openpyxl: zero warnings)
- 12-column CSV (식별/비고 added)
</details>

<details>
<summary><b>v0.1 — first release</b></summary>

- Standalone Windows `.exe` (PyInstaller onefile, ~10.7 MB)
- 10-column CSV
- options.xlsx (5 col) + categories.xlsx (4 col) Excel-editable
- Radio groups + checkbox grid + Korean tooltips
</details>

## Locked-down corp / network-drive / AppLocker environments

Workarounds for restrictive setups:

- **AppLocker / SRP blocks `.exe`**: even the zip-extracted `nmapParser.exe` may
  be blocked. Switch to Option B (Python source) — `python nmapParser.py` or
  `nmapParser.bat`.
- **`%APPDATA%` is GPO-redirected / read-only**: app falls back to
  `%TEMP%\nmapParser`. If that fails too it enters **memory-only mode**
  (option edits last for the session only).
- **Force a path via env vars** (no GUI clicks needed):
  - `NMAPPARSER_DATA_DIR=D:\nmapParser` — config files folder
  - `NMAPPARSER_OUTPUT_DIR=D:\scans` — scan output folder
  - `NMAPPARSER_NMAP_EXE=C:\Tools\Nmap\nmap.exe` — non-standard nmap path
- **GUI override**: option-manager bar → `설정 폴더 변경...` button. Folder
  picker; if you cancel, it offers a direct xlsx-file picker as last resort.
- **Slow network drives**: extract the zip to a local SSD when possible.

## Power features

- **NSE panel header**: `[✓ 스크립트 사용]` master toggle, `[전부 해제]` button.
- **Basic-options panel header**: `[✓ UDP 스캔 사용]` toggle — disables every
  option containing `-sU` or `U:` ports (including their radios).
- **Advanced — `직접 입력 명령 (override)`**: tick the `override 사용` box
  next to the entry and **all other options are bypassed**; your full
  `nmap -sS ...` line runs verbatim. Output flags (`-oA` etc.) you provide
  are stripped and re-added to keep the CSV pipeline working.

## Limits

- `-sS` / `-O` needs admin. As a normal user, pick the `Connect` radio in `TCP 스캔 타입`.
- NSE scripts missing in older nmap → nmap warns and skips them.
- IPv6-only hosts appear in the CSV `IP` column with their IPv6 address.
- override mode skips IP validation and option-conflict checks — use carefully.

## License / Author

MIT — [LICENSE](./LICENSE) · [@patissierMongs](https://github.com/patissierMongs)
