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
| `nmapParser.exe` (single GUI file) | 5–30s on first run | one file | personal PCs / one-shot use |
| `nmapParser-cli.exe` (console) | immediate CLI output | one file | `--check-config`, automation, troubleshooting |

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
- **`phase1` standard default.** SYN + version detect + 26 UDP ports + 27 NSE scripts in one command.
- **NSE field extraction.** 19 NSE scripts (ssl-cert, smb-os-discovery, rdp-ntlm-info, http-server-header, …) are parsed into key fields (`TLS_CN`, `SMB_OS`, `NTLM_Computer`, `SSH_FP_SHA256`, …) and emitted as the `NSE추출` CSV column.
- **Time-axis report.** `📊 Time-axis report` button — merges multiple CSVs from a folder into a 5-or-6-sheet xlsx (Status / Heatmap / Change-history / Risk-trend / Meta / NSE-detail) with per-cell color fills (new=red, kept=blue, closed=purple, unobserved=gray).
- **Diff xlsx with colors.** `--out-format xlsx|csv|both` (default `both`). NEW_OPEN=red / CLOSED=purple / CHANGED=yellow rows in the xlsx; CSV outputs preserved.
- **Auto `-p` merge.** Both TCP-full and UDP rows ON → single `-p T:...,U:...`.
- **Live log** (last 275 lines on screen, full output to `.log` file) + auto `--stats-every 1m` to defeat stdout buffering.
- **Window-close kills nmap** — no zombie processes.

## CSV — 24 columns

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
| 18 | 출처 | `KISA U-21, 국정원 정보보안기본지침 제32조, CIS 4.5, MITRE T1040` — 4-source mapping |
| 19 | 상세(제품/버전) | verbose — `OpenSSH 9.6p1 Ubuntu...` |
| 20 | 비고 | one-line summary — detail + NSE key (CN, OS, hostname, title) |
| 21 | NSE스크립트명 | comma-joined script ids (one row per port) |
| 22 | 스크립트출력 | `[id] output` blocks newline-joined |
| 23 | NSE추출 | `TLS_CN=foo; SMB_OS=Windows 10; NTLM_Computer=WIN01` — auto-extracted from 19 NSE scripts |
| 24 | 점검메모 | empty — for the reviewer to fill in Excel (preserved across runs) |

### Risk / exposure / attack-surface / source — data priority

The 4 columns are **observational facts only** (no judgment / remediation). Mapping priority:

1. **KISA** — Korea Internet & Security Agency "취약점 분석·평가 상세 가이드" UNIX/Linux (U-01~U-72), Windows (W-01~W-72), ISMS-P, MOIS e-Government, KFSI rules.
2. **국정원 (NIS)** — National Intelligence Service "정보보안기본지침" / "기술적 보호조치 지침" / KCMVP. Cited for items common in Korean inspection (telnet/ftp/SMB1/SNMP v1·v2/RDP/cleartext credentials).
3. **CIS Critical Security Controls v8** — Control 4 (Secure Configuration), 4.5/4.6/4.8/4.10 etc.
4. **MITRE ATT&CK** — Technique IDs (T1021.001 RDP / T1021.002 SMB / T1190 / T1133 etc).

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

- **Required headers**: `서비스명` (categories), `스캔 옵션`/`옵션`/`활성화` (options). Missing → friendly Korean popup or `--check-config` failure message.
- **Common header aliases accepted**: `스캔옵션`, `옵션명`, `사용여부`, `설명`, `service`, `port`, `risk`, `memo`, etc. are normalized to standard headers.
- **Duplicate header diagnostics**: alias-equivalent duplicates such as `스캔 옵션` + `옵션명` fail loudly instead of silently choosing one.
- **Optional headers**: everything else. Missing standard columns are auto-filled from the in-code 105-service dict.
- **Custom user columns**: ignored by GUI, preserved by the migration script.
- **Backward compat**: 3/4/6/8-col `categories.xlsx` auto-detected. To force 13-col upgrade run `python scripts/migrate_categories_to_13col.py` (preserves user edits and custom columns, auto-backup).

### Config preflight without GUI

Before deploying to a site, or before a monthly check, validate config files from CLI:

```bash
# Validate options.xlsx / categories.xlsx in the current folder
python nmapParser.py --check-config

# Validate explicit files
python nmapParser.py --check-config --options options.xlsx --categories categories.xlsx
```

Success example:
```text
[check-config] OK options.xlsx: 37 rows — options.xlsx
[check-config] OK categories.xlsx: 105 services — categories.xlsx
```
Failures print `[check-config] FAIL ...` and return a non-zero exit code, so the command is suitable for deployment scripts/checklists.

## Offline XML→CSV / base-vs-current Diff

Existing nmap XML outputs can be converted and compared without scanning.

```bash
# XML file or folder -> CSV
python nmapParser.py --xml2csv <input.xml_or_dir> --out <output_dir> --open-only

# Base/current comparison (xml/csv can be mixed)
python nmapParser.py --diff --base <base.xml_or_csv> --curr <curr.xml_or_csv> \
                     --out <output_dir> --only-changes --out-format both

# Multiple CSVs -> time-axis Excel report
python nmapParser.py --report --csv-folder <csv_folder> --out <report.xlsx>

# Config preflight
python nmapParser.py --check-config --options <options.xlsx> --categories <categories.xlsx>

# Optional: explicit categories.xlsx
python nmapParser.py --xml2csv <input.xml_or_dir> --categories <categories.xlsx> --out <output_dir>
```

Generated diff files:
- `diff_<base>_vs_<curr>_<timestamp>.csv` — detailed changes. `changed_fields` uses `state/service/detail/nse_or_script`.
- `summary_<base>_vs_<curr>_<timestamp>.csv` — NEW_OPEN/CLOSED/CHANGED/UNCHANGED counts.
- `snapshot_<curr>_<timestamp>.csv` — current snapshot.
- `diff_<base>_vs_<curr>_<timestamp>.xlsx` — colored Excel when `--out-format xlsx|both`.

CLI also prints `[diff] SUMMARY: NEW_OPEN=... CLOSED=... CHANGED=...` after each diff run.

## Reference command (`phase1`)

GUI defaults assemble exactly this — type target, click ▶:

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
     -oA phase1 <TARGET>
```

## Changelog

<details open>
<summary><b>v0.4.0 — time-axis report + NSE extraction (in progress)</b></summary>

- **24-column CSV** — added `NSE추출` (NSE-extract) column. 19 NSE outputs (ssl-cert / smb-os-discovery / rdp-ntlm-info / http-server-header / ssh-hostkey / nbstat / snmp-info / ike-version / ntp-info / sip-methods / ms-sql-info / oracle-tns-version / rpcinfo / fingerprint-strings / tls-alpn / ssl-enum-ciphers / http-headers / http-title / smb-protocols) parsed into key fields (TLS_CN, TLS_SAN, TLS_Issuer, TLS_NotAfter, TLS_SelfSigned, SMB_OS, SMB_Computer, SMB_Domain, SMB_HasV1, NTLM_Computer, NTLM_OS_Build, SSH_FP_SHA256, SSH_KeyTypes, HTTP_Server, HTTP_Title, SNMP_sysDescr, IKE_Version, NTP_Stratum, MSSQL_Version, …).
- **5-or-6-sheet xlsx report** — `📊 Time-axis report` button / `--report --csv-folder <path>` CLI. Sheets: Status / Heatmap (color-filled cells) / Change-history / Risk-trend / Meta / NSE-detail.
- **Diff color xlsx** — `--out-format xlsx|csv|both` (default `both`). NEW_OPEN red / CLOSED purple / CHANGED yellow / UNCHANGED white.
- **categories.xlsx 13-column migration prompt** — header check at startup; missing cols → popup. Yes preserves user edits + custom columns; auto-backup.
- **options.xlsx new-option auto-add prompt** — compares to DEFAULT_OPTIONS; missing → popup. Yes inserts as `enabled=0` (user decides).
- **NIS (국정원) source citations** — KCMVP / Information Security Basic Guideline / Technical Safeguards Guideline added to the 출처 column. 4-source mapping (KISA + NIS + CIS + MITRE).
- **Config diagnostics CLI** — `--check-config --options <options.xlsx> --categories <categories.xlsx>` validates Excel aliases/duplicate headers/required columns without launching the GUI.
- **Diff/report supportability** — diff CLI summary output, `changed_fields=nse_or_script` label, report Meta sheet records input filenames/encodings, Heatmap marks service-signature changes as changed.
- Misc: GUI override + GUI targets auto-merge, CSV collection dedup (hash + skip prior `_collected_/`), preflight strengthened with config validation, `_relocate_config_dir` None-safety.
- Tests 59 passing.
</details>

<details>
<summary><b>v0.3.1 — corporate hardening + regression fix</b></summary>

- **Regression fix** (`fix(scan): regression — restore bufsize=0 + conditional cwd, raise watchdog thresholds`):
  - `bufsize=0` restored (v0.2 default). `bufsize=-1` left nmap stdout in OS full-buffer → GUI looked frozen for tens of seconds + watchdog false alarm.
  - `cwd` now defaults to `None` (parent inherit). Falls back to `tempdir` only when an UNC path (`\\server\share`) is detected in the command.
  - Watchdog hint 5s → 30s, warn 30s → 90s, tick 5s → 15s — absorbs nmap's normal phase transitions / NSE loading silence.
- **BEL/control-char strip** — `\x07` and other invalid control chars stripped before tk Text insert; kills repeated Windows alert sound.
- **Atomic xlsx write** — tempfile + os.replace; survives UNC drops / disk-full / Excel locks.
- **shutil.which** auto-discover for nmap.
- **Red banner** when running as non-admin and `-sS` / `-O` is selected.
- **📂 CSV collection button** — recursive `*.csv` gather + hash dedup.
- **UPX disabled** (AV signature avoidance).
</details>

<details>
<summary><b>v0.3.0 — KISA-first data + diff CLI/GUI</b></summary>

- **23-column CSV** (식별/분류/용도/위험도/암호화/인증/노출위험/공격표면/출처/상세/비고/NSE/출력/점검메모).
- **위험도 (상/중/하)** Korean enum.
- **categories.xlsx 13-column** schema. Header-name based reader — free column reordering + user custom columns preserved.
- **`--diff` CLI + GUI button** — base/curr CSV(or XML) → diff/summary/snapshot triplet.
- **`--xml2csv` CLI** — bulk XML→CSV.
- **Override mode**, **UDP master toggle**, **NSE master toggle**.
</details>

<details>
<summary><b>v0.2 — stability</b></summary>

- No more zombie nmap on window close.
- Stop-button shows a friendly popup (no XML ParseError).
- Multi `-p` auto-merge.
- xlsx XML-invalid control-char sanitize.
- IP octet validation (`192.168.1.999` rejected).
- styles.xml OOXML-strict (openpyxl: zero warnings).
- 12-column CSV (식별/비고 added).
</details>

<details>
<summary><b>v0.1 — first release</b></summary>

- Standalone Windows `.exe` (PyInstaller onefile, ~10.7 MB).
- 10-column CSV.
- options.xlsx (5 col) + categories.xlsx (4 col) Excel-editable.
- Radio groups + checkbox grid + Korean tooltips.
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

## CSV collection (time-series audit)

CSVs accumulate across recurring scans and get scattered. The **`📂 CSV 취합`** button gathers them into one folder:

1. In the `결과 CSV 변환` area, click **`📂 CSV 취합`**.
2. Pick the parent folder containing the scattered CSVs (search is recursive).
3. `<chosen>/_collected_<yyyyMMdd_HHmmss>/` is auto-created and all `*.csv` are copied in (originals preserved; name conflicts get `_2`, `_3`).
4. Done popup shows count, oldest/newest timestamps, and any failures.
5. The folder opens automatically on Windows.

Use the gathered folder for whole-asset review, time-series comparison via the Diff feature, or export to external tooling.

## Corporate / restricted environments

Common symptoms and fixes when running on locked-down corporate PCs:

| Symptom | Root cause | Fix |
|---|---|---|
| SmartScreen "Unknown publisher" on first run | unsigned .exe (personal build) | "More info → Run anyway", or use `nmapParser-x86.zip` (`--onedir`) — archives are generally not blocked the same way |
| AV quarantines the .exe | UPX signature / PyInstaller heuristic | v0.3.1+ ships with UPX disabled. If still blocked, use the `--onedir` zip |
| "Starting Nmap" never shows, GUI looks frozen | Python build difference — stdout has no `read1` | Fixed in v0.2 (`a045f58`); use latest .exe |
| AppLocker / GPO blocks user-folder .exe | policy | Whitelist request, or run `python nmapParser.py` via PowerShell |
| Korean username path (`C:\Users\홍길동\`) + `--onefile` | PyInstaller `_MEI` extraction issue with non-ASCII path on some builds | Use `--onedir` zip |
| nmap stdout stalls on UNC / mapped drive | nmap cwd on UNC can deadlock IO | v0.3.1+ uses `cwd=None` by default (parent inherit, v0.2 behavior) and falls back to `tempdir` only when an UNC path is detected in the command. Forcing tempdir unconditionally caused regressions in some setups, fixed in v0.3.1 |
| DLP blocks option xlsx | policy | Set `NMAPPARSER_DATA_DIR` env var to a permitted folder |

## Limits

- `-sS` / `-O` needs admin. As a normal user, pick the `Connect` radio in `TCP 스캔 타입`.
- NSE scripts missing in older nmap → nmap warns and skips them.
- IPv6-only hosts appear in the CSV `IP` column with their IPv6 address.
- override mode skips IP validation and option-conflict checks — use carefully.

## License / Author

MIT — [LICENSE](./LICENSE) · [@patissierMongs](https://github.com/patissierMongs)
