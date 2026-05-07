# nmapParser

> **Korean-friendly nmap GUI for non-technical reviewers/managers** — Korean labels, Excel-driven options, CSV output with auto-filled category/identification/note columns ready to drop into a report.

🇰🇷 *한국어: [README.md](./README.md)*

![nmapParser GUI](./screenshot_readme.png)

---

## 30-second pitch

1. **Type a target → ▶ Scan.** GUI defaults assemble the user's standard `phase1` command end-to-end.
2. **12-column CSV output.** Open in Excel, filter by `분류` / `용도` / `식별` — 90% of the triage is done.
3. **Excel-managed options.** Add rows to `options.xlsx` / `categories.xlsx`, click reload, GUI picks them up.

![Sample CSV](./screenshot_csv_sample.png)

## Quick start

**Option A — standalone `.exe` (no Python)**
1. Install nmap: <https://nmap.org/download.html>
2. Download `nmapParser.exe` from [Releases](https://github.com/patissierMongs/nmapParser/releases/latest) (x86 build — runs on both 32-bit and 64-bit Windows)
3. Double-click. `options.xlsx` / `categories.xlsx` auto-created on first run.

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

## CSV — 12 columns

| Column | Meaning |
|---|---|
| IP, PORT, 포트상태 | nmap basics |
| **추측서비스** | port→name lookup (`nmap-services`) |
| **확인서비스(short)** | XML `<service>@name`. `?` suffix on probe failure |
| **식별** | `확인` / `추측` / `tcpwrapped` / `미확인` (4 values) |
| **분류** | `웹` / `원격접속` / `DBMS` / `RPC` / ... (from `categories.xlsx`) |
| **용도** | `관리` / `사용자` / `시스템` / `모니터링` / ... |
| **상세(제품/버전)** | verbose — `OpenSSH 9.6p1 Ubuntu...` |
| **비고** | one-line summary — detail + NSE key (CN, OS, hostname, title) |
| NSE스크립트명, 스크립트출력 | NSE raw result |

> **Observation only.** Priority, exposure assessment, recommendations are intentionally not generated — that's the human's call.

### Why two service columns
- Port 22000 with 추측서비스 = `snapenetio` but 확인서비스(short) = `ssh` → table guess was wrong.
- 확인서비스(short) ending in `?` (e.g. `microsoft-ds?`) → probe attempted, failed. Don't trust the table guess alone.

## Excel-managed options

Click `options.xlsx 열기 (Excel)` → edit → save → click `옵션 다시 불러오기`.

| File | Columns | Purpose |
|---|---|---|
| `options.xlsx` | label / option / enable / group / desc | checkbox/radio/tooltip |
| `categories.xlsx` | service / category / usage / desc | auto-fills `분류` / `용도` (95 entries shipped) |

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

## Limits

- `-sS` needs admin. As a normal user, pick the `Connect` radio in `TCP 스캔 타입`.
- NSE scripts missing in older nmap → nmap warns and skips them.
- IPv6-only hosts appear in the CSV `IP` column with their IPv6 address.

## License / Author

MIT — [LICENSE](./LICENSE) · [@patissierMongs](https://github.com/patissierMongs)
