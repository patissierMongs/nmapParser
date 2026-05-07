#!/usr/bin/env python3
import csv
from pathlib import Path

import nmapParser as np

REQUESTED = [
    "chargen","ftp","ssh","telnet","smtp","dns","tftp","http","https","rpcbind","ntp",
    "microsoft-ds","snmp","irc","914c-g","cldap","rcp","rlogin","rsh","lpd","cadlock2",
    "webpush","ipcserver","dbms","vmrdp","rdp","vnc","ajp","ftp-proxy","echo","ipsec-nat-t","syslog","sip"
]

DBMS_KEYS = {"mysql","mariadb","postgresql","postgres","ms-sql-s","oracle-tns","mongodb","redis","db2"}


def main():
    out = Path("service_checklist.csv")
    catmap = np.default_categories_as_map()
    guide = np.SERVICE_EXPOSURE_GUIDE

    rows = []
    for req in REQUESTED:
        if req == "dbms":
            keys = sorted(DBMS_KEYS)
        elif req == "ajp":
            keys = ["ajp", "ajp13"]
        elif req == "rsh":
            keys = ["rsh", "shell"]
        else:
            keys = [req]
        present_keys = [k for k in keys if k in guide or k in catmap]
        rows.append([req, ",".join(keys), bool(present_keys), ",".join(present_keys)])

    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["요청서비스", "매핑키", "반영여부", "발견키"])
        w.writerows(rows)
    print(out)


if __name__ == "__main__":
    main()
