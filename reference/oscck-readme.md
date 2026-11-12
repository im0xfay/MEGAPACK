# CVE-2026-102427 — OrdaSoft OS CCK (com_os_cck) unauthenticated upload RCE

Python 3 PoC for **[CVE-2026-102427](https://www.cve.org/CVERecord?id=CVE-2026-102427)** — **OrdaSoft Joomla CCK** — **unauthenticated RCE** via `task=getContent` → `site/uploader.php` (GIF/PHP polyglot, `.php` filename).

| | |
|---|---|
| **CVE.org** | https://www.cve.org/CVERecord?id=CVE-2026-102427 (**PUBLISHED** 2026-09-30) |
| **NVD** | https://nvd.nist.gov/vuln/detail/CVE-2026-102427 |
| **CNA** | Joomla! Project |
| **Component** | `com_os_cck` |
| **Affected** | **1.0.0 – 8.3.15** |
| **Fix** | **≥ 8.3.16** |
| **CWE** | **CWE-434** |
| **CVSS 4.0** | **10.0 Critical** — `AT:N` |

## Mechanism

Front-end **`task=getContent`** reaches **`site/uploader.php`** with no auth. Magic-byte image check passes on a **polyglot**; extension comes from the attacker filename (allow-list commented out in source). PoC uploads local **`up.php`** (GIF header + PHP) and verifies **`POCBIT-102427-OK`** via HTTP GET on the returned path.

## Requirements

- Python **3.9+**
- `pip install requests urllib3 colorama`

## Usage

```bash
cd CVE-2026-102427
python poc.py
python poc.py hits.txt
python poc.py --check fofa_hosts.txt
python poc.py -u https://site.tld
python poc.py --lab
python _engine.py --help
```

## Legal

Authorized security testing only.
