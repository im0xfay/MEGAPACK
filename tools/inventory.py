#!/usr/bin/env python3
"""
Inventaris CVE massal. Query MITRE CVE API + NVD, simpan JSON per CVE.
Dipakai untuk fase 1 multi-CVE chaining: build per-CVE inventory.
"""
import concurrent.futures as cf
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; cve-inventory/1.0)"
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)          # root project (satu level di atas tools/)
OUT = os.path.join(PROJECT, "reference")


def get_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}"}


def mitre(cve):
    return get_json(f"https://cveawg.mitre.org/api/cve/{cve}")


def nvd(cve):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"cveId": cve})
    return get_json(url)


def parse_mitre(d):
    """Ambil field penting dari respons MITRE."""
    out = {}
    if not isinstance(d, dict) or "_error" in d or "_http_error" in d:
        return out
    cna = (d.get("containers") or {}).get("cna") or {}
    out["state"] = d.get("cveMetadata", {}).get("state")
    out["title"] = cna.get("title")
    descs = cna.get("descriptions") or []
    out["description"] = descs[0].get("value") if descs else None
    # versi terdampak
    aff = []
    for a in cna.get("affected") or []:
        prod = a.get("product") or a.get("packageName")
        vendor = a.get("vendor") or a.get("collectionURL")
        vers = []
        for v in a.get("versions") or []:
            if v.get("status") == "affected":
                if v.get("lessThan"):
                    vers.append(f"<{v['lessThan']}")
                elif v.get("version"):
                    vers.append(v["version"])
        aff.append({"vendor": vendor, "product": prod, "versions": vers[:6]})
    out["affected"] = aff[:5]
    # CWE
    cwes = []
    for p in cna.get("problemTypes") or []:
        for dd in p.get("descriptions") or []:
            if dd.get("cweId"):
                cwes.append(dd["cweId"] + " " + (dd.get("description") or ""))
    out["cwe"] = cwes[:4]
    # referensi
    out["refs"] = [r.get("url") for r in (cna.get("references") or [])][:8]
    # metrics / CVSS
    cv = []
    for m in cna.get("metrics") or []:
        for k, v in m.items():
            if isinstance(v, dict) and v.get("baseScore"):
                cv.append(f"{k}={v.get('baseScore')} {v.get('vectorString','')}")
    out["cvss_mitre"] = cv[:3]
    return out


def parse_nvd(d):
    out = {}
    if not isinstance(d, dict) or "_error" in d or "_http_error" in d:
        return out
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return out
    c = vulns[0].get("cve") or {}
    out["nvd_status"] = c.get("vulnStatus")
    out["nvd_published"] = c.get("published")
    descs = c.get("descriptions") or []
    out["nvd_description"] = next((x.get("value") for x in descs if x.get("lang") == "en"), None)
    m = c.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for e in m.get(key) or []:
            cd = e.get("cvssData") or {}
            if cd.get("baseScore"):
                out["cvss_nvd"] = f"{cd.get('baseScore')} {cd.get('vectorString','')}"
                out["cvss_severity"] = cd.get("baseSeverity") or e.get("baseSeverity")
                break
        if out.get("cvss_nvd"):
            break
    # CPE (produk)
    cfgs = c.get("configurations") or []
    cpes = []
    for cfg in cfgs:
        for n in cfg.get("nodes") or []:
            for cm in n.get("cpeMatch") or []:
                if cm.get("criteria"):
                    cpes.append(cm["criteria"])
    out["cpe"] = cpes[:5]
    out["nvd_refs"] = [r.get("url") for r in (c.get("references") or [])][:8]
    return out


def one(cve):
    t0 = time.time()
    m = mitre(cve)
    n = nvd(cve)
    rec = {
        "cve": cve,
        "mitre_found": bool(m and not m.get("_error") and not m.get("_http_error")),
        "nvd_found": bool(n and (n.get("vulnerabilities") or [])),
        "mitre_http": m.get("_http_error") if isinstance(m, dict) else None,
        "nvd_http": n.get("_http_error") if isinstance(n, dict) else None,
        "elapsed": round(time.time() - t0, 2),
    }
    rec.update(parse_mitre(m))
    rec.update(parse_nvd(n))
    return rec


def main():
    listfile = sys.argv[1] if len(sys.argv) > 1 else os.path.join(PROJECT, "cve-list.txt")
    with open(listfile) as f:
        cves = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    os.makedirs(OUT, exist_ok=True)

    results = []
    workers = int(os.environ.get("WORKERS", "6"))
    print(f"[*] {len(cves)} CVE, {workers} workers")
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, c): c for c in cves}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            c = futs[fut]
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"cve": c, "mitre_found": False, "nvd_found": False, "error": str(e)}
            results.append(rec)
            flag = "OK " if (rec.get("mitre_found") or rec.get("nvd_found")) else "MISS"
            print(f"  [{i:>3}/{len(cves)}] {flag} {c}")

    results.sort(key=lambda r: r["cve"])
    outfile = os.path.join(OUT, "inventory.json")
    with open(outfile, "w") as f:
        json.dump(results, f, indent=2)

    found = sum(1 for r in results if r.get("mitre_found") or r.get("nvd_found"))
    print(f"\n[+] ditemukan: {found}/{len(results)}")
    print(f"[+] -> {outfile}")


if __name__ == "__main__":
    main()
