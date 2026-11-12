#!/usr/bin/env python3
"""Verifikasi ulang temuan VULN dari mass scan.

Ambil setiap (host, CVE) berstatus VULN dari hasil scan, lalu jalankan modul itu
SATU KALI lagi terhadap host tersebut. Tujuan: memisahkan temuan yang stabil
dari yang flaky/transien (target mati saat scan, halaman error, CDN challenge).

Pakai:
  python3 tools/verify_hits.py massrun/s1500.txt
  python3 tools/verify_hits.py massrun/s1500.txt --repeat 3
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mp  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINE_RX = re.compile(r"^(VULN|RCE|PWN)\s+(CVE-[0-9-]+)\s+(\S+)")


def parse(path: str) -> list:
    hits = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = LINE_RX.match(ln.strip())
            if m:
                hits.append((m.group(2), m.group(3)))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scan_output", help="stdout mass scan (satu baris per temuan)")
    ap.add_argument("--repeat", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--threads", type=int, default=32)
    args = ap.parse_args()

    mp.load_modules(os.path.join(HERE, "modules"))
    hits = parse(args.scan_output)
    print(f"[*] temuan VULN dari scan: {len(hits)}")
    if not hits:
        return 0

    stats = collections.Counter()
    stable, flaky = [], []
    for cve, url in hits:
        mod = mp.REGISTRY.get(cve)
        if mod is None:
            stats["modul-tidak-ada"] += 1
            continue
        try:
            t = mp.run_target(url, argparse.Namespace(
                timeout=args.timeout, proxy=None, verify_tls=False, verbose=False,
                delay=0.0, exploit=False, i_know_what_im_doing=False, cve=[cve],
                cluster=None, threads=1, api_token=None, username=None, password=None,
                field_id=None, contact_id=None, membership=None, category_id=None,
                category_ext=None, shell_url=None, username_role=None))
        except Exception:  # noqa: BLE001
            stats["error"] += 1
            continue
        seen = collections.Counter()
        for _ in range(args.repeat):
            try:
                st, _d, _e = mod.check(t, mp.Http(timeout=args.timeout), None)
            except Exception:  # noqa: BLE001
                st = "ERR"
            seen[st] += 1
        if seen.get(mp.ST_VULN):
            stable.append((cve, url, dict(seen)))
            stats["STABIL"] += 1
        else:
            flaky.append((cve, url, dict(seen)))
            stats["FLAKY"] += 1

    print("\n=== STABIL (VULN bertahan setelah diulang) ===")
    for cve, url, seen in stable:
        print(f"  {cve}  {url}  {seen}")
    print("\n=== FLAKY (tidak reproduksi) ===")
    for cve, url, seen in flaky:
        print(f"  {cve}  {url}  {seen}")
    print(f"\n[*] ringkasan: {dict(stats)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
