#!/usr/bin/env python3
"""Re-verifikasi SELURUH temuan live dengan modul versi sekarang.

Temuan hasil scan bisa ditulis oleh versi modul yang lebih lama (bug deteksi
belum diperbaiki) atau bersifat flaky (host sempat membalas berbeda). Skrip ini
mengambil setiap pasangan (CVE, host) dari JSONL hasil scan, menjalankannya
ULANG dengan modul saat ini, lalu menulis daftar yang benar-benar lolos.

Pakai:
  python3 tools/reverify.py massrun/joomla_core_full.jsonl \\
      massrun/joomla_ext_full.jsonl --out massrun/verified.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mp  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOTED = {"CVE-2026-90907"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", nargs="+")
    ap.add_argument("--out", default="massrun/verified.jsonl")
    ap.add_argument("--threads", type=int, default=24)
    ap.add_argument("--timeout", type=float, default=12.0)
    args = ap.parse_args()

    mp.load_modules(os.path.join(HERE, "modules"))

    pairs = set()
    for path in args.jsonl:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                for cve, fnd in (r.get("findings") or {}).items():
                    if cve in DEMOTED:
                        continue
                    if fnd.get("status") in (mp.ST_VULN, mp.ST_RCE, mp.ST_PWN):
                        pairs.add((cve, r["url"]))
    print(f"[*] pasangan (CVE, host) untuk diverifikasi ulang: {len(pairs)}")

    def job(pair):
        cve, url = pair
        mod = mp.REGISTRY.get(cve)
        if mod is None:
            return pair, "SKIP", "modul tidak ada"
        ns = argparse.Namespace(
            timeout=args.timeout, proxy=None, verify_tls=False, verbose=False,
            delay=0.0, exploit=False, i_know_what_im_doing=False, cve=[cve],
            cluster=None, threads=1, api_token=None, username=None, password=None,
            field_id=None, contact_id=None, membership=None, category_id=None,
            category_ext=None, shell_url=None, username_role=None, new_password=None)
        try:
            t = mp.Target(url=mp.norm_url(url))
            h = mp.Http(timeout=args.timeout)
            mp.prep_target(t, h, ns)
            st, detail, ev = mod.check(t, h, ns)
            return pair, st, (detail or "")[:200]
        except Exception as e:  # noqa: BLE001
            return pair, "ERR", f"{type(e).__name__}: {e}"[:150]

    keep = collections.Counter()
    drop = collections.Counter()
    rows = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(job, p) for p in sorted(pairs)]
        for i, fut in enumerate(as_completed(futs), 1):
            (cve, url), st, detail = fut.result()
            if st in (mp.ST_VULN, mp.ST_RCE, mp.ST_PWN):
                keep[cve] += 1
                rows.append({"cve": cve, "url": url, "status": st, "detail": detail})
            else:
                drop[cve] += 1
            if i % 50 == 0:
                el = time.time() - t0
                print(f"  [{i}/{len(pairs)}] {i/el:.1f}/s | lolos={sum(keep.values())} "
                      f"gugur={sum(drop.values())}", flush=True)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in sorted(rows, key=lambda x: (x["cve"], x["url"])):
            f.write(json.dumps(r) + "\n")

    print("\n[*] hasil re-verifikasi")
    print(f"    LOLOS: {dict(keep)}")
    print(f"    GUGUR: {dict(drop)}")
    print(f"[*] output: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
