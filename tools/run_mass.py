#!/usr/bin/env python3
"""Batch runner MEGAPACK untuk daftar target besar (ratusan ribu).

Masalah mp.py biasa: semua target di-submit sekaligus ke ThreadPoolExecutor,
sehingga 300k URL berarti 300k Future hidup bersamaan + tidak ada output
sampai proses selesai. Runner ini memecah daftar jadi wave, menulis hasil
INCREMENTAL (bisa dilihat/di-resume), dan menampilkan throughput.

Pakai:
  python3 tools/run_mass.py joomla.txt --cluster joomla_core \\
      --threads 96 --timeout 6 --out massrun/hasil.jsonl

Sifat: DETECT-ONLY (tidak pernah memanggil exploit).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mp  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_targets(path: str) -> list:
    out, seen = [], set()
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for ln in f:
            v = ln.strip().strip('"').strip("'").strip()
            if not v or v.startswith("#"):
                continue
            u = mp.norm_url(v)
            k = u.rstrip("/").lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(u)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets_file")
    ap.add_argument("--cluster", default=None)
    ap.add_argument("--cve", action="append", default=None,
                    help="batasi ke CVE tertentu (boleh diulang)")
    ap.add_argument("--threads", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--out", default="massrun/hasil.jsonl")
    ap.add_argument("--resume", action="store_true",
                    help="lewati target yang sudah ada di --out")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--wave", type=int, default=2000,
                    help="jumlah target per wave (batasi memori)")
    args = ap.parse_args()

    mp.load_modules(os.path.join(HERE, "modules"))
    targets = load_targets(args.targets_file)
    if args.limit:
        targets = targets[: args.limit]

    done = set()
    if args.resume and os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            for ln in f:
                try:
                    done.add(json.loads(ln)["url"].rstrip("/").lower())
                except Exception:
                    pass
    if done:
        before = len(targets)
        targets = [t for t in targets if t.rstrip("/").lower() not in done]
        print(f"[*] resume: {before - len(targets)} dilewati, {len(targets)} tersisa")

    mods = mp.selected_modules(argparse.Namespace(cve=args.cve, cluster=args.cluster))
    if not mods:
        print("[!] tidak ada modul cocok")
        return 1
    print(f"[*] modul: {len(mods)} | target: {len(targets)} | threads: {args.threads}")
    print(f"[*] output: {args.out} (append, JSONL)")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    ns = argparse.Namespace(
        timeout=args.timeout, proxy=None, verify_tls=False, verbose=False,
        delay=args.delay, exploit=False, i_know_what_im_doing=False, cve=args.cve,
        cluster=args.cluster, threads=args.threads, api_token=None, username=None,
        password=None, field_id=None, contact_id=None, membership=None,
        category_id=None, category_ext=None, shell_url=None, username_role=None)

    hits = 0
    seen_n = 0
    t0 = time.time()
    with open(args.out, "a", encoding="utf-8") as fo:
        for start in range(0, len(targets), args.wave):
            wave = targets[start: start + args.wave]
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futs = {ex.submit(mp.run_target, x, ns): x for x in wave}
                for fut in as_completed(futs):
                    try:
                        t = fut.result()
                    except Exception as e:  # noqa: BLE001
                        t = mp.Target(url=futs[fut])
                        t.notes.append(f"fatal: {type(e).__name__}")
                    seen_n += 1
                    rec = {
                        "url": t.url,
                        "platform": t.platform,
                        "joomla_version": (".".join(map(str, t.joomla_version))
                                           if t.joomla_version else None),
                        "wp_version": (".".join(map(str, t.wp_version))
                                       if t.wp_version else None),
                        "notes": t.notes,
                        "findings": t.results,
                    }
                    severe = [c for c, f in t.results.items()
                              if f.get("status") in (mp.ST_VULN, mp.ST_RCE, mp.ST_PWN)]
                    if severe:
                        hits += 1
                        rec["severe"] = severe
                        print(f"[+] {t.url}  " + " ".join(severe), flush=True)
                    fo.write(json.dumps(rec) + "\n")
                    if seen_n % 200 == 0:
                        fo.flush()
                        el = time.time() - t0
                        rate = seen_n / el if el else 0
                        eta = (len(targets) - seen_n) / rate / 3600 if rate else 0
                        print(f"  [{seen_n}/{len(targets)}] {rate:.1f} t/s "
                              f"ETA {eta:.1f}j | VULN host: {hits}", flush=True)
            fo.flush()
    el = time.time() - t0
    print(f"\n[*] selesai: {seen_n} target dalam {el/60:.1f} menit "
          f"({seen_n/el:.1f} t/s) | host VULN: {hits}")
    print(f"[*] hasil: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
