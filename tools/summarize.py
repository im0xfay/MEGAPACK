#!/usr/bin/env python3
"""Ringkas hasil mass scan JSONL menjadi laporan temuan live.

Membaca JSONL incremental dari tools/run_mass.py, mengelompokkan temuan,
menandai entri yang ditulis oleh versi modul lama, dan menulis laporan Markdown
yang jujur: hanya temuan dengan bukti objek yang dinaikkan sebagai temuan.

Pakai:
  python3 tools/summarize.py massrun/joomla_core_full.jsonl -o massrun/LIVE-report.md
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mp  # noqa: E402

# CVE yang statusnya TURUN setelah verifikasi lapangan. Entri lama (ditulis
# sebelum koreksi) dibiarkan di JSONL tetapi TIDAK dihitung sebagai temuan.
DEMOTED = {"CVE-2026-90907": "jalur terbuka, pembuatan akun tidak terbukti"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", nargs="+", help="satu atau lebih JSONL hasil run_mass")
    ap.add_argument("-o", "--out", default="massrun/LIVE-report.md")
    args = ap.parse_args()

    mp.load_modules(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules"))

    n = 0
    plat = collections.Counter()
    ver = collections.Counter()
    hits = collections.defaultdict(list)   # cve -> [(url, evidence)]
    demoted = collections.defaultdict(list)

    # Gabungkan beberapa pass (core + ext) dalam satu laporan; host yang sama
    # boleh muncul sekali per pass karena modulnya berbeda.
    for path in args.jsonl:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                try:
                    r = json.loads(ln)
                except Exception:
                    continue
                n += 1
                plat[r.get("platform") or "?"] += 1
                if r.get("platform") == "joomla" and r.get("joomla_version"):
                    ver[".".join(r["joomla_version"].split(".")[:2])] += 1
                for cve, fnd in (r.get("findings") or {}).items():
                    if fnd.get("status") not in (mp.ST_VULN, mp.ST_RCE, mp.ST_PWN):
                        continue
                    if cve in DEMOTED:
                        demoted[cve].append((r["url"], fnd.get("detail", "")))
                    else:
                        hits[cve].append((r["url"], fnd.get("detail", ""),
                                          fnd.get("evidence", "")))

    L = []
    L.append("# MEGAPACK — temuan live (joomla_core)")
    L.append("")
    L.append(f"Host dipindai: **{n}**")
    pj = plat.get("joomla", 0)
    L.append(f"Platform: Joomla **{pj}**, WordPress {plat.get('wordpress', 0)}, "
             f"unknown {plat.get('unknown', 0)}")
    L.append("")
    if ver:
        L.append("Versi Joomla terdeteksi (mayor.minor):")
        L.append("")
        for v, c in ver.most_common(12):
            L.append(f"- `{v}`: {c}")
        L.append("")

    L.append("## Temuan terverifikasi")
    L.append("")
    if not hits:
        L.append("_belum ada temuan dengan bukti objek._")
    for cve in sorted(hits, key=lambda c: -len(hits[c])):
        rows = hits[cve]
        mod = mp.REGISTRY.get(cve)
        title = mod.title if mod else cve
        L.append(f"### {cve} — {len(rows)} host")
        L.append("")
        L.append(f"{title}")
        L.append("")
        L.append("| Host | Bukti |")
        L.append("|---|---|")
        for url, _d, ev in rows[:40]:
            L.append(f"| {url} | { (ev or '')[:110] } |")
        if len(rows) > 40:
            L.append(f"| … +{len(rows)-40} lagi | |")
        L.append("")

    if demoted:
        L.append("## Turun status setelah verifikasi lapangan")
        L.append("")
        for cve, rows in demoted.items():
            L.append(f"### {cve} — {len(rows)} host (TIDAK dihitung)")
            L.append("")
            L.append(f"Alasan: {DEMOTED[cve]}")
            L.append("")
        L.append("")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print(f"[*] host: {n} | temuan: {sum(len(v) for v in hits.values())} "
          f"| diturunkan: {sum(len(v) for v in demoted.values())}")
    print(f"[*] laporan: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
