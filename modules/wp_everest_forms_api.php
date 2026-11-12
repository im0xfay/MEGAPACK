#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Everest Forms — tambahan modul (kelas PHP Object Injection).

CVE-2026-3296 (<= 3.4.3) — PHP Object Injection via unserialize() pada entry meta
    [documented: sink verified, jalur inject unauth TIDAK terbukti di lab]

Lihat modules/wp_everest_forms.py untuk CVE-2025-1128 (RCE, verified).

SINK (terverifikasi responsif):
    includes/admin/views/html-admin-page-entries-view.php:133
        $raw_meta_val = unserialize( $meta_value );            // tanpa allowed_classes
    Fix 3.6.0 -> evf_maybe_unserialize() (allowed_classes => false).

JEBAKAN (kenapa status = documented, bukan verified):
    Semua jalur tulis entry meta memakai maybe_serialize(), yang MEMBUNGKUS payload
    satu lapis lagi (WP: is_serialized($data,false) -> serialize($data)). Hasilnya
    unserialize() sekali hanya menghasilkan string/array, bukan objek.
    Butuh jalur tulis yang menyimpan serialized object VERBATIM + POP chain.

Modul ini hanya melakukan DETEKSI versi + verifikasi bahwa sink ada (via penanda
file statis pada source lokal tidak tersedia saat remote), sehingga statusnya
`documented` dan tidak melakukan eksploitasi.
"""
from __future__ import annotations

from mp import (CveModule, register, ST_VULN, ST_CLEAN, ST_INFO, ST_SKIP,
                ver_le, plugin_installed, plugin_version)

SLUG = "everest-forms"
ASSET = "everest-forms/everest-forms.php"
V_MAX = (3, 4, 3)


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def check(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "everest-forms tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "everest-forms ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if ver_le(ver, V_MAX):
        return ST_INFO, ("everest-forms %s <= 3.4.3: sink unserialize() tanpa "
                         "allowed_classes ada di admin entry view — status "
                         "documented (jalur inject unauth tidak terbukti; semua "
                         "jalur tulis memakai maybe_serialize yang membungkus "
                         "payload)" % vstr), ""
    return ST_CLEAN, ("everest-forms %s sudah dipatch (3.6.0: evf_maybe_unserialize "
                      "dengan allowed_classes=false)" % vstr), ""


def exploit(t, h, opts):
    return ST_SKIP, ("CVE-2026-3296 tidak dijalankan: sink terverifikasi tetapi "
                     "reachability dari attacker unauth tidak terbukti di lab "
                     "(maybe_serialize membungkus payload). Gunakan modul ini "
                     "untuk deteksi saja."), ""


def register_all():
    register(CveModule(
        cve="CVE-2026-3296", cluster="wordpress",
        title="Everest Forms <= 3.4.3 PHP Object Injection (entry view unserialize)",
        vclass="object-injection", cvss="8.8", severity="high", cwe="CWE-502",
        product="Everest Forms",
        versions_affected="<= 3.4.3",
        status="documented", check=check, exploit=exploit,
        notes="html-admin-page-entries-view.php:133 memanggil unserialize() tanpa "
              "allowed_classes pada nilai entry meta. Sink terbukti responsif "
              "(marker __wakeup jalan bila meta_value berisi objek serialized mentah). "
              "NAMUN setiap jalur tulis (class-evf-form-task.php:1329, "
              "evf-entry-functions.php:58) memakai maybe_serialize(), yang membungkus "
              "payload satu lapis lagi sehingga unserialize() sekali hanya "
              "menghasilkan string/array. Jalur inject unauth tidak direproduksi; "
              "status documented. Fix 3.6.0: evf_maybe_unserialize() dengan "
              "allowed_classes=false.",
    ))


register_all()
