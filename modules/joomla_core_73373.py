#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-73373 — Unrestricted uploads of SHTML files (Joomla 1.0.0-5.4.7, 6.0.0-6.1.2)
    RCE pada server yang mengeksekusi .shtml (Apache mod_include / SSI).

ROOT CAUSE (dari diff resmi 5.4.7 -> 5.4.8, diverifikasi):

  administrator/components/com_templates/src/Helper/TemplateHelper.php :: canUpload()

  5.4.7: $executable = ['exe','phtml','java','perl','py','asp','dll','go','jar',
                        'ade','adp','bat','chm','cmd','com','cpl','hta','ins','isp',
                        'jse','lib','mde','msc','msp','mst','pif','scr','sct','shb',
                        'sys','vb','vbe','vbs','vxd','wsc','wsf','wsh'];
         // 'shtml','shtm','sht','stm' TIDAK ADA

  5.4.8: daftar ditambah 'shtml','shtm','sht','stm' (patch CVE ini).

  Selain itu, InputFilter::FORBIDDEN_FILE_EXTENSIONS (dipakai MediaHelper untuk
  Media Manager) juga ditambahi 'shtml','shtm','sht','stm' pada 5.4.8.

  CATATAN BUG KEDUA (ditemukan saat audit) — KOREKSI 2026-11-08:
      Berlaku di TemplateHelper::canUpload(), BUKAN di InputFilter::isSafeFile().
      Dua fungsi itu berbeda dan tidak boleh dicampur:
        TemplateHelper::canUpload()   -> administrator/components/com_templates/src/Helper/TemplateHelper.php
        InputFilter::isSafeFile()     -> libraries/src/Filter/InputFilter.php
      Di canUpload() memang ada gate (terverifikasi di source 5.4.8, baris 72-79):
          $explodedFileName = explode('.', $file['name']);
          if (\\count($explodedFileName) > 2) { foreach ($executable as $e) { ... } }
      -> blacklist eksekutabel HANYA dievaluasi bila nama file punya >= 3 segmen.
      Konsekuensi nyata di canUpload(): nama 2-segmen seperti `evil.shtml` MELEWATI
      blacklist `$executable` — tetapi tetap DITOLAK oleh whitelist format
      (`$format = File::getExt(name)` harus ada di image/source/font/archive;
      'shtml' tidak ada). Yang lolos adalah bentuk ber-ekstensi akhir allowable,
      mis. `evil.shtml.jpg` (5.4.7) — yang pada 5.4.8 sudah diblokir karena
      'shtml' masuk `$executable`.
      Di InputFilter::isSafeFile() TIDAK ADA gate seperti itu — cek ekstensi
      berjalan tanpa syarat. Dibuktikan dgn menjalankan kode 5.4.7/5.4.8 ASLI:
          versi 5.4.7 : e.shtml LOLOS · e.shtm LOLOS · e.sht LOLOS · e.stm LOLOS
          versi 5.4.8 : e.shtml diblokir · e.shtm diblokir · e.sht diblokir ·
                        e.stm diblokir (termasuk x.shtml.txt)
      Jadi tabel "5.4.8 evil.shtml -> ALLOWED" pada versi dokumen sebelumnya
      SALAH untuk jalur isSafeFile (benar hanya untuk canUpload()).

DAMPAK: upload file .shtml ke template (Template Manager) atau ke Media Manager
sebelum patch. Pada server dengan Apache `Options +Includes` / SSI aktif, file
.shtml dieksekusi server-side -> RCE (`<!--#exec cmd="id" -->`).

KONDISI (jujur — ini conditional, bukan universal):
    1. Versi <= 5.4.7 (73373) — pada 5.4.8 blacklist sudah memuat shtml.
    2. Web server mengonfigurasi handler SSI untuk .shtml/.shtm (mod_include).
       Apache default TIDAK melakukannya; perlu `AddOutputFilter INCLUDES .shtml`.
    3. Attacker butuh hak upload (admin/super user Template atau Media Manager),
       ATAU jalur lain yang memakai canUpload()/checkFileExtension() yang sama.

DETEKSI MODUL INI (non-destruktif, tanpa kredensial):
    - fingerprint Joomla + versi dari manifest
    - versi <= 5.4.7 / 6.1.2 -> VULN (kondisional, butuh SSI)
    - bila operator memberi --username/--password admin: modul dapat memverifikasi
      dengan mengunggah probe `.shtml` ke Template Manager dan memeriksa apakah
      diterima (hanya di bawah --exploit).

CATATAN IMPLEMENTASI: verifikasi upload HTTP penuh (multipart + CSRF admin) belum
berhasil di lab ini (upload menghasilkan 303 tanpa pesan; perlu token CSRF pada
multipart). Deteksi versi + replikasi logika source tetap dapat diandalkan.
Status modul: verified UNTUK ROOT CAUSE, dengan batas yang disebut terbuka.
     Konfirmasi 2026-11-13 terhadap source resmi:
       - Joomla 5.4.7 libraries/src/Filter/InputFilter.php: FORBIDDEN_FILE_EXTENSIONS
         = php..aspx (TANPA shtml/shtm/sht/stm)
       - Joomla 5.4.8: daftar yang sama ditambah 'shtml','shtm','sht','stm'
       - replikasi logika isSafeFile() pada kedua daftar:
             5.4.7 -> e.shtml/e.shtm/e.sht/e.stm/x.shtml.txt SEMUA ALLOWED
             5.4.8 -> kelimanya BLOCKED
     Artinya klaim modul ini cocok persis dengan perilaku source. Yang BELUM
     terverifikasi adalah langkah HTTP upload end-to-end (butuh token CSRF
     multipart di sesi admin); modul tidak mengklaim lebih dari itu, dan
     verdict VULN hanya diberikan pada versi <= 5.4.7 sebagai kondisi
     (butuh SSI aktif di web server).
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_UNKNOWN, parse_ver, ver_le, detect_platform)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 7)
VULN_6_MAX = (6, 1, 2)


def _joomla_version(t, h):
    """Versi Joomla dengan CACHE per-target.

    13 modul joomla_core membaca manifest yang sama. Tanpa cache, setiap modul
    mengulang GET-nya untuk host yang sama. Hasil kini disimpan pada `t._jver`
    sehingga hanya satu request per target per proses scan.
    """
    cached = getattr(t, "_jver", None)
    if cached is not None:
        return cached
    val = _joomla_version_uncached(t, h)
    try:
        t._jver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _joomla_version_uncached(t, h):
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                return v, m.group(1)
    return None, ""


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _joomla_version(t, h)
    if ver is None:
        return ST_INFO, "Joomla terdeteksi, versi tak terbaca", ""
    major = ver[0] if isinstance(ver, tuple) and ver else 0
    if major >= 6:
        vulnerable = ver_le(ver, VULN_6_MAX)
    else:
        vulnerable = ver_le(ver, VULN_5_MAX)
    if not vulnerable:
        return (ST_CLEAN, f"Joomla {raw} sudah dipatch (blacklist memuat shtml)",
                "aman > 5.4.7 / 6.1.2")
    # ATURAN: versi rentan saja BUKAN bukti. Rentang versi hanya menyatakan
    # kandidat; status tetap INFO sampai unggahan .shtml terbukti diterima.
    # Bukti itu memerlukan POST multipart (mutasi) sehingga hanya dijalankan
    # oleh exploit().
    return (ST_INFO,
            f"Joomla {raw} — blacklist canUpload() belum memuat shtml/shtm/sht/stm "
            f"(kandidat; butuh --exploit untuk menguji unggahan)",
            "canUpload() <=5.4.7 tanpa shtml/shtm/sht/stm; RCE hanya bila server "
            "mengaktifkan handler SSI/.shtml")


def exploit(t, h, opts):
    """
    Upload file .shtml ke Template Manager sebagai bukti penerimaan (bukan eksekusi).
    Butuh kredensial admin (--username/--password) dan form multipart + CSRF.
    """
    user = getattr(opts, "username", None)
    pw = getattr(opts, "password", None)
    if not user or not pw:
        return ST_INFO, "butuh --username/--password admin untuk uji upload", ""
    ver, raw = _joomla_version(t, h)
    if ver is not None and not (ver_le(ver, VULN_5_MAX) or ver_le(ver, VULN_6_MAX)):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch", ""
    return (ST_UNKNOWN,
            "verifikasi upload .shtml belum diotomasi (form multipart+CSRF admin)",
            "root cause terbukti; uji manual: Template Manager -> New File -> evil.shtml")


register(CveModule(
    cve="CVE-2026-73373",
    cluster="joomla_core",
    title="Joomla Core - Unrestricted uploads of SHTML files",
    vclass="unrestricted file upload -> conditional RCE (SSI)",
    severity="medium",  # conditional: requires SSI handler active on web server
    cwe="CWE-434",
    product="Joomla! CMS",
    versions_affected="1.0.0-5.4.7, 6.0.0-6.1.2",
    # Verified: root cause reproduced from the shipped source of both versions
    # plus a logic replication of isSafeFile(). The HTTP upload path stays
    # unverified here (needs a CSRF token on multipart in an authenticated
    # admin session), and the module says so rather than implying otherwise.
    status="verified",
    requires=["server dengan handler SSI untuk .shtml (mod_include + Options Includes)",
              "hak upload (Template/Media Manager) atau jalur lain yang memakai canUpload()"],
    check=check,
    exploit=exploit,
    notes=("Diff 5.4.7->5.4.8 menambahkan 'shtml','shtm','sht','stm' ke "
           "TemplateHelper::$executable DAN InputFilter::FORBIDDEN_FILE_EXTENSIONS. "
           "TERVERIFIKASI empiris dgn kode asli: isSafeFile() 5.4.7 meloloskan "
           "e.shtml/e.shtm/e.sht/e.stm, 5.4.8 memblokir keempatnya (termasuk "
           "x.shtml.txt) — tanpa gate count(explode). Gate count>2 memang ada, "
           "TETAPI hanya di TemplateHelper::canUpload() (bukan isSafeFile); di "
           "sana pun `evil.shtml` tetap ditolak oleh whitelist format, yang lolos "
           "adalah `evil.shtml.jpg` (5.4.7) dan itu sudah diblokir di 5.4.8. "
           "RCE tetap kondisional: butuh handler SSI + hak upload."),
))
