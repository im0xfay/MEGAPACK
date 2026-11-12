#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-35222 — com_tags ordering: NOT an exploitable SQL injection.

VERDICT: documented, not verified. There is no exploit() here on purpose.

The advisory ("com_tags filter_order SQL injection") does not hold up. The only
change attributed to this CVE is the removal of

    onchange="document.adminForm.submit()"

from three templates (components/com_tags/tmpl/tag/default_items.php,
tag/list_items.php, tags/default_items.php) between 5.4.5 and 5.4.7. That is UI
hardening, not a server-side fix.

Evidence gathered in the lab:

  * components/com_tags/src/Model/TagModel.php is byte-identical across
    5.4.0 / 5.4.5 / 5.4.7 / 5.4.8 / 5.4.9 / 5.4.10 (md5 5bdfac59...).
  * libraries/src/Helper/TagsHelper.php is identical between 5.4.5 and 5.4.8.
  * The server-side whitelist has existed since Joomla 4.1.0:

        if (!in_array($orderCol, $this->filter_fields)) $orderCol = 'c.core_title';
        if (!in_array(strtoupper($listOrder), ['ASC', 'DESC', ''])) $listOrder = 'ASC';

    filter_fields is a fixed list of core_* columns plus match_count, and
    match_count reaches the query as COUNT(`m`.`tag_id`) after quoteName.

Live test on 5.4.5 with ORDERS instrumentation in TagsHelper::getTagItemsQuery
captured the ORDER BY that actually ran:

    filter_order_Dir=ASC, (SELECT 1)      -> MAX(`core_title`) ASC   (fallback)
    filter_order_Dir=ASC AND SLEEP(3)     -> MAX(`core_title`) ASC   (fallback)
    filter_order=core_alias               -> MAX(`c`.`core_title`) ASC (fallback)
    filter_order=match_count              -> COUNT(`m`.`tag_id`) ASC (valid, whitelisted)
    filter_order=(SELECT 1)               -> request rejected / empty

No non-whitelisted value ever reached the ORDER BY clause.

Full analysis: notes/CVE-2026-35222-analysis.md
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

# Dua versi yang dibandingkan: sebelum & sesudah template diubah.
PATCH_VER = (5, 4, 6)
WHITELIST_SINCE = (4, 1, 0)

TAGS_MODEL = "/components/com_tags/src/Model/TagModel.php"
TAG_TMPL = "/components/com_tags/tmpl/tags/default_items.php"


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
    r = h.get(f"{t.url}/administrator/manifests/files/joomla.xml")
    if r is not None and r.status_code == 200 and "<version>" in (r.text or ""):
        m = re.search(r"<version>\s*([0-9][0-9.]*)", r.text)
        if m:
            v = parse_ver(m.group(1))
            if v:
                return v, m.group(1)
    return None, ""


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    """
    Tidak ada oracle exploit yang bermakna: tidak ada modul exploit. `check`
    hanya melaporkan apakah versi berada di rentang yang diklaim, plus apakah
    template masih memuat onchange autosubmit (penanda jalur 'belum di-harden').
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""

    if ver < WHITELIST_SINCE:
        return (ST_UNKNOWN,
                f"Joomla {ver_s} < 4.1.0 — varian lama, belum dianalisis",
                f"version={ver_s}")

    r = h.get(f"{t.url}{TAG_TMPL}")
    ui = "tidak diketahui"
    if r is not None and r.status_code == 200:
        ui = "ada onchange autosubmit" if "onchange=\"document.adminForm.submit" in (r.text or "") \
             else "tidak ada onchange"

    detail = (f"Joomla {ver_s} — dilaporkan rentan (patch 5.4.5->5.4.7); "
              f"whitelist server-side aktif sejak 4.1.0; {ui}")
    return ST_INFO, detail, f"version={ver_s} ui={ui} exploit=not-reproducible"


register(CveModule(
    cve="CVE-2026-35222",
    cluster="joomla_core",
    title="Joomla Core - com_tags ordering (reported SQLi; not reproducible)",
    vclass="ui-hardening",
    cvss="",
    severity="",
    cwe="CWE-89",
    product="Joomla! Core (com_tags)",
    versions_affected="—",
    status="unsupported",
    requires=["—"],
    check=check,
    exploit=None,
    unsupported_reason=("Tidak reproducible: klaim SQLi kom_tags tidak punya "
                        "perbaikan kode. Patch 5.4.7 hanya UI (hapus onchange "
                        "autosubmit); TagModel.php identik byte-per-byte di "
                        "5.4.5/5.4.7/5.4.8; filter_order & filter_order_Dir "
                        "divalidasi allowlist (filter_fields + ASC/DESC)"),
    notes=("VERDICT unsupported (triase 2026-11-08). Bukti: (1) md5 TagModel.php "
           "identik di j545/j547/j548 -> tak ada yang diperbaiki di model, jadi "
           "'patch di 5.4.7' tidak konsisten dgn klaim SQLi; (2) diff 5.4.5->5.4.7 "
           "hanya menyentuh tmpl Comtags (onchange=\"document.adminForm.submit()\" "
           "dihapus) = UI hardening; (3) diff com_tags/src 5.4.5->5.4.8 = kosong; "
           "(4) satu-satunya jalur ordering: TagModel.php:234-250 -> "
           "if(!in_array($orderCol,$this->filter_fields)) reset; "
           "if(!in_array(strtoupper($listOrder),['ASC','DESC',''])) reset; "
           "plus DisplayController.php memfilter filter_order/_Dir sbg CMD; "
           "(5) allowlist sudah ada di 4.1.0 (j410:242)."),
))
