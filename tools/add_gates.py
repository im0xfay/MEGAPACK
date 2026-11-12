#!/usr/bin/env python3
"""Tambah gate detect_platform ke modul check() yang belum punya."""
import pathlib
import re

GATE_JOOMLA = (
    '    plat = detect_platform(t, h)\n'
    '    if plat not in ("joomla", "unknown"):\n'
    '        return ST_SKIP, "bukan Joomla", f"platform={plat}"\n'
)
GATE_WP = (
    '    plat = detect_platform(t, h)\n'
    '    if plat not in ("wordpress", "unknown"):\n'
    '        return ST_SKIP, "bukan WordPress", f"platform={plat}"\n'
)

TARGETS = {
    "modules/joomla_core_23899.py": "joomla",
    "modules/joomla_core_35221.py": "joomla",
    "modules/joomla_core_35222.py": "joomla",
    "modules/joomla_core_35223.py": "joomla",
    "modules/joomla_core_40383.py": "joomla",
    "modules/joomla_core_40384.py": "joomla",
    "modules/joomla_core_73371_73372.py": "joomla",
    "modules/joomla_core_90913.py": "joomla",
    "modules/joomla_core_92227.py": "joomla",
    "modules/wp_everest_forms.py": "wp",
    "modules/wp_pods.py": "wp",
    "modules/wp_profile_builder.py": "wp",
    "modules/wp_translatepress.py": "wp",
    "modules/wp_ultimate_member.py": "wp",
    "modules/wp_user_registration.py": "wp",
}


def ensure_imports(s: str, need: list) -> str:
    m = re.search(r"from mp import \(([^)]*)\)", s)
    if m:
        cur = [x.strip() for x in m.group(1).replace("\n", " ").split(",") if x.strip()]
        for n in need:
            if n not in cur:
                cur.append(n)
        s = s[: m.start()] + "from mp import (" + ", ".join(sorted(set(cur))) + ")" + s[m.end():]
        return s
    m2 = re.search(r"^from mp import (.+)$", s, re.M)
    if m2:
        cur = [x.strip() for x in m2.group(1).split(",") if x.strip()]
        for n in need:
            if n not in cur:
                cur.append(n)
        s = s[: m2.start()] + "from mp import " + ", ".join(sorted(set(cur))) + s[m2.end():]
        return s
    return s


def main() -> None:
    for fn, kind in TARGETS.items():
        p = pathlib.Path(fn)
        s = p.read_text()
        m = re.search(r"def check\(t, h[^)]*\):\n", s)
        if not m:
            print("  SKIP (tak ada def check):", fn)
            continue
        if "detect_platform" in s[m.end(): m.end() + 1500]:
            print("  sudah bergate:", fn)
            continue
        gate = GATE_JOOMLA if kind == "joomla" else GATE_WP
        s = s[: m.end()] + gate + s[m.end():]
        need = []
        head = s.split("def check", 1)[0]
        if "detect_platform" not in head:
            need.append("detect_platform")
        if "ST_SKIP" not in head:
            need.append("ST_SKIP")
        if need:
            s = ensure_imports(s, need)
        p.write_text(s)
        print("  gate ditambah:", fn, "| import:", need or "-")


if __name__ == "__main__":
    main()
