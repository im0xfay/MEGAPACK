#!/usr/bin/env python3
"""Cache versi Joomla per-target.

13 modul joomla_core masing-masing mendefinisikan `_joomla_version(t, h)` yang
melakukan GET manifest Joomla yang SAMA. Untuk 15 modul itu berarti 13+ request
redundan per host — pada mass scan ratusan ribu target itu biaya besar.

Skrip ini mengganti nama implementasi menjadi `_joomla_version_uncached` dan
menambahkan pembungkus `_joomla_version` yang menyimpan hasilnya pada atribut
`_jver` milik Target, sehingga pemanggilan berikutnya gratis.

Idempoten: modul yang sudah dipatch dilewati.
"""
from __future__ import annotations

import pathlib
import re

WRAPPER = '''def _joomla_version(t, h):
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


'''


def main() -> None:
    n = 0
    for p in sorted(pathlib.Path("modules").glob("joomla_core_*.py")):
        s = p.read_text()
        if "_joomla_version_uncached" in s:
            print("  sudah dipatch:", p.name)
            continue
        m = re.search(r"^def _joomla_version\(t, h[^)]*\):\n", s, re.M)
        if not m:
            print("  tanpa _joomla_version:", p.name)
            continue
        # ganti nama implementasi asli
        s = s[: m.start()] + "def _joomla_version_uncached(t, h):\n" + s[m.end():]
        # sisipkan wrapper tepat sebelum implementasi (urutan definisi tidak
        # masalah karena Python menyelesaikan nama saat dipanggil)
        s = s[: m.start()] + WRAPPER + s[m.start():]
        p.write_text(s)
        n += 1
        print("  dipatch:", p.name)
    print(f"  total: {n}")


if __name__ == "__main__":
    main()
