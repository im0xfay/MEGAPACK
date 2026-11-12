# modules/

Satu file Python per klaster atau per CVE. Setiap modul mendaftarkan CVE-nya
via `register(CveModule(...))` dari `mp.py`, atau mendefinisikan `register_all()`
untuk mendaftarkan beberapa CVE sekaligus.

## Kontrak fungsi

```python
def check(t, h, opts) -> tuple[str, str, str]:
    """Deteksi tanpa aksi destruktif. Return (status, detail, evidence)."""

def exploit(t, h, opts) -> tuple[str, str, str]:
    """Aksi destruktif (hanya dipanggil dgn --exploit). Return (status, detail, evidence)."""
```

- `t` : `mp.Target` — state target (url, plugins, results, ...)
- `h` : `mp.Http` — client HTTP
- `opts` : namespace argparse

## Status yang sah
`VULN` `RCE` `PWN` `INFO` `CLEAN` `SKIP` `ERR` `UNKNOWN`

Semua status harus berdasarkan pengamatan NYATA, bukan asumsi.
