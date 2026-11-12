# Self-Attack MEGAPACK — 2026-11-07

Serangan terhadap tool sendiri: 10 skenario kegagalan di lapangan.

| # | Skenario | Sebelum | Sesudah |
|---|---|---|---|
| 1 | Host tidak resolve (DNS mati) | **hang 63s**, 14 request, 7 error, tanpa output | `SKIP` + `host tidak terjangkau (pre-flight)`, **0 request** |
| 2 | Port mati (connection refused) | cepat, `SKIP` | tidak berubah ✅ |
| 3 | URL tanpa skema (`127.0.0.1:8106`) | auto-prefix `http://` | tidak berubah ✅ |
| 4 | TLS ditolak / `SSLError` | diretry penuh | fast-fail |
| 5 | `--exploit` tanpa izin | ditolak | tidak berubah ✅ |
| 6 | CVE tidak dikenal | pesan jelas, exit 1 | tidak berubah ✅ |
| 7 | JSON out (`-o`) | valid, 2 entri | tidak berubah ✅ |
| 8 | Batch besar, TTY | tanpa umpan balik → tampak hang | **progress `[i/N]`** |
| 9 | Batch besar, non-TTY | tanpa progress (benar) | tidak berubah ✅ |
| 10 | Semua 28 modul pada 1 target | 2.6s, hasil konsisten | tidak berubah ✅ |

## Perbaikan yang di-commit

1. **`Http._fatal_transport()`** — `NameResolutionError`, `InvalidURL`, `SSLError`,
   `ProxyError`, `ConnectionError`, `Max retries exceeded` **tidak diretry**; mengulang
   error deterministik hanya menambah satu timeout penuh per percobaan.
2. **`_host_unreachable()` pre-flight** di `prep_target()` — satu `getaddrinfo()` murah
   memutus biaya DNS; seluruh modul target itu di-`SKIP` tanpa satu pun request.
3. **Progress counter** `[i/N]` ke stderr, hanya bila TTY — batch besar tetap terlihat
   hidup, output non-TTY (pipeline) tidak terkotori.

## Sisa risiko (belum ditutup)

- **Resolver OS lambat** (15s per nama gagal) tidak bisa dipercepat dari dalam tool tanpa
  resolver kustom. Dengan `-t 8` paralel, 250 nama gagal ≈ 8 menit. Diterima, bukan hang.
- **`--threads` belum diuji pada 250 target nyata** — perlu run mass berikutnya.
- **Rate limiting belum adaptif** — `--delay` statis; belum ada back-off 429/503 global.

## Integrasi & rilis (lanjutan 2026-11-07)

### Mass mode — sudah ada sejak awal, diverifikasi
- `--targets <file>` (satu URL per baris, `#` komentar), `-u` boleh diulang, digabung.
- Threading `-t 8` via `ThreadPoolExecutor`; hasil diurutkan per URL sebelum output.
- `-o/--json-out` → array entri `{url, platform, plugins, findings, notes}`.
- Output operator: satu baris per temuan (`STATUS CVE url detail`) + baris bukti ringkas.
- Progress `[i/N]` ke stderr bila TTY.

### Rate limiting — ditambahkan
- `--delay <detik>` — jeda minimum antar-request **per target** (tiap worker punya `Http`
  sendiri, jadi delay tidak saling menahan antar-target).
- **Back-off adaptif** pada `429`/`503`: `_backoff` berlipat dua (batas 30s), UA diputar,
  lalu direlaksasi bertahap saat respons kembali normal. Dihitung sebagai `throttled=N`
  di baris catatan target sehingga operator tahu target membatasi laju.
- Bukti: server uji yang mengembalikan `429` tiga kali → `throttled=3`, back-off `1→2→4s`,
  request keempat `200`.

### WAF — belum
Belum ada WAF nyata di jalur uji (lab memakai Apache polos). Modul mengandalkan UA
rotation + delay + fast-fail; klaim "lolos WAF" **belum boleh** dibuat sampai diuji
terhadap ModSecurity/Cloudflare.
