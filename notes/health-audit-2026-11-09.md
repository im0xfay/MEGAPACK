# Health audit MEGAPACK — 2026-11-09

Permintaan operator: "beresin, pastikan semua jalan baik; yang tidak bisa di-skip,
jangan digabung." Hasil: **framework sehat, tidak ada modul rusak**.

## Metode (2 lapis, lab tidak diganggu)

1. **Dummy-server sweep** (`scratchpad/health_sweep.py`): server lokal :18099
   membalas 200 generik; panggil `check()` tiap modul dgn timeout keras per-modul.
   Tujuan: deteksi crash/hang, bukan uji kerentanan.
   → **58 modul (punya check, non-alias): 0 CRASH, 0 HANG.** Semua return status valid.

2. **Scan read-only lab hidup** (44 container, `mp.py --targets`, tanpa `--exploit`
   → non-mutasi, sesuai jaminan purity):
   → `44 target | SKIP=1511 CLEAN=1001 INFO=205 VULN=134 UNKNOWN=9` — **0 ERR**.

## Matriks per-modul (status tertinggi lintas 44 target)

- **21 modul VULN** terbukti di lab (2015-7857, 8562, 2016-8869, 2017-8917, 18-11322,
  19-10945, 20-10238/24597, 21-23132, 23-23752, 25-15030/2594, 26-19598/35221/48899/
  48907/48908/48909/67365/74251/76570).
- **23 modul INFO-only**: by design — `check()` mendeteksi komponen, verdict akhir
  butuh `--exploit`/kredensial/`--api-token`. Bukan kerusakan.
- **14 modul tak menyala VULN/INFO**: diverifikasi **CLEAN jujur** —
  - 2 `unsupported` (35222, 62103) → SKIP bersih (tetap tidak digabung).
  - 12 `verified` CLEAN/UNKNOWN karena **fixture lab sudah dipatch / di luar rentang**:
    TranslatePress 3.3.9, BLC 2.4.15, Joomla core 5.4.5–5.4.8. Spot-check: modul
    membaca versi dgn benar lalu menyimpulkan tidak-rentan. Modul bekerja sempurna.

**Kesimpulan:** tidak ada yang perlu di-skip/disable — arsitektur sudah mengisolasi
kegagalan (`try/except check()/exploit() → ST_ERR`) dan SKIP otomatis untuk
alias + unsupported-with-reason. Tidak ada modul yang menggagalkan run lain.

## Bug yang ditemukan & diperbaiki

**`plugin_installed()` InvalidURL** (mp.py): beberapa modul WP mengirim `ASSET`
tanpa `/` di depan (mis. `"translatepress-multilingual/index.php"`,
`"broken-link-checker/broken-link-checker.php"`) → `t.url + asset` jadi
`http://hostslug/...` = `InvalidURL`, 1 error sia-sia tiap scan WP modul tsb.
Fix: normalisasi leading-slash terpusat di `plugin_installed` (menutup semua
pemanggil; verdict tak berubah krn fallback readme/CHANGELOG tetap jalan).
Bukti: scan 8103/8104 `1 error → 0 error`, verdict CLEAN identik. ruff bersih,
kontrak 65 modul OK.

## Sisa (bukan blocker)

- File kosong `2` dan `3` (0 byte) di root project — artefak redirect shell nyasar,
  bukan bagian tool. Aman dihapus (belum dihapus; nunggu konfirmasi).
