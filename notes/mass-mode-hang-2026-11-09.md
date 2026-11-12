# Menu 6 (MASS) terlihat "tidak jalan" — root cause & fix (2026-11-09)

Laporan operator: daftar 300.000 target, menu 6 → mode explode (scan), **tidak ada
progress sama sekali**, seolah hang.

## Root cause (terukur, bukan dugaan)

`_namespace()` meneruskan setiap target ke argparse sebagai `-u <url>`.
`argparse.parse_args()` bersifat **kuadratik** terhadap jumlah argumen:

| jumlah target | waktu parse_args |
|---|---|
| 5.000 | 0,07 s |
| 10.000 | 0,23 s |
| 20.000 | 0,94 s |
| 300.000 | **>300 s (belum selesai)** |

Selama fase ini belum ada satu pun request keluar dan tidak ada output — dari sisi
operator identik dengan hang. Ditambah lagi `run_batch()` menahan SELURUH objek
`Target` di RAM sampai selesai (300k target × 45 modul ≈ 13 juta dict) dan progres
dicetak tiap 25 target (12.000 baris progress bar saat output dipipa).

## Perbaikan

1. **`_namespace()`**: target diset langsung ke `Namespace` (O(n)); argparse hanya
   memproses argumen kecil. Hasil ukur: 300.000 target = **0,011 s** (dari >300 s).
2. **`run_batch()` streaming** (`total > 5000`): hasil tidak ditahan; temuan dicetak
   & ditulis ke file seketika, status dihitung bertahap (`counts`).
3. **Progress**: 0,5 dtk sekali saat TTY; hanya tiap 5% saat dipipa. Tidak ada lagi
   ribuan baris bar.
4. **Estimasi** diberi label "batas-atas" (target mati gugur di pre-flight).
5. **Ringkasan** kini `N target | hasil modul: …` — sebelumnya `SKIP=270000` mudah
   disalahartikan sebagai jumlah target.

## Bukti

- Menu 6, 6.000 target (2 lab hidup + 5.998 mati), klaster WordPress, 24 thread:
  selesai **0,2–0,4 menit**, `VULN=1` ditemukan di 8190, file hasil 12 baris.
- CLI jalur kecil (3 target) tidak berubah: `3 target | SKIP=1 | VULN=1 | CLEAN=1`.
- Jalur streaming CLI (6.000 target): `6000 target | SKIP=5998 | VULN=1 | CLEAN=1`.
- `ruff` bersih, kontrak 65 modul OK.

## Pelajaran

- "Tidak ada output" bukan berarti thread macet: ukur fase persiapan (parse, submit,
  alokasi) secara terpisah sebelum menyalahkan jaringan.
- Semua yang O(n²) akan menabrak daftar besar: argv argparse, progress per-item,
  dan akumulasi objek hasil.

---

## Tambahan: throughput & rantai scan→exploit (permintaan operator)

### Apakah thread 50 + timeout 12 mempercepat?

Terukur pada **200 target hidup** (lab loopback), 1 modul:

| threads | waktu scan | waktu chain |
|---|---|---|
| 8 | 12,5 s (6000 target campuran) | — |
| 12 | 9 s | 9 s |
| 25 | — | — |
| 50 | 8 s | 8 s |

Kesimpulan: **thread membantu sampai ~25, lalu mendatar.** Penyebabnya bukan thread
pool, tapi tiap target menjalankan beberapa request **berurutan** (pre-flight →
deteksi platform → versi → check), jadi latensi per target tidak bisa diparalelkan
lagi oleh thread tambahan. Pada host mati, thread malah tidak menolong sama sekali
(CPU-bound, GIL): 2000 target mati = 2,66 s (1 thread) vs 3,84 s (50 thread).

Saran praktis: `-t 25..50 --timeout 8..12` untuk daftar besar. Lebih tinggi dari
itu menambah beban target tanpa menambah kecepatan.

### --chain (scan → exploit hanya yang VULN)

Sebelumnya `--exploit` memanggil `exploit()` untuk setiap modul yang check-nya
VULN **atau INFO** — pada host tidak rentan itu puluhan request sia-sia. Sekarang
`--chain` memisahkan dua fase dan hanya menyentuh modul yang VULN:

| host | `--exploit` | `--chain` |
|---|---|---|
| Joomla 8145 (punya 4 modul VULN) | 96 req | 83 req |
| Joomla 8108 (patched) | 73 req | 68 req |
| Ultimate Member 8100 | 57 req | 44 req |

Verdict identik. Bonus: operator melihat daftar sasaran sebelum fase destruktif.

### Bug yang muncul saat menguji chain (dan sudah dipatch)

1. **Profil generik merusak exploit spesifik**: `field_id=900` dari profil `final`
   membuat modul 2594 hanya mencoba member 900 → gagal → verdict `VULN` padahal
   PWN tercapai bila mencoba ID 1. Kini `field_id` dicoba dulu, lalu fallback 1..5.
2. **Kegagalan exploit disembunyikan**: hasil non-PWN/non-CLEAN tidak dicetak,
   jadi operator hanya melihat `VULN` tanpa sebab. Kini muncul sebagai `INFO` +
   "exploit belum tuntas: <alasan>" beserta evidence.
3. **Progres FASE 1 spam** saat output dipipa (200+ baris) → kini tiap 10%.
