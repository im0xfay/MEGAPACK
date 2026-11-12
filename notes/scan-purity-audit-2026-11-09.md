# Audit kemurnian scan — 2026-11-09

Kontrak: `check()` = deteksi saja, tidak memutasi target. Audit ini lahir dari
temuan nyata saat verifikasi operator-grade.

## Temuan (semua diperbaiki + diverifikasi ulang)

| # | Modul | Sifat bug | Bukti terukur | Perbaikan |
|---|---|---|---|---|
| 1 | CVE-2026-48939 (iCagenda upload) | `check()` mem-POST `submit.submit` dengan form LENGKAP | `#__icagenda_events` +1 baris TIAP SCAN (4 baris `mp-probe` terkumpul) | GET-only: versi manifest + GET halaman submit. Terukur 32→32 baris |
| 2 | CVE-2026-19598 (Pods privesc) | `check()` memanggil `method=add_pod` (write-capable) | lab tidak (belum) menulis, tapi panggilan mampu-menulis | oracle baca-saja `method=load_pod`: tanpa bypass 500 "Invalid AJAX request", dengan bypass 200 JSON pod. `wp_posts` 9→9 |
| 3 | CVE-2026-56290 (PageBuilderCK) | `check()` mem-POST `fonts.save`; klaim "tidak ada berkas ditulis" SALAH | `media/com_pagebuilderck/gfonts/bb.css` ditulis + `/tmp/pbck_save.txt` +1 baris/scan | GET-only: versi dari manifest XML publik. Terukur md5+baris identik |
| 4 | CVE-2026-48939 versi | `check()` memakai manifest PERTAMA (komponen stale) | target modul 4.0.14 masih menyajikan `icagenda.xml` 4.0.7 → dilaporkan rentan | versi = TERTINGGI dari kedua manifest. 8145 sekarang CLEAN |
| 5 | CVE-2026-15368 / 15826 (Profile Builder) | prasyarat tidak terpenuhi dilaporkan `UNKNOWN` (terbaca seperti error tool) | 4 baris UNKNOWN di 2 target | jadi `INFO` + penjelasan prasyarat |

## Verifikasi akhir (terukur, bukan klaim)

- Sweep joomla (5 target, 325 hasil): `bb.css` md5 + log baris identik,
  `jos_icagenda_events` 32→32.
- Sweep wordpress (12 target, 240 hasil): `wp_posts`/`wp_users` identik di 9 DB.
- Nol `UNKNOWN`/`ERR` pada sweep WordPress setelah perbaikan #5.

## Guard permanen

`tests/test_contract.py::check_purity()` menolak `check()` yang mengirim
`method='add_pod'|'save_user'|'submit.submit'|...` (daftar `_WRITE_METHODS`).
Diuji negatif: menyuntikkan kembali `add_pod` → kontrak GAGAL; dipulihkan → OK.

## Pelajaran proses

- "Tidak ada berkas dikirim" ≠ "tidak ada berkas ditulis": controller bisa
  menulis SEBELUM validasi argumen (56290 menulis log bahkan tanpa token).
- Oracle POST apa pun harus diuji dengan pengukuran state di target, bukan
  dengan membaca kode saja. Satu-satunya oracle yang aman = GET.
- Versi extension Joomla: manifest komponen bisa stale setelah upgrade; pakai
  nilai TERTINGGI dari semua manifest yang tersedia.
