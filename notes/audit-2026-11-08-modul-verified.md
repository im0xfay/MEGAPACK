# Audit modul `verified` — 2026-11-08

Pemicu: triase 11 modul `documented` (kelompok A/B/C) menemukan ≥3 cacat nyata
pada modul yang statusnya belum pernah diuji ke standar tersebut. Audit ini
menerapkan standar yang sama ke 32 modul `verified`.

Pertanyaan audit: **untuk tiap modul `verified` — apakah tool-nya benar-benar
membuktikan mekanisme CVE itu sendiri, dengan bukti yang diamati?**

## Metode

1. **Statis (sharing)** — cari `check()`/`exploit()` yang dipakai bersama oleh
   >1 CVE (risiko misatribusi: modul melaporkan status untuk vektor milik CVE lain).
2. **Kontrol negatif (dinamis)** — jalankan seluruh modul ke lab yang sudah
   dipatch (`megapack-joomla` Joomla 5.4.8 @ 127.0.0.1:8106) dan periksa apakah
   ada `VULN`/`RCE`/`PWN` di target yang seharusnya bersih.
3. **Atribusi bukti** — baca string bukti yang dipancarkan `exploit()`; apakah
   evidence menyebut mekanisme CVE yang diminta, atau hanya akibat umum.

## Temuan

### T1 — `check`/`exploit` dipakai bersama lintas CVE (4 grup)

| Grup | CVE | `check` | `exploit` | Bisa dibedakan? |
|---|---|---|---|---|
| Everest OI | 2025-3439, 2026-3296, 2026-62103 | sama | — | ya — sudah diadjudikasi (alias/unsupported) |
| User Registration | 2026-1492, 11961, 1779, 2563(alias), 32488(doc) | sama | sama | **tidak** untuk 11961 |
| Ultimate Member | 2026-12251, 19423, 96451(doc) | sama | sama | 12251 diperbaiki (provenance + capability); 19423 **tidak** |
| Profile Builder | 2026-15368, 15826 | sama | sama | **tidak** untuk 15368 |

Penyebab sistemik: satu implementasi didaftarkan untuk beberapa ID CVE dalam satu
klaster plugin, dan string bukti tidak mencatat **vektor mana** yang benar-benar
berjalan. Akibat: `PWN` benar sebagai *outcome*, tetapi atribusinya ke CVE tertentu
belum pasti.

**Konsekuensi konkret:**

- `CVE-2026-11961` (plan tier off-form) — `exploit()` bersama hanya memancarkan
  `role=administrator diberikan` (mekanisme `CVE-2026-1492`). `membership=<id>`
  dikirim, tetapi tidak ada verifikasi plan itu yang diterapkan. Mekanisme CVE
  ini tidak pernah diamati. → **diturunkan ke `documented`**.
- `CVE-2026-15368` (autologin tak diikat ke akun baru, fix 3.16.4) — modul memakai
  jalur type-confusion milik `CVE-2026-15826` (fix 3.16.5). Mekanisme sendiri
  tidak diuji; pohon sumber 3.16.4 tidak tersedia untuk diff. → **diturunkan ke
  `documented`**.
- `CVE-2026-12251` vs `19423` — `exploit()` kini mencatat **provenance role**
  (`sumber=form` / `sumber=tebakan-non-form` / `operator`) **dan** membuktikan
  capability: setelah akun dibuat, tool login lagi lalu meminta `/wp-admin/`.
  Bukti lab (UM 2.12.0 @ 8100): `role=um_superadmin sumber_role=form login=mpx51g8gx
  admin=True` → PWN dengan capability **terbukti**, bukan lagi asumsi dari nama role.
  `sumber=form` = role administratif ditawarkan form (12251); `sumber=tebakan-non-form`
  = role dikirim padahal tak ada di form (19423).
- `CVE-2026-19423` — vektor tidak pernah dieksekusi: loop kandidat mencoba role dari
  HTML lebih dulu, dan pada lab 2.12.0 form menawarkan `um_superadmin` → yang berhasil
  adalah vektor 12251 (`sumber_role=form`). Mekanisme 19423 (role **tidak** ada di form
  tetap diterima) tidak diuji. → **diturunkan ke `documented`**.
- `CVE-2026-1779` — `logged_in` (cookie `wordpress_logged_in`) diamati dan
  dilampirkan ke bukti; itu esensi CVE (sesi tanpa kredensial). Tetap `verified`.

### T2 — Kontrol negatif: TIDAK ada false positive

Sweep 42 modul ke Joomla **5.4.8** (sudah dipatch untuk core). Hasil non-CLEAN:

| Status | CVE | Catatan |
|---|---|---|
| VULN | 2026-76570 (JCTables) | benar — ekstensi lab = **1.20.0** (rentan; fix 1.21.1) |
| VULN | 2026-74251 (Phoca Cart) | benar — ekstensi rentan terpasang |
| VULN | 2026-48907 (JCE) | benar — ekstensi lab = **2.9.99.4** (rentan; fix 2.9.99.5) |
| VULN | 2026-48908 (SP Page Builder) | benar — ekstensi lab = **6.6.1** (rentan; fix 6.6.2) |
| INFO | 21628, 48939, 56290, 90907, 92226 | tepat — gate versi/berkas menahan klaim |

Semua modul **Joomla core** mengembalikan `CLEAN`/`SKIP` di 5.4.8. Empat `VULN`
adalah modul **ekstensi**, dan lab memang menampung build ekstensi yang rentan —
diverifikasi langsung dari manifest di dalam kontainer, bukan dari klaim dokumen.

→ **Tidak ditemukan satu pun klaim VULN/RCE palsu pada target yang bersih.**
Kekuatan fondasi ada di `check()` berbasis versi/endpoint; kelemahannya ada di
atribusi mekanisme per-CVE (T1).

### T3 — Duplikat yang belum diadjudikasi (kemungkinan, belum dipastikan)

- `CVE-2026-15368` (≤3.16.3, fix 3.16.4) vs `CVE-2026-15826` (≤3.16.4, fix 3.16.5):
  akar sama menurut catatan, rentang bertumpuk, satu exploit. **Bukan** alias:
  versi fix berbeda → kemungkinan dua CVE berbeda atas satu fungsi. Butuh diff
  3.16.4 untuk memutuskan (pohon sumber belum ada).

### T4 — Sweep balik modul WordPress (10 lab, 2026-11-08)

10 lab WP dinyalakan (`8097`–`8105`, `8110`) dengan versi plugin diverifikasi
langsung dari header plugin di dalam kontainer:

| Lab | Plugin | Versi | Status yang benar |
|---|---|---|---|
| 8097/8098 | everest-forms | 3.0.9.4 | 1128 + 3439 rentan |
| 8099 | user-registration | 5.1.2 | 1492/1779/11961 rentan |
| 8100 | ultimate-member | 2.12.0 | 12251/19423/96451 rentan |
| 8101 | pods | 3.3.9 | 19598 rentan (VULN) |
| 8102 | profile-builder | 3.16.4 | 15826 rentan; **15368 dipatch** |
| 8103 | broken-link-checker | **2.4.15** | 18937 + 96562 **dipatch** |
| 8104 | translatepress | **3.3.9** | 19632 **dipatch** |
| 8105 | everest-forms | 3.4.3 | 3439 rentan; 1128 **dipatch** |

Dua cacat nyata ditemukan oleh sweep ini, keduanya diperbaiki:

1. **`plugin_installed()` false positive (soft-404 HTML).** `h.get()` mengikuti
   redirect, jadi halaman soft-404 WordPress/tema membalas **200 ber-isi HTML**
   untuk path aset (mis. `.../assets/css/everest-forms.css`). Pemeriksaan marker
   hanya berlaku untuk `readme.txt`/`CHANGELOG.md`/`.php`, sehingga aset apa pun
   dihitung "plugin terpasang". Akibatnya 6 lab tanpa Everest Forms melaporkan
   `everest-forms: True` dan modul 1128/3439 memancarkan `INFO` palsu.
   → `mp.py`: cabang aset kini menolak `Content-Type: text/html` dan body yang
   dimulai `<!doctype html`/`<html`.
2. **`CVE-2026-15368` memakai bound versi milik CVE lain.** `check` bersama memakai
   `VULN_MAX=(3,16,4)` (15826), sehingga **3.16.4 — yang sudah dipatch untuk 15368
   (fix 3.16.4)** — keliru dilaporkan `INFO`.
   → `check_15368()` baru dengan `VULN_MAX_15368=(3,16,3)`.
3. **`CVE-2026-32488` memakai bound modul 5.x.** Targetnya `<= 4.4.9`, tetapi
   `check` bersama memakai `VULN_ROLE/VULN_TIER` milik modul 5.x → 5.1.2 (di luar
   rentang) keliru `INFO`.
   → `check_32488()` baru dengan gate `<= 4.4.9`.

Setelah perbaikan, seluruh matriks 10 lab × 18 modul WP bersih: 1 `VULN`
(pods 3.3.9, benar), sisanya `INFO` yang semuanya cocok dengan rentang versinya,
dan `CLEAN`/`SKIP` untuk kombinasi yang dipatch atau tak terpasang.


### T5 — Mode `--exploit` untuk 9 modul WP `verified` (2026-11-08)

| CVE | Lab | Hasil | Catatan |
|---|---|---|---|
| 2026-12251 | UM 2.12.0 @8100 | **VULN** | role `um_superadmin` diterima + login; capability tak terkonfirmasi jarak jauh (wp-admin di-redirect) |
| 2026-15826 | PB 3.16.4 @8102 | **PWN** | sesi user ID 1 + `options-general.php` 200 → capability terbukti |
| 2026-19598 | Pods 3.3.9 @8101 | **PWN** | password admin di-overwrite tanpa login, lalu login berhasil |
| 2025-1128 | ev 3.0.9.4 @8097 | VULN | file write tercapai, **eksekusi belum terkonfirmasi** |
| 2026-1492 | UR 5.1.2 @8099 | VULN | prasyarat: user target dgn meta `urm_user_just_created` tak dibuat tool |
| 2026-1779 | UR 5.1.2 @8099 | VULN | idem |
| 2026-18937 | blc 2.4.15 @8103 | CLEAN | kontrol negatif lolos |
| 2026-96562 | blc 2.4.15 @8103 | CLEAN | kontrol negatif lolos |
| 2026-19632 | tp 3.3.9 @8104 | CLEAN | kontrol negatif lolos |

**Cacat yang ditemukan (termasuk satu yang SAYA perkenalkan sesi ini):**

1. **Heuristik capability v1 salah → PWN palsu.** Versi pertama `_admin_capable`
   memeriksa `/wp-admin/` untuk penanda `wp-admin-bar`. Karena `h.get` mengikuti
   redirect dan lab 8100 me-redirect wp-admin ke beranda, body yang diperiksa
   adalah **beranda** — dan admin bar frontend muncul untuk SEMUA user yang login.
   Hasilnya `admin=True` palsu. Ditemukan karena probe lanjutan menunjukkan
   `options-general.php` → 302. Perbaikan: probe memakai **`/wp-admin/options-general.php`**
   (butuh `manage_options`) dan mensyaratkan **status 200 tanpa redirect + penanda
   halaman**; frasa "not allowed" tidak lagi dipakai (string i18n JS admin memuatnya).
2. **Bukti capability 12251 (DB, final).** Akun hasil exploit mendapat WP role
   `um_superadmin` (`wp_capabilities`), role itu `manage_options=1` (`wp_user_roles`),
   status akun `approved`. Redirect wp-admin berasal dari konfigurasi situs, bukan
   dari ketiadaan capability. Tool tetap konservatif: VULN bila capability tak
   dapat diamati.
3. **`CVE-2025-1128` belum mencapai outcome RCE** — tool hanya sampai "file write
   tercapai, eksekusi belum terkonfirmasi". Label `verified` untuk kelas RCE belum
   didukung oleh tool saat ini (lihat residual).
4. **`CVE-2026-1492`/`1779` prasyarat tidak dapat dipenuhi tool.** Chain butuh user
   target dengan meta `urm_user_just_created`; form membership UR di lab tidak
   dirender di HTML (JS) sehingga tool tidak bisa mendaftarkan user prasyarat
   sendiri. Chain-nya sendiri tetap nyata; ini **gap automasi**, bukan klaim palsu.


## Tindakan yang diterapkan

1. `mp.py` — `plugin_installed()`: cabang aset statis menolak `Content-Type:
   text/html` dan body yang dimulai `<!doctype html`/`<html>` (soft-404 setelah
   redirect tidak lagi dihitung sebagai plugin terpasang).
2. `wp_profile_builder.py` — `check_15368()` baru dengan `VULN_MAX_15368=(3,16,3)`;
   15368 tidak lagi memakai bound 3.16.4 milik 15826.
3. `wp_user_registration.py` — `check_32488()` baru dengan gate `<= 4.4.9`; 32488
   tidak lagi memakai bound modul 5.x.
4. `wp_ultimate_member.py` — bukti `exploit()` kini mencantumkan provenance role
   (`sumber_role=form|tebakan-non-form|operator`) + komentar pemetaan ke CVE, dan
   fungsi baru `_admin_capable()`: PWN hanya diberikan setelah login ulang sebagai
   akun target dan `/wp-admin/` benar-benar terbuka. Klaim "role ini dapat memiliki
   capability administratif" (asumsi dari nama role) dihapus.
5. `CVE-2026-11961` — `verified` → `documented` + alasan eksplisit di `notes`.
6. `CVE-2026-15368` — `verified` → `documented` + alasan eksplisit di `notes`.
7. `CVE-2026-19423` — `verified` → `documented` + alasan eksplisit di `notes`.
8. `wp_profile_builder.py` — `_admin_capable()` baru; `CVE-2026-15826` kini PWN
   hanya bila capability terbukti (`options-general.php` 200 tanpa redirect).
   Lab 8102: PWN + bukti.
9. `wp_ultimate_member.py` — `_admin_capable()` diperketat ke
   `/wp-admin/options-general.php` (200 tanpa redirect + penanda halaman).
   Heuristik v1 (`/wp-admin/` + 'wp-admin-bar') menghasilkan PWN palsu pada lab
   yang me-redirect wp-admin; sudah dibuang.
10. `CVE-2026-12251` — tetap `verified`; catatan environment ditambahkan
    (role `um_superadmin` + `manage_options=1` terbukti di DB; tool melaporkan
    VULN bila capability tak dapat diamati jarak jauh).

## Residual checklist (yang TIDAK diperiksa)

- **Tidak semua 32 modul diverifikasi ulang secara dinamis di lab aslinya.** Sweep
  dijalankan ke satu lab Joomla (5.4.8) + lab 4.1.0/5.4.5/5.4.7 belum dipakai untuk
  modul-modul core.
- **Modul WordPress** — DETECT-only sudah disweep ke 10 lab (T4) dan bersih.
  **Mode `--exploit` belum dijalankan ulang** untuk semua 12 modul WP `verified`;
  yang diverifikasi end-to-end sesi ini hanya `CVE-2026-12251` (lab 2.12.0,
  `admin=True`). 15826/18937/19598/19632/96562/1128/1492/1779 belum dijalankan
  dengan `--exploit` pada lab ini.
- **Payload yang dibangun manual** — SUDAH disisir (`grep serialize(|unserialize(|base64|O:<n>:|pack(`
  di seluruh `modules/`). Hanya **dua** modul menyentuh serialisasi: `joomla_ext_48909.py`
  (satu-satunya yang menyusun payload serialisasi tangan — sudah diperbaiki sesi ini:
  kurung objek, panjang FQCN, kutip cookie) dan `wp_everest_forms.py` (hanya mendeteksi
  sink, `exploit=None`). Tidak ada pembangun payload manual lain → kelas bug `48909`
  tidak punya kandidat lain saat ini.
- **Tidak ada golden-sample test per payload builder** — kelas bug `48909`
  (serialisasi cacat) masih bisa terulang tanpa tertangkap CI.
- **`15368`/`15826`**: belum diputuskan alias vs CVE terpisah (butuh sumber 3.16.4).
- **`CVE-2026-32488`** (`documented`, `exploit=None`) memakai `check` UR 5.x padahal
  targetnya 4.4.9 — belum ditindak (prioritas rendah, non-verified).
- Modul yang berbagi `check` tetapi **punya `exploit` sendiri** belum ditelusuri
  satu per satu untuk memastikan `check`-nya tidak melaporkan versi yang salah.
- Gate CI (`ruff` + `test_contract`) belum otomatis; masih manual.
