# MEGAPACK

Satu tool untuk banyak CVE sekaligus: WordPress plugin, Joomla Core, Joomla Extensions.
Menu pilih CVE → scan / exploit. Setiap modul **lab-verified end-to-end** sebelum
dinyatakan `verified`.

**Baru mulai? Baca [`PANDUAN.md`](PANDUAN.md)** — panduan operator dari nol
(buat profil → scan → exploit → baca output), termasuk troubleshooting.


## Katalog CVE

**65 modul** — 35 Joomla Core, 10 Joomla Extension, 20 WordPress plugin.

Status: **56 verified**, 7 documented, 2 unsupported.

Setiap CVE punya folder sendiri di [`cve/`](cve/) berisi ringkasan, root cause, dan tautan ke modul + catatan riset.

| CVE | Cluster | Kelas | CVSS | Status |
|---|---|---|---|---|
| [CVE-2015-7857](cve/CVE-2015-7857/) | joomla_core | sql injection | 7.5 | verified |
| [CVE-2015-8562](cve/CVE-2015-8562/) | joomla_core | object injection | 9.8 | verified |
| [CVE-2016-8869](cve/CVE-2016-8869/) | joomla_core | privilege escalation | 9.8 | verified |
| [CVE-2016-8870](cve/CVE-2016-8870/) | joomla_core | privilege escalation | 9.8 | verified |
| [CVE-2016-9836](cve/CVE-2016-9836/) | joomla_core | arbitrary file upload / remote code execution | 9.8 | verified |
| [CVE-2017-8917](cve/CVE-2017-8917/) | joomla_core | sql injection | 9.8 | verified |
| [CVE-2018-11322](cve/CVE-2018-11322/) | joomla_core | unrestricted upload | 7.5 | verified |
| [CVE-2019-10945](cve/CVE-2019-10945/) | joomla_core | path traversal | 9.8 | verified |
| [CVE-2020-10238](cve/CVE-2020-10238/) | joomla_core | acl bypass | 7.5 | verified |
| [CVE-2020-24597](cve/CVE-2020-24597/) | joomla_core | path traversal | - | verified |
| [CVE-2021-23132](cve/CVE-2021-23132/) | joomla_core | path traversal | 7.5 | verified |
| [CVE-2023-23752](cve/CVE-2023-23752/) | joomla_core | broken access control / information disclosure | 5.3 | verified |
| [CVE-2025-1128](cve/CVE-2025-1128/) | wordpress | upload | 9.8 | verified |
| [CVE-2025-15030](cve/CVE-2025-15030/) | wordpress | auth-bypass | 9.8 | verified |
| [CVE-2025-22207](cve/CVE-2025-22207/) | joomla_core | sql injection | 6.7 | verified |
| [CVE-2025-22213](cve/CVE-2025-22213/) | joomla_core | unrestricted file upload | 7.1 | verified |
| [CVE-2025-25227](cve/CVE-2025-25227/) | joomla_core | authentication bypass | - | verified |
| [CVE-2025-2594](cve/CVE-2025-2594/) | wordpress | auth-bypass | 8.1 | verified |
| [CVE-2025-3439](cve/CVE-2025-3439/) | wordpress | object-injection | 9.8 | documented |
| [CVE-2026-11961](cve/CVE-2026-11961/) | wordpress | privesc | 9.8 | documented |
| [CVE-2026-12251](cve/CVE-2026-12251/) | wordpress | privesc | 9.8 | verified |
| [CVE-2026-1492](cve/CVE-2026-1492/) | wordpress | privesc | 9.8 | verified |
| [CVE-2026-15368](cve/CVE-2026-15368/) | wordpress | auth-bypass | 9.8 | verified |
| [CVE-2026-15826](cve/CVE-2026-15826/) | wordpress | auth-bypass | 9.8 | verified |
| [CVE-2026-1779](cve/CVE-2026-1779/) | wordpress | auth-bypass | 9.8 | verified |
| [CVE-2026-18937](cve/CVE-2026-18937/) | wordpress | other | 9.8 | verified |
| [CVE-2026-19423](cve/CVE-2026-19423/) | wordpress | privesc | 9.8 | documented |
| [CVE-2026-19598](cve/CVE-2026-19598/) | wordpress | privesc | 9.8 | verified |
| [CVE-2026-19632](cve/CVE-2026-19632/) | wordpress | auth-bypass | 9.8 | verified |
| [CVE-2026-21628](cve/CVE-2026-21628/) | joomla_ext | arbitrary file upload / write (unauth) + stored XSS | - | verified |
| [CVE-2026-21630](cve/CVE-2026-21630/) | joomla_core | sql injection | 8.8 | verified |
| [CVE-2026-23899](cve/CVE-2026-23899/) | joomla_core | broken access control | 6.5 | verified |
| [CVE-2026-2563](cve/CVE-2026-2563/) | wordpress | privesc | 8.8 | documented |
| [CVE-2026-32488](cve/CVE-2026-32488/) | wordpress | privesc | 8.8 | documented |
| [CVE-2026-3296](cve/CVE-2026-3296/) | wordpress | object-injection | 9.8 | documented |
| [CVE-2026-35221](cve/CVE-2026-35221/) | joomla_core | sqli | 8.1 | verified |
| [CVE-2026-35222](cve/CVE-2026-35222/) | joomla_core | ui-hardening | - | unsupported |
| [CVE-2026-35223](cve/CVE-2026-35223/) | joomla_core | broken access control | 6.5 | verified |
| [CVE-2026-40383](cve/CVE-2026-40383/) | joomla_core | broken access control / information disclosure | 7.5 | verified |
| [CVE-2026-40384](cve/CVE-2026-40384/) | joomla_core | path traversal / arbitrary file read (glob injection) | 6.5 | verified |
| [CVE-2026-48896](cve/CVE-2026-48896/) | joomla_core | authentication bypass | - | verified |
| [CVE-2026-48898](cve/CVE-2026-48898/) | joomla_core | privesc / broken access control (authenticated) | 9.8 | verified |
| [CVE-2026-48899](cve/CVE-2026-48899/) | joomla_core | acl bypass | 9.8 | verified |
| [CVE-2026-48904](cve/CVE-2026-48904/) | joomla_core | privesc / broken access control (API) | 8.2 | verified |
| [CVE-2026-48907](cve/CVE-2026-48907/) | joomla_ext | arbitrary file upload / RCE (unauth) | - | verified |
| [CVE-2026-48908](cve/CVE-2026-48908/) | joomla_ext | arbitrary file upload / RCE (unauth) | - | verified |
| [CVE-2026-48909](cve/CVE-2026-48909/) | joomla_ext | rce | - | verified |
| [CVE-2026-48939](cve/CVE-2026-48939/) | joomla_ext | rce | - | verified |
| [CVE-2026-49049](cve/CVE-2026-49049/) | joomla_ext | missing authorization / path traversal (unauth) | - | verified |
| [CVE-2026-56290](cve/CVE-2026-56290/) | joomla_ext | rce | - | verified |
| [CVE-2026-62103](cve/CVE-2026-62103/) | wordpress | xss | - | unsupported |
| [CVE-2026-67365](cve/CVE-2026-67365/) | joomla_ext | sql injection | 9.8 | verified |
| [CVE-2026-71574](cve/CVE-2026-71574/) | joomla_core | auth_bypass / broken access control (API) | - | verified |
| [CVE-2026-73337](cve/CVE-2026-73337/) | joomla_core | authentication bypass | - | verified |
| [CVE-2026-73371](cve/CVE-2026-73371/) | joomla_core | broken access control (ACL bypass / privilege escalation) | 6.5 | verified |
| [CVE-2026-73372](cve/CVE-2026-73372/) | joomla_core | acl bypass | - | verified |
| [CVE-2026-73373](cve/CVE-2026-73373/) | joomla_core | unrestricted file upload -> conditional RCE (SSI) | - | verified |
| [CVE-2026-74251](cve/CVE-2026-74251/) | joomla_ext | sql injection (unauth) | - | verified |
| [CVE-2026-76570](cve/CVE-2026-76570/) | joomla_ext | sql injection (unauth, read+write) / broken access control | - | verified |
| [CVE-2026-90907](cve/CVE-2026-90907/) | joomla_core | auth_bypass / account creation | - | verified |
| [CVE-2026-90913](cve/CVE-2026-90913/) | joomla_core | authbypass / broken access control (API) | 7.0 | verified |
| [CVE-2026-92226](cve/CVE-2026-92226/) | joomla_core | broken access control (context confusion + kategori tanpa ACL per-record) | - | verified |
| [CVE-2026-92227](cve/CVE-2026-92227/) | joomla_core | authentication bypass (MFA gate) | 8.1 | verified |
| [CVE-2026-96451](cve/CVE-2026-96451/) | wordpress | privesc | 8.8 | documented |
| [CVE-2026-96562](cve/CVE-2026-96562/) | wordpress | rce | 9.8 | verified |

## Kebijakan verdict

Tool ini **tidak pernah menebak**. Urutan status, dari lemah ke kuat:

| Status | Arti |
|---|---|
| `SKIP` | Modul tidak berlaku (platform salah, alias/duplikat, butuh kredensial) |
| `CLEAN` | Terdeteksi dan **tidak** rentan (versi di luar rentang, sudah dipatch) |
| `INFO` | Versi dalam rentang rentan, **tetapi** belum dibuktikan — biasanya butuh kredensial backend |
| `UNKNOWN` | Data tidak cukup untuk menyimpulkan |
| `VULN` | Ada **bukti balik** dari target (respons oracle, read-back, bypass terverifikasi) |
| `PWN` | **Outcome terkontrol** tercapai (admin takeover, RCE, webshell) |

`VULN` dan `PWN` hanya muncul kalau ada bukti yang bisa dipertanggungjawabkan.
Versi rentan saja **tidak pernah** cukup — itu selalu `INFO`.

## Pakai

```bash
# MENU INTERAKTIF — tanpa argumen (pintu operator, tanpa perlu hafal flag)
python3 mp.py

# lihat modul
python3 mp.py --list

# deteksi satu CVE pada satu target
python3 mp.py -u http://TARGET:PORT --cve CVE-2026-49049

# deteksi SEMUA modul pada satu target
python3 mp.py -u http://TARGET:PORT

# mass mode
python3 mp.py --targets targets.txt --cluster joomla_ext -o hasil.json

# eksploitasi (detect-only default; destruktif butuh KEDUA flag)
python3 mp.py --targets targets.txt --cve CVE-2026-48908 \
    --exploit --i-know-what-im-doing
```

Gambaran cepat alur menu:

```
3 → n → namaprofil → 1 → http://target:8080 → 0   # profil + target
1 → profil → modul                                # SCAN  (tidak memutasi)
2 → profil → modul → ketik "ya"                   # EXPLOIT (memutasi)
```

Target menerima `host:port` tanpa skema (`http://` ditambahkan; hanya 443/8443 yang
menyiratkan `https`).

## Flag berguna

| Flag | Fungsi |
|---|---|
| `--cve ID` (boleh diulang) | batasi ke CVE tertentu |
| `--username` / `--password` | kredensial akun backend (modul yang butuh login) |
| `--field-id N` | ID record/user target |
| `--delete-user N` | **destruktif**: hapus user ID N (modul bersink hapus) |
| `-m`, `--menu` | buka menu interaktif (sama dgn menjalankan tanpa argumen) |
| `--cluster` | `wordpress` / `joomla_core` / `joomla_ext` |
| `--targets FILE` | satu URL per baris, `#` untuk komentar |
| `-t N` | jumlah worker (default 8) |
| `--delay S` | jeda minimum antar-request per target |
| `--timeout S` | timeout per request (default 20) |
| `--proxy URL` | lewat proxy |
| `--verify-tls` | aktifkan verifikasi sertifikat TLS (default: dimatikan) |
| `-o FILE` | simpan hasil sebagai JSON |
| `--report [FILE]` | tulis report agregat Markdown dari registry |
| `-q` / `-v` | senyap / verbose (satu baris per request) |

## Status tag

`VULN` (terdampak) · `RCE` · `PWN` (outcome terkontrol tercapai) · `INFO` ·
`CLEAN` (versi sudah dipatch) · `SKIP` (bukan produk sasaran) · `ERR` · `UNKNOWN`.

`PWN` hanya diberikan setelah exploit mencapai outcome terkontrol di lab
(`uid=0(root)`, berkas tertulis, webshell dapat dipanggil) — bukan sekadar
"request berhasil".

## Isi repo

```
mp.py                  framework + CLI
modules/               satu modul per CVE
notes/                 analisis per CVE + run-log + self-attack
src/                   sumber vendor/plugin (referensi diff)
MEGAPACK-report.md     report agregat (generate: mp.py --report)
```

## Etika

Detect-only secara default. Mode destruktif terpisah di balik dua flag eksplisit.
Gunakan hanya pada sistem yang Anda berwenang uji.
