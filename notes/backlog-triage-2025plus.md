# Triage backlog (CVE tanpa modul) — metadata NVD

Diambil otomatis 2026-11-08 lewat NVD API 2.0 untuk 31 ID di `cve-list.txt` yang belum
punya modul. Kolom deskripsi dipotong 380 karakter. **Semua klaim di sini berasal dari
NVD apa adanya — vektor PR/CVSS NVD terbukti beberapa kali salah (lihat
`notes/backlog-joomla-historis-map.md` §3), jadi verifikasi ke kode tetap wajib.**

| CVE | Skor (vektor) | Deskripsi NVD | CPE |
|---|---|---|---|
| CVE-2015-7858 | 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P) | SQL injection vulnerability in Joomla! 3.2 before 3.4.4 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, a different vulnerability than CVE-2015-7297. | joomla\!:3.2.0:*:*:*:*:*:*:*; joomla\!:3.2.1:*:*:*:*:*:*:*; joomla\!:3.2.2:*:*:*:*:*:*:* |
| CVE-2015-8565 | 7.5 (AV:N/AC:L/Au:N/C:P/I:P/A:P) | Directory traversal vulnerability in Joomla! 3.2.0 through 3.3.x and 3.4.x before 3.4.6 allows remote attackers to have unspecified impact via unknown vectors. | joomla\!:3.2.0:*:*:*:*:*:*:*; joomla\!:3.2.1:*:*:*:*:*:*:*; joomla\!:3.2.2:*:*:*:*:*:*:* |
| CVE-2018-11322 | 7.5 (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H) | An issue was discovered in Joomla! Core before 3.8.8. Depending on the server configuration, PHAR files might be handled as executable PHP scripts by the webserver. | joomla\!:*:*:*:*:*:*:*:* |
| CVE-2020-10238 | - | GAGAL: HTTP Error 429: Too Many Requests | - |
| CVE-2020-24597 | - | NVD tidak mengembalikan data | - |
| **CVE-2021-23132** | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) | com_media allowed paths that are not intended for image uploads | ✅ **SELESAI** — `modules/joomla_core_23132.py`, lab-verified 3.9.24 @8170 VULN (akar media pindah ke `tmp`, penanda ditulis di luar `images`) / 3.9.25 @8171 CLEAN. Catatan: **PR:N di NVD tidak akurat** — save opsi butuh `core.admin`/`core.options`, unggah `core.create`, hapus `core.delete`. Fix = `FilePathRule` (3.9.25) menambah 'karakter pertama wajib huruf' + daftar `exclude` XML; berkas bersaudara dengan CVE-2020-24597 (rule yang sama dari patch 3.9.21). Detail: `notes/CVE-2021-23132-analysis.md` |
| **CVE-2025-15030** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | User Profile Builder < 3.15.2 — proses reset password tidak benar; beberapa request unauth dapat mereset password user mana pun (cukup tahu username) | ✅ **SELESAI** — ditambahkan ke `modules/wp_profile_builder.py` (registrasi ketiga). Lab: WP 6.7.1 + pb **3.15.1 @8180** → `PWN` (kunci reset jadi milik penyerang → password admin diganti → login wp-admin terbukti), **3.15.2 @8181** → CLEAN. Akar: filter global `random_password` mengambil `$_POST['user_pass']` → `get_password_reset_key()` menyimpan kunci pilihan penyerang → reset diselesaikan lewat `wp-login.php?action=rp`. Detail: `notes/CVE-2025-15030-analysis.md` |
| CVE-2025-22207 | - | Improperly built order clauses lead to a SQL injection vulnerability in the backend task list of com_scheduler. | - | ✅ **modul dibuat & terverifikasi lab** — `modules/joomla_core_22207.py`; fix 4.4.11/5.2.4; lab 5.2.3 VULN/PWN (`database()='j523'`) vs 5.2.4 CLEAN; PR:H (butuh sesi backend com_scheduler) |
| CVE-2025-22213 | - | Inadequate checks in the Media Manager allowed users with "edit" privileges to change file extension to arbitrary extension, including .php and other potentially executable extensions. | - |
| CVE-2025-25227 | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) | Insufficient state checks lead to a vector that allows to bypass 2FA checks. | joomla\!:*:*:*:*:*:*:*:* | ✅ **tercakup** — alias `alias_of=CVE-2026-92227` (deskripsi NVD identik: 'Insufficient state checks ... bypass 2FA checks'; putaran patch 5.4.8/6.1.3 sama). Bukti lab ada di modul utama |
| CVE-2025-2563 | 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) | The User Registration & Membership  WordPress plugin before 4.1.2 does not prevent users to set their account role when the Membership Addon is enabled, leading to a privilege escalation issue and allowing unauthenticated users to gain admin privileges | user_registration_\&_membership:*:*:*:*:free:wordpress:*:*; user_registration_\&_membership:*:*:*:*:pro:wordpress:*:* |
| CVE-2025-2594 | 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) | The User Registration & Membership WordPress plugin before 4.1.3 does not properly validate data in an AJAX action when the Membership Addon is enabled, allowing attackers to authenticate as any user, including administrators, by simply using the target account's user ID. | user_registration_\&_membership:*:*:*:*:free:wordpress:*:*; user_registration_\&_membership:*:*:*:*:pro:wordpress:*:* |
| CVE-2026-102427 | - | GAGAL: <urlopen error [Errno 104] Connection reset by peer> | - |
| CVE-2026-102785 | - | Joomla Extension - yootheme.com - Unauthenticated remote code execution in YOOtheme Pro 5.0.0-5.0.52 - YOOtheme Pro’s publicly accessible image transformation handler incompletely binds normalized image operations and the output destination to its request signature. An unauthenticated remote attacker can reuse a signature disclosed in a legitimate public image URL, inject addit | - |
| CVE-2026-14894 | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | The Super Forms – Drag & Drop Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 6.3.313 via the submit_form function. This is due to missing file type validation and the absence of any capability check on the submit_form nopriv AJAX handler, whose only barrier is a session nonce freely obtainable by unauthenticated vi | - |
| CVE-2026-21630 | 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) | Improperly built order clauses lead to a SQL injection vulnerability in the articles webservice endpoint. | joomla\!:*:*:*:*:*:*:*:* | ✅ **modul dibuat & terverifikasi lab** — `modules/joomla_core_21630.py`; fix 5.4.4/6.0.4 (CPE 5.4.4 & 6.0.4); lab 6.0.3 VULN/PWN (`database()='j603'`) vs 6.1.3 CLEAN; PR:L NVD salah → praktiknya PR:H (plugin token hanya grup Super Users) |
| CVE-2026-32475 | 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H) | Unrestricted Upload of File with Dangerous Type vulnerability in Elementor Elementor Pro allows Using Malicious Files.  This issue affects Elementor Pro: from n/a through 4.2.1. | - |
| CVE-2026-48896 | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) | Insufficient state checks lead to a vector that allows to bypass 2FA checks. | joomla\!:*:*:*:*:*:*:*:* | ✅ **tercakup** — alias `alias_of=CVE-2026-92227` (deskripsi NVD identik dengan 2025-25227; putaran patch sama). Bukti lab ada di modul utama |
| **CVE-2026-48899** | 9.8 (CVSS:3.1/AV:N/AC:L/**PR:N**/UI:N/S:U/C:H/I:H/A:H) | com_users batch task tanpa cek core.manage (privesc) | joomla\! core | ✅ **SELESAI** — lab-verified PWN (`modules/joomla_core_48899.py`, `notes/CVE-2026-48899-analysis.md`). **PR:N SALAH.** 6.0.3 @8140: Manager (grup 6) — com_users 403 → 200, keanggotaan 6+7; 6.1.3 @8141: 403, tidak berubah; grup 8 (Super User) ditolak guard `Access::checkGroup`. Batas versi: 5.4.5 rentan / 5.4.6 patched; 6.0.3 rentan / 6.1.1+ patched |
| CVE-2026-5118 | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | The Divi Form Builder plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 5.1.2. This is due to the plugin accepting a user-controlled 'role' parameter from POST data during user registration without validating it against the form's configured default_user_role setting. This makes it possible for unauthenticated attackers to create admin | - |
| CVE-2026-5524 | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | The Divi Form Builder plugin for WordPress is vulnerable to Arbitrary File Upload leading to Remote Code Execution in all versions up to and including 5.1.8. This is due to insufficient file extension validation in the do_image_upload() function where user-supplied input from the acceptFileTypes POST parameter is directly interpolated into a regular expression used to validate  | - |
| CVE-2026-56291 | 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | Joomla Extension - balbooa.com - Unauthenticated file upload in Balbooa Forms extension < 2.4.1 - The Joomla extension Balbooa Forms is vulnerable to an unauthenticated arbitrary file upload that allows uploading executable files and leads to full RCE. | forms:*:*:*:*:*:joomla\!:*:* |
| CVE-2026-65766 | - | Joomla Extension - joomshaper.com - Unauthenticated SQL injection  in SP Page Builder < 6.7.1 - Improper validation of order parameters in the Dynamic Content endpoint leads to an SQL injection vector. | - |
| CVE-2026-65876 | - | Joomla Extension - joomshaper.com - Unauthenticated SQL injection  in SP Page Builder < 6.8.0 - Improper validation of catid parameters in the loadMoreArticles endpoint leads to an SQL injection vector. | - |
| CVE-2026-67285 | - | Joomla Extension - joomshaper.com - Unauthenticated arbitrary local PHP file inclusion in SP Page Builder < 6.8.0 - An unauthenticated attacker can perform includes to arbitrary PHP files that are accessible by the system. | - |
| CVE-2026-67365 | - | Joomla Extension - icagenda.com - Unauthenticated SQL injection in iCagenda < 4.0.0-4.0.11 - Unauthenticated SQL injection in mod_icagenda_calendar (iCagenda), reachable via com_ajax with no session, token or account. | - |
| CVE-2026-73337 | 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) | Joomla! Core - [20260807] - MFA Authentication Bypass in Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2 - Insufficient state checks lead to a vector that allows to bypass 2FA checks. | joomla\!:*:*:*:*:*:*:*:* | ✅ **tercakup** — alias `alias_of=CVE-2026-92227` (fixed 5.4.8/6.1.3; tambahan spesifiknya perbaikan plugin multifactorauth/email `$exception->errorMessage()` → `getMessage()`, tidak berdiri sendiri) |
| CVE-2026-73372 | 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N) | Joomla! Core - [20260809] - Improper ACL checks when injection schema.org contact data in Joomla 5.1.0-5.4.7 and 6.0.0-6.1.2 - An improper access check injects contact information for unaccessible contact items into schema.org snippets. | joomla\!:*:*:*:*:*:*:*:* | ✅ **tercakup** — alias `alias_of=CVE-2026-73371` (satu kelas bug, satu putaran patch; `notes/CVE-2026-73371-73372-analysis.md`, modul `joomla_core_73371_73372.py`) |
| CVE-2026-74253 | - | Joomla Extension - regularlabs.com - Unauthenticated RCE through unverified reflected user input in Sourcerer < 16.0.0 - Regular Labs Sourcerer before 16.0.0 processes {source} blocks found in Joomla’s final rendered HTML without reliably determining where that code originated. | - |
| CVE-2026-82222 | 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) | Deserialization of Untrusted Data vulnerability in Liquid Web / StellarWP GiveWP allows Object Injection.  This issue affects GiveWP: from n/a through 4.16.7.1. | - |
| CVE-2026-94169 | 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) | Improper Control of Generation of Code ('Code Injection') vulnerability in Theme-one The Grid the-grid allows Command Injection.This issue affects The Grid: from n/a through 2.8.1. | - |

## Recon lanjutan (2026-11-08) — bukti kode, bukan teks advisory

### CVE-2026-48899 (Joomla Core, CVSS 9.8, NVD PR:N) — "improper access check on com_users batch task"
Referensi NVD menunjuk advisory Joomla
`https://developer.joomla.org/security-centre/1047-20260515-core-incorrect-access-control-in-sample-data-plugins.html`
(halaman diblokir bot-check; teksnya tidak bisa diambil). Bukti diambil dari **commit rilis**:
`api.github.com/repos/joomla/joomla-cms/commits?path=plugins/sampledata&since=2026-04-01` → satu commit:
`bd77f0e215` "Prepare Joomla! 6.1.1" (2026-05-15). Patch commit itu menunjukkan **tiga hal berbeda**
dalam satu rilis:

1. `administrator/components/com_users/src/Model/UserModel.php` — `batchReset()` dan `batchUser()`
   mendapat cek baru:
   `if (!$this->getCurrentUser()->authorise('core.manage', 'com_users')) { setError(JLIB_APPLICATION_ERROR_BATCH_CANNOT_EDIT); return false; }`
   → task batch com_users (reset password massal / anggotakan grup massal) bisa dipanggil aktor
   yang TIDAK punya `core.manage` di com_users ⇒ privesc (mis. anggotakan akun sendiri ke grup
   Super Users). Ini yang cocok dengan deskripsi NVD ("com_users batch task").
2. `api/components/com_users/src/Controller/GroupsController.php` — `delete()`/`allowAdd()`
   ditambahi cek `authorise('core.admin', $this->option)` (NoAllowed 403) ⇒ jalur Web Services API
   juga bisa dipakai untuk membuat/menghapus grup user tanpa hak admin.
3. `plugins/sampledata/*` — plugin sample data (blog/multilang/testing) ditambahi cek
   `core.edit`/`core.manage` per komponen (mis. `authorise('core.edit','com_tags')`,
   `core.manage` `com_installer`) → aktor berhak rendah tidak bisa memicu pembuatan data contoh
   (yang dapat membuat akun berkredensial diketahui ⇒ privesc). Ini yang jadi judul advisory.

Batas versi (grep kode nyata, bukan teks):
| versi | cek batch di UserModel | cek core.admin di API GroupsController | status |
|---|---|---|---|
| 5.4.6 | ada (5 kemunculan `core.manage','com_users`) | ada (3) | sudah dipatch |
| 5.4.7 / 5.4.10 | ada | ada | sudah dipatch |
| **6.0.3** | **tidak ada** (3 kemunculan saja) | **tidak ada** | **RENTAN** |
| 6.1.1+ | ada (per commit fix) | ada | dipatch |

Catatan: jalur `administrator/components/com_users/src/...` pada 6.1.3 berbeda lokasi berkas
sehingga grep berbasis path tidak cocok — verifikasi ulang lokasi bila modul dibuat.

Konsekuensi untuk modul: lab harus **Joomla 6.0.3 + PHP 8.3+ / MySQL 8** (6.x tidak jalan di
image php74/php56 yang sudah ada) → perlu build image baru. Aktor yang tepat (backend berhak
rendah vs token API) belum ditentukan empiris ⇒ **PR:N NVD belum terbukti dan kemungkinan salah
lagi**; jangan tulis "unauth" sebelum diuji.

### CVE-2020-10238
Sudah **SELESAI** (modul `joomla_core_10238.py`, lab-verified PWN) — lihat
`notes/CVE-2020-10238-analysis.md`. NVD PR:N salah (entry com_templates memeriksa `core.manage`).
