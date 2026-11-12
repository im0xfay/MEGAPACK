# Peta backlog CVE historis Joomla (14) — status & urutan kerja

Disusun 2026-11-08. `cve-list.txt` hanya memuat ID tanpa metadata, jadi kolom
advisory/rentang diambil dari pusat keamanan Joomla + NVD (dikutip di bawah).
Kolom "fix diverifikasi" berarti rentang/jalur sudah dikonfirmasi dari **diff
rilis rentan vs rilis patch**, bukan dari klaim dokumen.

| CVE | Advisory | Kelas | Rentang | Fix | Butuh auth? | Status |
|---|---|---|---|---|---|---|
| **CVE-2015-8562** | 20151214 RCE | object injection → RCE | 1.5.0 – 3.4.5 | 3.4.6 | **tidak** | ✅ **SELESAI** — lab-verified PWN (`modules/joomla_core_8562.py`, `notes/CVE-2015-8562-analysis.md`; syarat PHP ≤5.6.12 + session handler database) |
| CVE-2015-8565 | 20151204 Directory Traversal | path traversal | 3.2.0 – 3.4.x (<3.4.6) | 3.4.6 | belum pasti | belum |
| **CVE-2015-7857** | 20151001 SQL Injection | SQL injection (unauth) | 3.2.0 – 3.4.4 | **3.4.5** | **tidak** (NVD: 'remote attackers ... via index.php') | ✅ **SELESAI** — lab-verified PWN (`modules/joomla_core_7857.py`, `notes/CVE-2015-7857-analysis.md`) |
| CVE-2015-7858 | 20151001 SQL Injection | SQL injection | 3.2.0 – 3.4.3 | 3.4.4 | diduga tidak | sink **belum ditemukan** (bag. 2b) |
| **CVE-2016-8869** / 8870 | privesc registrasi | privilege escalation | 3.4.4 – 3.6.3 | 3.6.4 | tidak | ✅ **SELESAI** (`99f87af`) |
| **CVE-2016-9836** | 20161202 Shell Upload | upload blacklist | 3.0.0 – 3.6.4 | 3.6.5 | ya (hak media) | ✅ **SELESAI** (lab-verified, lihat `notes/CVE-2016-9836-analysis.md`) |
| **CVE-2017-8917** | com_fields SQLi | SQL injection | 3.7.0 | 3.7.1 | tidak | ✅ **SELESAI** (`5ab8c99`) |
| CVE-2018-11322 | belum diambil | ? | ? | ? | ? | belum |
| CVE-2019-10945 | 20190401 Directory Traversal in com_media | path traversal | 1.5.0 – 3.9.4 | 3.9.5 | ya | belum |
| **CVE-2020-10238** | 7.5 · AV:N/AC:L/**PR:N** | Joomla < 3.9.16 — aksi com_templates kurang ACL | ✅ **SELESAI** — lab-verified PWN (`modules/joomla_core_10238.py`, `notes/CVE-2020-10238-analysis.md`). **PR:N NVD TERBUKTI SALAH.** Diff 3.9.15→3.9.16: `controllers/template.php` menambah `// Access check. if (!$this->allowEdit())` di ~12 method (createFile/uploadFile/delete/… sebelumnya TANPA cek) dan `allowEdit()` berubah dari `authorise('core.edit','com_templates')` menjadi **`authorise('core.admin')` GLOBAL** (hanya Super User). Rantai: createFile(name,type=php) → berkas kosong, save(jform[source]) → isi PHP → GET = `uid=33(www-data)` (dibuktikan di 3.9.15 @8132 dengan Manager yang diberi core.manage com_templates; 3.9.16 @8133 = "Save not permitted"). `uploadFile` mati untuk .php karena `Joomla\CMS\Input\Files::get()` → `InputFilter::isSafeFile()` menolak sebelum ACL ("No file was found") |
| **CVE-2020-24597** | NVD kosong | Joomla < 3.9.21 — opsi `file_path`/`image_path` com_media tanpa validasi | ✅ **SELESAI** — lab-verified VULN (`modules/joomla_core_24597.py`, `notes/CVE-2020-24597-analysis.md`). `media.php: define('COM_MEDIA_BASE', JPATH_ROOT.'/'.$params->get($path,'images'))` tanpa validasi ⇒ akar Media Manager keluar JPATH_ROOT. Patch 3.9.21: berkas baru `libraries/src/Form/Rule/FilePathRule.php` (`Path::check`) + `validate="filePath"` pada dua field di config.xml. Bukti: 3.9.20 @8150 menyimpan `../../tmp` dan unggahan mendarat di `/var/tmp/<nama>.txt` (di luar document root); 3.9.21 @8151 menolak 'Invalid field: Path to Images Folder' |
| **CVE-2021-23132** | 7.5 · PR:N (NVD, tidak akurat) | Joomla 3.0.0-3.9.24 — com_media menerima direktori sistem sebagai akar media | ✅ **SELESAI** — `modules/joomla_core_23132.py` (lab 3.9.24 @8170 VULN / 3.9.25 @8171 CLEAN). Fix 3.9.25: `FilePathRule` + `exclude` di config.xml + `is_dir()` di media.php |
| **CVE-2023-23752** | API config disclosure | broken access control | 4.0.0 – 4.2.7 | 4.2.8 | tidak | ✅ **SELESAI** (`f74edfd`) |

Sumber: developer.joomla.org/security-centre (advisory 20151201, 20151204,
20161202, 20190401, 20200303, 20200803, 20210306) dan NVD (CVE-2015-8562,
CVE-2015-8565, CVE-2015-7858, CVE-2020-10238). Halaman advisory Joomla memblokir
pengambilan otomatis (bot-check) sehingga detail diambil dari ringkasan hasil
pencarian; yang penting tetap dikonfirmasi ulang lewat **diff rilis**.

## Kenapa CVE-2021-23132 ditolak (bukti, bukan dugaan)

- Fix 3.9.25 pada domain ini = `libraries/src/Form/Rule/FilePathRule.php`
  (nilai wajib mulai huruf + segmen pertama tidak boleh masuk daftar `exclude`)
  plus `exclude="administrator|api|…|tmp"` pada `config.xml` — keduanya
  memvalidasi **opsi komponen** com_media.
- Menyimpan opsi komponen butuh `core.admin` (Super Users). Artinya vector-nya
  butuh sesi backend ber-hak Super User — tidak dapat dirantai dari
  CVE-2016-8869 (yang maksimal grup Administrator/Manager).
- `Path::resolve()` yang ditambahkan di rilis yang sama **tidak dipanggil di
  mana pun** pada 3.9.25 (diverifikasi dengan grep seluruh `libraries/src` +
  `administrator/components/com_media`) → bukan jalur runtime yang bisa diuji.
- Kesimpulan: outcome terkontrol sulit dibuktikan end-to-end di lab tanpa
  menyuntikkan sesi Super User — melanggar aturan "verified = dibuktikan, bukan
  diasumsikan". Lebih baik jujur menolak daripada membuat modul yang klaimnya
  tak bisa dipertanggungjawabkan.

## Urutan kerja berikutnya (usul, berbasis bukti di atas)

1. **CVE-2016-9836** (Shell Upload, 3.0.0–3.6.4 → 3.6.5). Akar sudah ditemukan
   dari diff: `JHelperMedia::canUpload()` 3.6.4 memblokir `php, js, exe, phtml, …`
   tetapi **tidak** memuat `php3, php4, php5, php6, php7, pht` — 3.6.5
   menambahkannya. Butuh sesi dengan hak media; outcome: berkas `.php5`
   terunggah dan (bila server mengeksekusi ekstensi itu) jadi shell.
   Lab: 3.6.4 (rentan) vs 3.6.5 (patched), image `megapack-php74`.
   Catatan: "eksekusi `.php5`" adalah pilihan konfigurasi server — harus
   dinyatakan eksplisit sebagai precondition di modul dan lab.
2. **CVE-2015-7857** (SQLi unauth via `list[select]`, 3.2.0-3.4.4 → fix 3.4.5) —
   sink & jangkauan sudah pasti (bag. 2b); butuh lab PHP 5.6 (Joomla 3.4.x fatal di
   PHP 7: `use Joomla\String\String as String`). **CVE-2015-7858** terpisah, sink
   belum ditemukan — jangan digabung.
3. **CVE-2015-8562** (object injection → RCE, unauth, 1.0.0–3.4.5) — nilai
   tertinggi tapi butuh lab PHP 5.x (`php:5.6-apache`) dan gadget chain; paling
   mahal, kerjakan setelah yang murah.
4. Sisanya (2015-8565, 2019-10945, 2020-10238, 2020-24597) — mayoritas
   traversal/ACL yang butuh sesi backend; kelompokkan sebagai satu batch
   "authenticated Joomla core" setelah yang unauth selesai.

## Residual

- CVE-2018-11322 belum diambil metadata-nya sama sekali.
- Rentang CVE-2015-8565 masih perlu konfirmasi diff. (CVE-2015-7857 sudah dikonfirmasi
  diff 3.4.4 → 3.4.5 + lab-verified; lihat §2b.)
- Belum ada modul yang menangani alur **login backend** secara terstandar
  (butuh `--username`/`--password` yang konsisten) — prasyarat untuk item 1 & 4.

## 2b. CVE-2015-7857 — sink terkonfirmasi (diff 3.4.4 -> 3.4.5)

Ground truth NVD: "SQL injection vulnerability in the **getListQuery function in
administrator/components/com_contenthistory/models/history.php** in Joomla! 3.2
before **3.4.5** allows remote attackers to execute arbitrary SQL commands via the
**`list[select]` parameter to index.php**" (CWE-89, CVSS 7.5, AU:N). Referensi
tambahan: advisory JSST `[20151001]`, Trustwave TWSL2015-021, exploit-db 38797,
packetstorm 134494 ("Content History SQL Injection RCE"), Rapid7
`joomla_contenthistory_sqli_rce`.

Sink sesungguhnya ada di **library bersama**, bukan di model itu sendiri:
`libraries/legacy/model/list.php :: JModelList::populateState()` pada 3.4.4
menyalin setiap kunci `list[*]` dari request ke state **tanpa validasi**
(`case 'limit': $limit = $value; break;`) dan tidak punya daftar hitam, sehingga
`list[select]` masuk ke state dan dipakai model history:

    $query->select($this->getState('list.select', 'h.version_id, h.ucm_item_id, ...'));

Perbaikan 3.4.5 (diff terverifikasi) menambahkan:
    protected $listBlacklist = array('select');     // list[select] tidak lagi di-merge
    $filterBlacklist = array();
    case 'limit': case 'start': $limit = $inputFilter->clean($value, 'int');
    case 'select': ... $inputFilter->clean($field, 'cmd')   // walau sudah diblokir

Kenapa bisa TANPA autentikasi: `components/com_contenthistory/contenthistory.php`
(komponen sisi SITUS) hanya memuat bahasa lalu
`require_once JPATH_COMPONENT_ADMINISTRATOR . '/contenthistory.php';` — jadi
frontend `index.php?option=com_contenthistory...` mengeksekusi komponen
**administrator** tanpa pemeriksaan ACL di titik masuk. Pada 3.4.4 model
`history.php` juga belum punya access check di `getItems()`; 3.4.5 menambahkan
`getItems()` + `authorise('core.edit', $typeAlias . '.' . (int) $ucm_item_id)`
(ini yang menjelaskan pasangan advisory `[20151002] ACL Violations` di rilis yang sama).

Catatan metode: dugaan awal saya (sink = `item_id`/`type_id` tanpa filter) SALAH —
3.4.4 dan 3.4.5 sama-sama sudah memakai `$input->get('item_id', 0, 'integer')`.
Koreksi datang dari membaca `JModelList::populateState()` pada diff + deskripsi NVD.

**SELESAI 2026-11-08.** Lab-verified end-to-end: `mp-j344` @8120 (Joomla 3.4.4,
PHP 5.6.40, MySQL 5.7.44) membocorkan tanpa autentikasi `version()`, `database()`,
nama tabel, dan kredensial super user (`password_verify('labpass', <hash>) = true`);
`mp-j345` @8121 (3.4.5) menjawab 200 "not authorised" untuk request identik. Modul:
`modules/joomla_core_7857.py` (PWN @8120, CLEAN @8121) — detail lengkap + resep lab
(termasuk jebakan PHP 5.6 / MySQL 5.7 / `curl -g`) di `notes/CVE-2015-7857-analysis.md`.

## 2b-bis. CVE-2015-7858 — sink belum ditemukan

NVD: "SQL injection vulnerability in Joomla! 3.2 before **3.4.4** ... via unspecified
vectors, **a different vulnerability than CVE-2015-7297**" (CPE sampai 3.4.3).
Referensinya identik dengan 7857 (advisory `[20151001]`, exploit-db 38797), tetapi
diff 3.4.3 -> 3.4.4 **tidak memuat perubahan apa pun** di
`administrator/components/com_contenthistory/`, `components/com_contenthistory/`,
atau `libraries/legacy/model/list.php`. Artinya ID ini menunjuk sink lain yang belum
dilokalisasi — atribusi 7857 vs 7858 belum boleh diasumsikan dari kemiripan
referensi. Status: **terbuka** (jangan dipetakan ke modul 7857 sebagai alias).

## 2c. CVE-2016-9836 — selesai

Lihat `notes/CVE-2016-9836-analysis.md`. Sink ganda (isSafeFile + canUpload),
lab mp-j364 @8118 vs mp-j365 @8119, PWN (uid=33(www-data)) terbukti pada varian
allowlist diperluas.

---

## 3. Triage backlog historis — metadata NVD + verifikasi kode (2026-11-08)

| CVE | NVD (skor, vektor) | Isi | Verifikasi kode / catatan |
|---|---|---|---|
| CVE-2015-8565 | 7.5 · AV:N/AC:L/**Au:N** | directory traversal, 3.2.0–<3.4.6, "unknown vectors" | sink **belum terkonfirmasi**; diff lengkap 3.4.5→3.4.6 hanya menyentuh 5 berkas kode. **Tiga kandidat**: (1) `libraries/joomla/uri/uri.php :: JUri::isInternal()` — logika klasifikasi URL internal/eksternal ditulis ulang (dapat dijangkau tanpa auth; paling cocok dengan label "directory traversal" pada makna *traversal URL/open redirect*); (2) `libraries/cms/installer/installer.php :: getAdapter()` — patch memvalidasi nama adapter lewat `getAdapters()`; nama adapter mengalir ke `loadAdapter()` → jalur berkas (`JLoader::import`), tetapi pemanggilnya (`installer.php:526/704/760/817`) memakai tipe dari manifest ekstensi → butuh hak pasang ekstensi; (3) `components/com_users/models/reset.php` — patch token reset (`md5(crypt)`+`explode(':')` → `JUserHelper::verifyPassword()`/`hashPassword()`), dapat dijangkau tanpa auth tetapi **itu kelemahan token, bukan traversal** (kemungkinan CVE lain di rilis yang sama) |
| **CVE-2018-11322** | 7.5 · AC:H/PR:L | Joomla < 3.8.8 — `.phar` lolos pemindai unggahan | ✅ **SELESAI** — lab-verified (`modules/joomla_core_11322.py`, `notes/CVE-2018-11322-analysis.md`). Patch 3.8.8 = **satu kata**: `phar` ditambahkan ke `forbidden_extensions` di `JFilterInput::isSafeFile()` (`libraries/src/Filter/InputFilter.php`); `com_media/helpers/media.php` TIDAK berubah. Chokepoint: `JFile::upload()` (`filesystem/file.php:533`) dan `Input\Files::get()` (`src/Input/Files.php:90`). Bukti lab: 3.8.7 @8160 menerima `x.phar` (payload short tag `<?=`) dan `GET /images/x.phar?c=id` mengembalikan `uid=33(www-data)` (**RCE**, dengan `phar` di whitelist com_media + handler `.phar`); 3.8.8 @8161 menolak 'Bad Request' dan berkas tidak ditulis. Diskriminator respons: `Bad Request`=pemindai menolak · `Unable to upload file.`=whitelist komponen · `Upload Complete`=lolos. Status: `lab-verified` → populasi live = situs dengan `phar` di daftar izin unggahan atau komponen pihak ketiga yang hanya memakai isSafeFile |
| CVE-2020-10238 | 7.5 · AV:N/AC:L/**PR:N** | Joomla < 3.9.16 — aksi di com_templates kurang ACL | **Diff 3.9.15→3.9.16 terverifikasi**: `administrator/components/com_templates/controllers/template.php` — patch menambah `// Access check. if (!$this->allowEdit()) { enqueueMessage(JLIB_APPLICATION_ERROR_SAVE_NOT_PERMITTED); return false; }` di beberapa method (method `save`/`apply`/lainnya berjalan tanpa pemeriksaan), dan `allowEdit()` diubah dari `authorise('core.edit','com_templates')` menjadi **`authorise('core.admin')`** ("check if the user can modify template files"). Artinya pengguna backend dengan `core.edit` (mis. Manager) bisa mengubah berkas template (= tulis berkas PHP) tanpa hak Super User. **PR:N NVD kemungkinan salah lagi** — perlu lab 3.9.15/3.9.16 + akun Manager untuk membuktikan. Rilis 3.9.16 juga memuat artefak `template.php.orig` (sisa paket) |
| **CVE-2019-10945** | 9.8 · AV:N/AC:L/**PR:N** | Joomla < 3.9.5 — Media Manager tidak menyaring parameter `folder` | ✅ **SELESAI** — lab-verified VULN (`modules/joomla_core_10945.py`, `notes/CVE-2019-10945-analysis.md`). **PR:N NVD TERBUKTI SALAH.** Diff 3.9.4→3.9.5 menambah jail `strpos(realpath($fullPath), JPath::clean(COM_MEDIA_BASE)) !== 0` di `com_media` (`controllers/folder.php`, `controllers/file.php`, `controllers/file.json.php`, `models/list.php`). Namun `components/com_media/media.php` (sisi situs) hanya `require_once JPATH_COMPONENT_ADMINISTRATOR . '/media.php'`, dan file itu memeriksa `$user->authorise('core.manage', 'com_media')` → **butuh sesi backend (Manager+)** |
| CVE-2020-24597 | — | NVD API tidak mengembalikan data | metadata perlu sumber lain (advisory Joomla / MITRE) |

Catatan metode untuk 10945: skor NVD tidak boleh dijadikan dasar klaim "unauth". Yang menentukan
adalah jalur kode: entry sisi situs memuat file admin, dan file admin itu memuat pemeriksaan ACL.
Pola ini kebetulan **kebalikan** dari CVE-2015-7857 (di sana model-nya yang tidak memeriksa hak).
