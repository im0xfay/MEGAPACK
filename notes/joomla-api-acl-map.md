# Joomla Core — peta sink API webservice (audit ACL)

Sumber: Joomla 5.4.8 (`src/joomla/j548`). Tujuan: memetakan permukaan serang kelas
CVE-2026-35223 / 71574 / 90913 / 92226 / 48898 / 48899 / 48904 / 2023-23752.

---

## 1. Mekanisme routing API (terverifikasi)

`libraries/src/Application/ApiApplication.php`

```php
$route = $router->parseApiRoute($method);     // method HTTP -> route
$this->input->set('controller', $route['controller']);
$this->input->set('task', $route['task']);
...
if (!isset($route['vars']['public']) || $route['vars']['public'] === false) {
    if (!$this->login(['username' => ''], ['silent' => true, 'action' => 'core.login.api'])) {
        throw new AuthenticationFailed();     // 401
    }
}
```

`libraries/src/Router/ApiRouter.php :: createCRUDRoutes()` memetakan:

| Method | Path | Task |
|--------|------|------|
| GET | `v1/<x>` | `<ctrl>.displayList` |
| GET | `v1/<x>/:id` | `<ctrl>.displayItem` |
| POST | `v1/<x>` | `<ctrl>.add` |
| PATCH | `v1/<x>/:id` | `<ctrl>.edit` |
| DELETE | `v1/<x>/:id` | `<ctrl>.delete` |

**Dua gerbang berbeda**: (1) `core.login.api` (autentikasi API, default **hanya group 8 = Super Users**),
(2) ACL di controller (`allowAdd/allowEdit/allowDelete` warisan `ApiController` = `core.manage` + `core.<verb>` pada option).

## 2. Dua lapis ACL yang harus diperiksa

`libraries/src/MVC/Controller/ApiController.php`

```php
protected function allowEdit(...)  { return $user->authorise('core.manage',$this->option)
                                          && $user->authorise('core.edit',$this->option); }
protected function allowAdd(...)   { ... core.manage && (core.create || authorisedCategories) }
protected function allowDelete()   { ... core.manage && core.delete }        // @since 5.4.8
```

`edit()` memanggil `allowEdit()`; `add()` memanggil `allowAdd()`; `delete()` memanggil `allowDelete()`.
`save()` **tidak** memanggil ACL sendiri — bergantung pada pemanggilnya.

**Konsekuensi**: controller yang meng-expose handler mutasi **di luar** `add/edit/delete`
(mis. method khusus) harus memanggil ACL sendiri. Bila tidak → kebocoran.

## 3. Inventaris controller API TANPA override ACL

Grep `function allow(Edit|Add|Delete)|NotAllowed|authorise(` pada setiap
`api/components/*/src/Controller/*Controller.php`:

```
NO-ACL  com_banners/BannersController         NO-ACL  com_menus/MenusController
NO-ACL  com_banners/ClientsController         NO-ACL  com_messages/MessagesController
NO-ACL  com_contact/ContactController         NO-ACL  com_modules/ModulesController
NO-ACL  com_contenthistory/HistoryController  NO-ACL  com_newsfeeds/FeedsController
NO-ACL  com_content/ArticlesController        NO-ACL  com_plugins/PluginsController
NO-ACL  com_installer/LanguagesController     NO-ACL  com_redirect/RedirectController
NO-ACL  com_installer/ManageController        NO-ACL  com_tags/TagsController
NO-ACL  com_joomlaupdate/BaseController       NO-ACL  com_templates/StylesController
NO-ACL  com_languages/LanguagesController     NO-ACL  com_users/LevelsController
NO-ACL  com_languages/OverridesController     NO-ACL  com_users/UsersController
NO-ACL  com_languages/StringsController       NO-ACL  com_media/AdaptersController
has-ACL com_categories, com_config(2), com_fields(2), com_joomlaupdate(3),
        com_media/Media, com_menus/Items, com_privacy(2), com_users/Groups
```

**Catatan penting**: “NO-ACL” ≠ otomatis rentan. `com_banners/BannersController` misalnya
memakai `allowEdit` warisan yang memeriksa `core.manage`+`core.edit` — cukup untuk `com_banners`.
Kebocoran muncul bila **asset/option yang diperiksa tidak mewakili item yang dioperasikan**
(mis. ACL dicek pada `com_tags` tetapi operasi menyentuh item kategori lain), atau bila
handler khusus tidak memanggil ACL sama sekali.

## 4. Handler mutasi non-standar (prioritas audit)

Method `public` di controller API yang **bukan** add/edit/delete/display* — calon kuat
kebocoran karena tidak melewati `ApiController::edit/add/delete`:

| Controller | Method | ACL terverifikasi |
|---|---|---|
| `com_contenthistory/HistoryController` | `keep()` | ada, di model (`canEdit()` → `authorise('core.edit',$record->item_id)` + fallback session state) |
| `com_contact/ContactController` | `submitForm()` | **TIDAK ADA** — hanya butuh `core.login.api`; mengirim email + dispatch `onSubmitContact` |
| `com_privacy/RequestsController` | `export()` | ada (`core.admin`) |
| `com_joomlaupdate/UpdatesController` | `getUpdate/prepareUpdate/finalizeUpdate` | token `X-JUPDATE-TOKEN` (`validateUpdateToken()`), route `public=>true` |
| `com_joomlaupdate/NotificationController` | `success/failed` | token `X-JUPDATE-TOKEN` |
| `com_joomlaupdate/HealthcheckController` | `show` | token |
| `com_languages/StringsController` | `search/refresh` | belum diaudit |
| `com_menus/ItemsController`, `com_modules/ModulesController` | `getTypes` | belum diaudit (read-only) |

## 5. Hasil pengujian live di lab (Joomla 5.4.8, port 8106)

| Uji | Hasil | Interpretasi |
|-----|-------|--------------|
| `POST /v1/users/levels` (low-priv, `core.login.api` diberikan) | **403 Access Denied** | ACL `LevelsController` warisan aktif → 90913 dipatch di 5.4.8 |
| `PATCH /v1/users/1` (low-priv) | **403 Access Denied** | 92226 dipatch |
| `PATCH /v1/banners/1/contenthistory/keep` (low-priv) | **400** (pesan aplikasi) | `keep()` ditempuh; model `canEdit()` menolak per-record tanpa 403 → bukan kebocoran bersih |
| `POST /v1/joomlaupdate/prepareUpdate` tanpa token | **400 "Token is required"** | route `public` **terlindungi token** |
| `GET /v1/joomlaupdate/getUpdate` tanpa token | **400** | idem |
| `POST /v1/contacts/form/:id` | butuh `core.login.api` | `submitForm()` tanpa ACL — abuse email form bila akun API tersedia |

## 6. Kondisi yang membuat kelas CVE ini hidup

1. `core.login.api` diberikan ke group non-super (mis. Registered/Manager) — umum di
   integrasi headless/SPA.
2. Endpoint khusus (bukan add/edit/delete) tanpa ACL → `com_contact submitForm` teridentifikasi
   sebagai kandidat nyata.
3. Pemeriksaan ACL pada asset yang salah (per-item vs per-component).

## 7. Kesenjangan (residual checklist)

- Verifikasi CVE-2026-90913 / 92226 / 71574 / 35223 **pada versi rentan sesungguhnya**
  (4.x / 5.4.7 / 6.1.2) — belum diunduh.
- Audit `com_languages/StringsController::search/refresh` dan `com_menus/com_modules getTypes`.
- CVE-2026-48898/48899 (com_users **batch** task) — batch task bukan bagian API webservice;
  ada di controller admin (`administrator/components/com_users/src/Controller/...`) → jalur berbeda.
- CVE-2026-48904 (group editing webservice) — `GroupsController` punya `allowEdit` = `core.admin`;
  perlu cek apakah 5.4.8 sudah memuat patch.
