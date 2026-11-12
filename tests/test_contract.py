"""Kontrak modul MEGAPACK — dijalankan tanpa jaringan.

Setiap modul harus: terdaftar di REGISTRY, punya check(), punya metadata wajib,
dan check() harus mengembalikan tripel (status, detail, evidence) yang bisa
diproses CLI meski tidak ada target (di sini dipanggil dengan target palsu yang
tidak akan pernah tersentuh karena check() diharapkan gagal cepat / skip).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.modules.setdefault("mp", __import__("mp"))

import mp  # noqa: E402

VALID_STATUS = {mp.ST_VULN, mp.ST_CLEAN, mp.ST_INFO, mp.ST_SKIP,
                mp.ST_ERR, mp.ST_PWN, mp.ST_UNKNOWN}
REQUIRED = ("cve", "cluster", "title", "vclass")

fails = []


def check_parser() -> None:
    """Regression: parser tunggal harus memuat SEMUA flag yang bisa dipancarkan
    `_namespace()`.

    Bug lama: `poc.py` menyimpan SALINAN parser yang kehilangan
    `--deploy-shell`/`--deploy-name`/`--deploy-password`/`--new-password`,
    sehingga mode deploy dari menu gagal `unrecognized arguments`. Konsolidasi
    ke satu `build_parser()` harus tetap dipagari tes ini.
    """
    prof = {
        "targets": ["http://example.invalid"], "targets_file": "", "threads": 4,
        "deploy_shell": True, "deploy_name": "idx", "deploy_password": "pw",
        "new_password": "np", "api_token": "t", "username": "u", "password": "p",
        "field_id": 1, "membership": 2, "contact_id": "7", "category_id": "3",
        "category_ext": "com_content", "shell_url": "http://s",
        "proxy": "http://p", "timeout": 5.0, "delay": 0.1,
    }
    try:
        ns = mp._namespace(prof, ["CVE-2026-48908"], exploit=True, quiet=False)
    except SystemExit as e:  # argparse keluar saat argumen tak dikenal
        fails.append(f"parser: _namespace profil penuh gagal parse (SystemExit {e})")
        return
    for attr in ("deploy_shell", "deploy_name", "deploy_password", "new_password"):
        if not hasattr(ns, attr):
            fails.append(f"parser: atribut '{attr}' hilang dari Namespace")
    if not (ns.deploy_shell and ns.deploy_name == "idx" and ns.new_password == "np"):
        fails.append("parser: flag deploy/new-password tidak diteruskan dengan benar")
    if not ns.exploit:
        fails.append("parser: --exploit tidak diteruskan")



# Metode write-capable yang TIDAK boleh dipanggil dari check(). check() harus
# murni deteksi; apa pun yang membuat/mengubah/menghapus state adalah exploit.
_WRITE_METHODS = {
    "add_pod", "save_pod", "save_user", "save_field", "delete_pod",
    "delete_user", "submit.submit", "submit", "save", "create_pod",
}


def check_purity() -> None:
    """Regression: check() tidak boleh memanggil metode yang menulis.

    Bug nyata 2026-11-09: check() CVE-2026-48939 mem-POST `submit.submit`
    dengan data form lengkap -> menulis +1 baris ke #__icagenda_events setiap
    scan (terukur di lab). check() CVE-2026-19598 memanggil `add_pod`.
    Pemindai yang memutasi target bukan pemindai.
    """
    import inspect
    import re as _re
    for cve, mod in sorted(mp.REGISTRY.items()):
        if mod.check is None:
            continue
        try:
            src = inspect.getsource(mod.check)
        except OSError:
            continue
        # hanya badan fungsi ini (dokumentasi string boleh menyebut nama metode)
        for hit in _WRITE_METHODS:
            if _re.search(rf'["\']method["\']\s*:\s*["\']{_re.escape(hit)}["\']', src):
                fails.append(
                    f"{cve}: check() mengirim method='{hit}' (write-capable) — "
                    f"pindahkan ke exploit() atau pakai oracle baca-saja")


def main() -> int:
    mp.load_modules(os.path.join(ROOT, "modules"))
    if not mp.REGISTRY:
        fails.append("REGISTRY kosong — tidak ada modul yang dimuat")
        return report()

    for cve, mod in sorted(mp.REGISTRY.items()):
        for field_name in REQUIRED:
            if not getattr(mod, field_name, None):
                fails.append(f"{cve}: field wajib '{field_name}' kosong")
        if mod.check is None and not mod.alias_of:
            fails.append(f"{cve}: tidak punya fungsi check()")
        if mod.cluster not in ("wordpress", "joomla_core", "joomla_ext"):
            fails.append(f"{cve}: cluster tidak dikenal '{mod.cluster}'")
        if mod.status not in ("verified", "documented", "unsupported"):
            fails.append(f"{cve}: status tidak dikenal '{mod.status}'")
        if mod.status == "verified" and mod.exploit is None and not mod.alias_of:
            fails.append(f"{cve}: status 'verified' tapi tanpa fungsi exploit()")
        if mod.cvss and not mod.cvss.replace(".", "").isdigit():
            fails.append(f"{cve}: cvss bukan angka '{mod.cvss}'")
        if mod.unsupported_reason and mod.status != "unsupported":
            fails.append(f"{cve}: unsupported_reason diisi tapi status != 'unsupported'")

    # alias_of harus menunjuk modul yang benar-benar ada, dan tidak boleh
    # menunjuk dirinya sendiri atau membentuk rantai alias.
    for cve, mod in sorted(mp.REGISTRY.items()):
        if not mod.alias_of:
            continue
        if mod.alias_of == cve:
            fails.append(f"{cve}: alias_of menunjuk dirinya sendiri")
        elif mod.alias_of not in mp.REGISTRY:
            fails.append(f"{cve}: alias_of '{mod.alias_of}' tidak ada di REGISTRY")
        elif mp.REGISTRY[mod.alias_of].alias_of:
            fails.append(f"{cve}: alias_of menunjuk alias lain "
                         f"('{mod.alias_of}' juga alias)")

    # setiap status yang mungkin dikembalikan check() harus dikenali CLI
    for st in VALID_STATUS:
        assert isinstance(st, str), st

    check_parser()
    check_purity()
    return report()


def report() -> int:
    if fails:
        print("KONTRAK GAGAL:")
        for f in fails:
            print(" -", f)
        return 1
    print(f"kontrak OK — {len(mp.REGISTRY)} modul")
    return 0


if __name__ == "__main__":
    sys.exit(main())
