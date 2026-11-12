#!/usr/bin/env php
<?php
/**
 * jfilter_check.php — jalankan Joomla\CMS\Filter\InputFilter::isSafeFile() ASLI
 * dari pohon source Joomla mana pun, tanpa bootstrap CMS.
 *
 * Kegunaan: memverifikasi (bukan meniru) perilaku blacklist ekstensi/isi file
 * antar versi Joomla — mis. untuk CVE-2026-73373 (upload .shtml).
 *
 * Pakai:
 *   php tools/jfilter_check.php <path-ke-InputFilter.php> [ext|php]
 *
 * Contoh:
 *   php tools/jfilter_check.php src/joomla/j547/libraries/src/Filter/InputFilter.php ext
 *   php tools/jfilter_check.php src/joomla/j548/libraries/src/Filter/InputFilter.php ext
 *
 * Catatan: parent class Joomla\Filter\InputFilter di-stub kosong; isSafeFile()
 * tidak memakai method parent, jadi hasilnya tetap berasal dari kode asli.
 */

namespace Joomla\Filter {
    class InputFilter
    {
    }
}

namespace {
    if ($argc < 2) {
        fwrite(STDERR, "usage: php jfilter_check.php <InputFilter.php> [ext|php]\n");
        exit(2);
    }

    $file = $argv[1];
    if (!is_file($file)) {
        fwrite(STDERR, "tidak ada file: {$file}\n");
        exit(2);
    }

    define('_JEXEC', 1);          // library Joomla memakai guard ini
    require $file;

    $cls  = \Joomla\CMS\Filter\InputFilter::class;
    $mode = $argv[2] ?? 'ext';

    $names = $mode === 'php'
        ? ['e.php', 'e.php.txt', 'e.phtml', 'e.phar', 'e.txt', 'e.php.jpg']
        : ['e.shtml', 'e.shtm', 'e.sht', 'e.stm', 'e.html', 'e.txt',
           'x.shtml.txt', 'e.shtml.jpg'];

    $tmp = tempnam(sys_get_temp_dir(), 'jf');
    file_put_contents($tmp, "PLAIN CONTENT, NO PHP TAG\n");

    $ver = preg_match('#/j([0-9]+)#', $file, $m) ? $m[1] : '?';
    echo "InputFilter: {$file}\n  (label versi: {$ver}) isi berkas: plain\n";
    foreach ($names as $n) {
        $ok = $cls::isSafeFile([
            'name' => $n, 'type' => 'text/plain', 'tmp_name' => $tmp,
            'error' => 0, 'size' => filesize($tmp),
        ]);
        printf("  %-16s %s\n", $n, $ok ? 'LOLOS' : 'diblokir');
    }
    @unlink($tmp);
}
