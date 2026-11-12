<?php
function mp_boot() {
    if (!defined('_JEXEC')) define('_JEXEC',1);
    if (!defined('JPATH_BASE')) define('JPATH_BASE', __DIR__);
    $_SERVER['HTTP_HOST']='localhost'; $_SERVER['SERVER_NAME']='localhost';
    $_SERVER['REQUEST_URI']='/'; $_SERVER['SCRIPT_NAME']='/index.php';
    $_SERVER['PHP_SELF']='/index.php'; $_SERVER['REQUEST_METHOD']='GET';
    $_SERVER['SERVER_PROTOCOL']='HTTP/1.1'; $_SERVER['SCRIPT_FILENAME']=JPATH_BASE.'/index.php';
    $_SERVER['REMOTE_ADDR']='127.0.0.1'; $_SERVER['SERVER_PORT']='80'; $_SERVER['HTTPS']='';
    require_once JPATH_BASE.'/includes/defines.php';
    require_once JPATH_BASE.'/includes/framework.php';
    $container = Joomla\CMS\Factory::getContainer();
    $container->alias('session.web','session.web.site')
        ->alias('session','session.web.site')
        ->alias('JSession','session.web.site')
        ->alias(\Joomla\CMS\Session\Session::class,'session.web.site')
        ->alias(\Joomla\Session\Session::class,'session.web.site')
        ->alias(\Joomla\Session\SessionInterface::class,'session.web.site');
    $app = $container->get(\Joomla\CMS\Application\SiteApplication::class);
    \Joomla\CMS\Factory::$application = $app;
    return $app;
}
