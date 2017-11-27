<?php
date_default_timezone_set('YOUR_TIME_ZONE');

function generic_autoloader($var) {
	$path = __DIR__.'/'.$var.'.php';
  if (file_exists($path)) {
    require_once($path);
  }
}
spl_autoload_register('generic_autoloader');
