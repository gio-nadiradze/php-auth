<?php
require_once(__DIR__.'/mailconfig.php');

class controller {
	
	public $up_def_dir = '/upload/img/profile/';
	public $def_link = 'https://www.domain.com/';
	
	public $mailTemplate = '<!doctype html><html><head><meta charset="utf-8"><title>TITLE</title></head><body>[@BODY@]<div style="color:#999;font-style:italic">[@DATE@]</div></body></html>';

	public function getResserPrc($user_id) {
		if(in_array($user_id, $this->vipReseller)) {
			return $this->vipResselerPer;
		} else {
			return $this->reseller;
		}
	}

	public function getVipUsers() {
		return $this->vipReseller;
	}
	
	public function genKey($length = 10) {
	    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	    $charLength = strlen($chars);
	    $genStr = '';
	    for ($i = 0; $i < $length; $i++) {
	        $genStr .= $chars[rand(0, $charLength - 1)];
	    }
	    return $genStr;
	}
	
	public function genKeyH($length = 10) {
	    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@_-+.';
	    $charLength = strlen($chars);
	    $genStr = '';
	    for ($i = 0; $i < $length; $i++) {
	        $genStr .= $chars[rand(0, $charLength - 1)];
	    }
	    return $genStr;
	}
	
	public function get_client_ip() {
	    $ipaddress = '';
	    if ($_SERVER['HTTP_CLIENT_IP'])
	        $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
	    else if($_SERVER['HTTP_X_FORWARDED_FOR'])
	        $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
	    else if($_SERVER['HTTP_X_FORWARDED'])
	        $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
	    else if($_SERVER['HTTP_FORWARDED_FOR'])
	        $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
	    else if($_SERVER['HTTP_FORWARDED'])
	        $ipaddress = $_SERVER['HTTP_FORWARDED'];
	    else if($_SERVER['REMOTE_ADDR'])
	        $ipaddress = $_SERVER['REMOTE_ADDR'];
	    else
	        $ipaddress = 'UNKNOWN';
	 
	    return $ipaddress;
	}

	public function redirect($url)
	{
		header("Location: ".$url);
	}
	
	public function sendMail($html, $title, $to, $attach) {
		try 
		{
			$body = str_replace('[@BODY@]', $html, $this->mailTemplate);
			$body = str_replace('[@DATE@]', date('H:i:s d.m.Y'), $body);
			
			$mailer = new mailer;
			$mailer->send($body, $title, $to, $attach);
			
			return true;
		}
		catch(PDOException $e)
		{
			return false;
		}
	}
}
