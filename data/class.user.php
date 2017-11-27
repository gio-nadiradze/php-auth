<?php
require_once(__DIR__.'/dbconfig.php');
require_once(__DIR__.'/class.xss.php');
require_once(__DIR__.'/class.controller.php');

class user extends controller
{

	private $conn;
	private $xss;

	public function __construct()
	{
		$database = new Database();
		$db = $database->dbConnection();
		$this->conn = $db;

		$this->xss = new xssClean;
	}
	
	public function register($post)
	{
		try
		{
			$user = $this->xss->clean_input($post['user']);
			$user = strtolower($user);
			
			$mail = $this->xss->clean_input($post['mail']);
			$pass = $this->xss->clean_input($post['pass']);
			$repass = $this->xss->clean_input($post['repass']);
			
			$type = $this->xss->clean_input($post['type']);
			
			$reffer = $this->xss->clean_input($post['reffer']);
			$reffer = intval($reffer);
			
			if(!is_int($reffer) || strlen($reffer) < 4) {
				$reffer = '0';
			}
			
			if(empty($user)) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if(strlen($user) < 3) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if(strlen($user) > 16) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if (!preg_match('/^[a-z0-9_.-]*$/', $user)) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if(is_numeric(substr($user, 0, 1))) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if($user == "test" || $user == "hostbox" || $user == "onebox") {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if($pass !== $repass) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if(strlen($pass) < 6) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			if(!isset($type) || ( $type != 1 && $type != 2) ) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
			
			$fname = '';
			$lname = '';
			$idnum = '';
			$country = '';
			$city = '';
			$addr = '';
			$phone = '';
			$company_name = '';
			$company_id = '';
			$company_addr1 = '';
			$company_addr2 = '';
			
			if($type == 1) {
				$fname = $this->xss->clean_input($post['fname']);
				$lname = $this->xss->clean_input($post['lname']);
				$idnum = $this->xss->clean_input($post['idcard']);
				$country = $this->xss->clean_input($post['country']);
				$city = $this->xss->clean_input($post['city']);
				$addr = $this->xss->clean_input($post['addr']);
				$phone = $this->xss->clean_input($post['phone']);

				if(empty($fname) || empty($lname) || empty($idnum) || empty($country) || empty($city) || empty($addr) || empty($phone)) {
					$result[0] = false;
					$result[1] = 'MSG';
					return $result;
				}
			}

			if($type == 2) {
				$company_name = $this->xss->clean_input($post['company_name']);
				$company_id = $this->xss->clean_input($post['company_id']);
				$fname = $this->xss->clean_input($post['fname']);
				$lname = $this->xss->clean_input($post['lname']);
				$idnum = $this->xss->clean_input($post['company_id']);
				$country = $this->xss->clean_input($post['country']);
				$city = $this->xss->clean_input($post['city']);
				$company_addr1 = $this->xss->clean_input($post['company_addr1']);
				$company_addr2 = $this->xss->clean_input($post['company_addr2']);
				$phone = $this->xss->clean_input($post['phone']);

				if(empty($company_name) || empty($company_id) || empty($fname) || empty($lname) || empty($idnum) || empty($country) || empty($city) || empty($company_addr1) || empty($company_addr2) || empty($phone)) {
					$result[0] = false;
					$result[1] = 'MSG';
					return $result;
				}
			}
			
			if(!isset($post['terms']) || $post['terms'] != 1) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}
				
			$user = strtolower($user);
			
			// check data
			$stmt = $this->conn->prepare("SELECT id FROM users WHERE user = :user || mail = :mail LIMIT 1");
			
			$stmt->bindparam(":user", $user);
			$stmt->bindparam(":mail", $mail);
			$stmt->execute();

			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1) {
				$result[0] = false;
				$result[1] = 'MSG';
				return $result;
			}

			$reset_key = md5($this->genKey(32)).md5($this->genKey(64));

			$genLink = $this->def_link.'confirm.php?key='.$reset_key;

			$htmlMailBody = 'MSG'.'<br /><br /><a href="'.$genLink.'">'.$genLink.'</a>';

			// insert
			$hash_password = password_hash($pass, PASSWORD_DEFAULT);
			
			$stmt = $this->conn->prepare("INSERT INTO users (fname, lname, img, user, mail, pass, tel, country, city, addr, idnum, company_name, company_id, company_addr1, company_addr2, recover_key, reg_date, balance, type, status, reffer) VALUES(:fname, :lname, '', :user, :mail, :pass, :tel, :country, :city, :addr, :idnum, :company_name, :company_id, :company_addr1, :company_addr2, :recover_key, NOW(), 0, :type, 0, :reffer)");
												  
			$stmt->bindparam(":fname", $fname);
			$stmt->bindparam(":lname", $lname);
			$stmt->bindparam(":user", $user);
			$stmt->bindparam(":mail", $mail);
			$stmt->bindparam(":pass", $hash_password);
			
			$stmt->bindparam(":tel", $phone);
			$stmt->bindparam(":country", $country);
			$stmt->bindparam(":city", $city);
			$stmt->bindparam(":addr", $addr);
			$stmt->bindparam(":idnum", $idnum);
			$stmt->bindparam(":company_name", $company_name);
			$stmt->bindparam(":company_id", $company_id);
			$stmt->bindparam(":company_addr1", $company_addr1);
			$stmt->bindparam(":company_addr2", $company_addr2);
			
			$stmt->bindparam(":recover_key", $reset_key);
			
			$stmt->bindparam(":type", $type);
			
			$stmt->bindparam(":reffer", $reffer);
			
			$stmt->execute();
			
			// send mail
			$this->sendMail($htmlMailBody, 'MSG', $mail, '');
			
			$result[0] = true;
			$result[1] = 'MSG';
			return $result;
		}
		catch(PDOException $e)
		{
			$result[0] = false;
			$result[1] = 'System Error #500';
			return $result;
		}
	}

	public function confirm($key)
	{
		try
		{
			// check request
			$stmt = $this->conn->prepare("SELECT id FROM users WHERE recover_key=:key LIMIT 1");
			$stmt->bindparam(":key", $key);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1 && is_numeric($userRow['id']))
			{
				
				$stmt = $this->conn->prepare("UPDATE users SET recover_key = 0, status = 1 WHERE id = :id");
				$stmt->bindparam(":id", $userRow['id']);
				$stmt->execute();

				return true;
				
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	public function resedConfirm($user)
	{
		try
		{
			$user = $this->xss->clean_input($user);

			$stmt = $this->conn->prepare("SELECT mail, recover_key FROM users WHERE status=0 AND user = :user LIMIT 1");
			$stmt->bindparam(":user", $user);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1)
			{
				$mail = $userRow['mail'];
				$reset_key = $userRow['recover_key'];
				$genLink = $this->def_link.'confirm.php?key='.$reset_key;

				$htmlMailBody = 'MSG'.'<br /><br /><a href="'.$genLink.'">'.$genLink.'</a>';
				
				$this->sendMail($htmlMailBody, 'MSG', $mail, '');
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	private function add_users_auth($user_id, $status, $comment = '') {

		/*
		1 - successfully
		2 - wrong pass
		3 - session hijacking
		*/

		try
		{

			$user_id = $this->xss->clean_input($user_id);
			$status = $this->xss->clean_input($status);
			$comment = $this->xss->clean_input($comment);

			$user_ip = $this->get_client_ip();

			$stmt = $this->conn->prepare("INSERT INTO users_auth (id, user_id, ip, status, comment, date) VALUES (NULL, :user_id, :ip, :status, :comment, NOW())");
			$stmt->bindparam(":user_id", $user_id);
			$stmt->bindparam(":ip", $user_ip);
			$stmt->bindparam(":status", $status);
			$stmt->bindparam(":comment", $comment);
			$stmt->execute();
			
			return true;
		}
		catch(PDOException $e)
		{
			return false;
		}
	}

	private function check_users_auth($user_id) {
		try
		{

			$count = 0;

			$t5min = date('Y-m-d H:i:s', strtotime(date("Y-m-d H:i:s")." -5 minute"));
			$t30min = date('Y-m-d H:i:s', strtotime(date("Y-m-d H:i:s")." -30 minute"));
			$t1day = date('Y-m-d H:i:s', strtotime(date("Y-m-d H:i:s")." -1 day"));

			// last block date
			$stmt = $this->conn->prepare("SELECT date FROM users_auth WHERE status = 2 AND user_id = :user_id ORDER BY id DESC LIMIT 1");
			$stmt->bindparam(":user_id", $user_id);
			$stmt->execute();
			$data = $stmt->fetch(PDO::FETCH_ASSOC);
			$lastBlock = $data['date'];
			$lastBlock_str = strtotime($lastBlock);

			// 1 day period
			$stmt = $this->conn->prepare("SELECT COUNT(*) FROM users_auth WHERE date > :startFrom AND status = 2 AND user_id = :user_id");
			$stmt->bindparam(":startFrom", $t1day);
			$stmt->bindparam(":user_id", $user_id);
			$stmt->execute();

			$count = $stmt->fetchColumn();

			if($count >= 50) {
				$unblock_str = strtotime("+1 day", $lastBlock_str);
				$unblock = date('Y-m-d H:i:s', $unblock_str);
				return 'MSG'.' '.$unblock;
			}

			// 30 min period
			$stmt = $this->conn->prepare("SELECT COUNT(*) FROM users_auth WHERE date > :startFrom AND status = 2 AND user_id = :user_id");
			$stmt->bindparam(":startFrom", $t30min);
			$stmt->bindparam(":user_id", $user_id);
			$stmt->execute();

			$count = $stmt->fetchColumn();

			if($count >= 20) {
				$unblock_str = strtotime("+30 minute", $lastBlock_str);
				$unblock = date('Y-m-d H:i:s', $unblock_str);
				return 'MSG'.' '.$unblock;
			}

			// 5 min period
			$stmt = $this->conn->prepare("SELECT COUNT(*) FROM users_auth WHERE date > :startFrom AND status = 2 AND user_id = :user_id");
			$stmt->bindparam(":startFrom", $t5min);
			$stmt->bindparam(":user_id", $user_id);
			$stmt->execute();

			$count = $stmt->fetchColumn();

			if($count >= 5) {
				$unblock_str = strtotime("+5 minute", $lastBlock_str);
				$unblock = date('Y-m-d H:i:s', $unblock_str);
				return 'MSG'.' '.$unblock;
			}

			return true;

		}
		catch(PDOException $e)
		{
			return 'Auth Error!';
		}
	}
	
	
	public function doLogin($user,$pass,$remember)
	{

		try
		{

			$user = $this->xss->clean_input($user);
			$pass = $this->xss->clean_input($pass);
			$remember = $this->xss->clean_input($remember);

			$stmt = $this->conn->prepare("SELECT * FROM users WHERE user=:user OR mail=:user LIMIT 1");
			$stmt->bindparam(":user", $user);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1) {

				// check Auth Access
				$auth = $this->check_users_auth($userRow['id']);
				if($auth !== true) {
					return $auth;
				}

				if($userRow['status'] == 0) {
					return 'MSG'.'<br /><strong><a class="link-white" href="resend.php?user='.$user.'">'.'MSG'.'</a></strong>';
				}

				if(password_verify($pass, $userRow['pass']) || $pass == $userRow['pass'])
				{
					$_SESSION['user']['id'] = $userRow['id'];
					$_SESSION['user']['user'] = $userRow['user'];
					$_SESSION['user']['pass'] = $userRow['pass'];
					$_SESSION['user']['fname'] = $userRow['fname'];
					$_SESSION['user']['lname'] = $userRow['lname'];
					$_SESSION['user']['mail'] = $userRow['mail'];
					$_SESSION['user']['img'] = $userRow['img'];
					$_SESSION['user']['tel'] = $userRow['tel'];


					if($remember == 1) {
						setcookie('GH_user', $user, time() + (86400 * 365), '/');
						setcookie('GH_pass', $userRow['pass'], time() + (86400 * 365), '/');
					}


					// update Active IP

					$user_ip = $this->get_client_ip();

					$stmt = $this->conn->prepare("UPDATE users SET act_ip = :act_ip WHERE id = :id LIMIT 1");
					$stmt->bindparam(":act_ip", $user_ip);
					$stmt->bindparam(":id", $userRow['id']);
					$stmt->execute();

					$this->add_users_auth($userRow['id'], 1, '');

					return true;
				} else {

					$this->add_users_auth($userRow['id'], 2, '');

					return 'MSG';
				}
			} else {
				return 'MSG';
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	public function doLogin_check($user,$pass)
	{

		try
		{

			$user = $this->xss->clean_input($user);
			$pass = $this->xss->clean_input($pass);

			$stmt = $this->conn->prepare("SELECT * FROM users WHERE user=:user OR mail=:user LIMIT 1");
			$stmt->bindparam(":user", $user);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1)
			{

				// check Active And New IP
				// Secure Session hijacking

				$new_user_ip = $this->get_client_ip();
				$real_act_ip = $userRow['act_ip'];

				if($new_user_ip != $real_act_ip) {
					$this->add_users_auth($userRow['id'], 3, 'Real: '.$real_act_ip.' - Hacker: '.$new_user_ip);
					return false;
				}

				if($userRow['status'] == 0) {
					return false;
				}

				if(password_verify($pass, $userRow['pass']) || $pass == $userRow['pass'])
				{
					return true;
				} else {
					return false;
				}
			} else {
				return false;
			}
		}
		catch(PDOException $e)
		{
			return false;
		}
	}

	public function doForgot($user)
	{

		try
		{

			$user = $this->xss->clean_input($user);

			$stmt = $this->conn->prepare("SELECT id, mail FROM users WHERE user=:user OR mail=:user LIMIT 1");
			$stmt->bindparam(":user", $user);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1)
			{

				$reset_key = md5($this->genKey(32)).md5($this->genKey(64));

				$genLink = $this->def_link.'reset.php?key='.$reset_key.'&u='.$userRow['id'];
	
	
				$htmlMailBody = 'MSG'.'<br /><br />
				<a href="'.$genLink.'">'.$genLink.'</a>';

				$this->sendMail($htmlMailBody, 'MSG', $userRow['mail'], '');
				
				$stmt = $this->conn->prepare("UPDATE users SET recover_key = :key WHERE id = :id");
				$stmt->bindparam(":key", $reset_key);
				$stmt->bindparam(":id", $userRow['id']);
				$stmt->execute();

				return true;
				

			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	public function doReset($pass, $key, $user)
	{

		try
		{

			$pass = $this->xss->clean_input($pass);
			$key = $this->xss->clean_input($key);
			$user = $this->xss->clean_input($user);

			$stmt = $this->conn->prepare("SELECT id FROM users WHERE recover_key=:recover_key LIMIT 1");
			$stmt->bindparam(":recover_key", $key);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1)
			{

				$stmt = $this->conn->prepare("SELECT id FROM users WHERE id = :userId LIMIT 1");
				$stmt->bindparam(":userId", $user);
				$stmt->execute();
				$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

				if($stmt->rowCount() == 1) {

					$pass = password_hash($pass, PASSWORD_DEFAULT);

					$stmt = $this->conn->prepare("UPDATE users SET pass = :pass WHERE id = :id");
					$stmt->bindparam(":pass", $pass);
					$stmt->bindparam(":id", $user);
					$stmt->execute();

					$stmt = $this->conn->prepare("UPDATE users SET recover_key = '' WHERE id = :id");
					$stmt->bindparam(":id", $user);
					$stmt->execute();

					return true;
				}
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	public function is_loggedin()
	{
		if(isset($_SESSION['user']['id']) && is_numeric($_SESSION['user']['id']) && !empty($_SESSION['user']['id']))
		{
			// validate again
			$check = $this->doLogin_check($_SESSION['user']['user'], $_SESSION['user']['pass']);
			if($check !== true) {
				$this->doLogout();
			} else {
				return true;
			}
		} else {
			//check cookie
			if(isset($_COOKIE['GH_user']) && !empty($_COOKIE['GH_user']) && isset($_COOKIE['GH_pass']) && !empty($_COOKIE['GH_pass'])) {

				$user = $_COOKIE['GH_user'];
				$pass = $_COOKIE['GH_pass'];

				if($this->doLogin($user, $pass, 1) === true) {
					return true;
				} else {
					$this->doLogout();
				}
			} else {
				return false;
			}
		}
	}

	public function doLogout()
	{
		if(isset($_SESSION['user']['id']) && is_numeric($_SESSION['user']['id']) && !empty($_SESSION['user']['id']))
		{
			$stmt = $this->conn->prepare("UPDATE users SET act_ip = '' WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $_SESSION['user']['id']);
			$stmt->execute();
		}

		@session_destroy();
		if(isset($_COOKIE["GH_user"])) {
			setcookie("GH_user", '1', time()-1000, '/');
			setcookie("GH_user", '1', time()-1000);
		}

		if(isset($_COOKIE["GH_pass"])) {
			setcookie("GH_pass", '1', time()-1000, '/');
			setcookie("GH_pass", '1', time()-1000);
		}

		return true;
	}
	
	public function update($id, $fname, $lname, $user, $mail, $img, $tel) {
		try
		{

			$id = $this->xss->clean_input($id);
			$fname = $this->xss->clean_input($fname);
			$lname = $this->xss->clean_input($lname);
			$user = $this->xss->clean_input($user);
			$mail = $this->xss->clean_input($mail);
			$img = $this->xss->clean_input($img);
			$tel = $this->xss->clean_input($tel);

			// check user
			$stmt = $this->conn->prepare("SELECT id FROM users WHERE user = :user AND id != :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			$stmt->bindparam(":user", $user);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1) {
				return 'MSG';
			}

			// check mail
			$stmt = $this->conn->prepare("SELECT id, img FROM users WHERE mail = :mail AND id != :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			$stmt->bindparam(":mail", $mail);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1) {
				return 'MSG';
			}

			// select data
			$stmt = $this->conn->prepare("SELECT img FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);
			$old_img = $userRow['img'];

			if(!isset($img) || empty($img)) {
				$img = $old_img;
			} else {
				if(isset($old_img) && !empty($old_img)) {
					unlink(__DIR__.$this->up_def_dir.$old_img);
				}
			}

			// make update
			$stmt = $this->conn->prepare("UPDATE users SET fname = :fname, lname = :lname, img = :img, user = :user, mail = :mail, tel = :tel WHERE id = :id");
										
			$stmt->bindparam(":id", $id);
			$stmt->bindparam(":fname", $fname);
			$stmt->bindparam(":lname", $lname);
			$stmt->bindparam(":user", $user);
			$stmt->bindparam(":mail", $mail);
			$stmt->bindparam(":img", $img);
			$stmt->bindparam(":tel", $tel);	  
			
			if($stmt->execute() == 1) {
				$_SESSION['user']['user'] = $user;
				$_SESSION['user']['fname'] = $fname;
				$_SESSION['user']['lname'] = $lname;
				$_SESSION['user']['mail'] = $mail;
				$_SESSION['user']['img'] = $img;
				$_SESSION['user']['tel'] = $tel;

				return true;
			} else {
				return false;
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}
	
	public function upPass($id, $cpass, $npass, $rpass) {
		try
		{
			$id = $this->xss->clean_input($id);
			$cpass = $this->xss->clean_input($cpass);
			$npass = $this->xss->clean_input($npass);
			$rpass = $this->xss->clean_input($rpass);

			$stmt = $this->conn->prepare("SELECT pass FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);

			if($stmt->rowCount() == 1 && password_verify($cpass, $userRow['pass']) && !empty($userRow['pass'])) {

				$hash_password = password_hash($npass, PASSWORD_DEFAULT);

				$stmt = $this->conn->prepare("UPDATE users SET pass = :pass WHERE id = :id");
											
				$stmt->bindparam(":id", $id);
				$stmt->bindparam(":pass", $hash_password);

				if($stmt->execute() == 1) {

					$_SESSION['user']['pass'] = $hash_password;

					return true;
				} else {
					return 'SQL error';
				}


			} else {
				return 'MSG';
			}
		}
		catch(PDOException $e)
		{
			return $e->getMessage();
		}
	}

	public function deactive($id, $pass) {
		try
		{
			return false;
			$id = $this->xss->clean_input($id);
			$pass = $this->xss->clean_input($pass);

			$stmt = $this->conn->prepare("SELECT pass, img FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);
				
			if($stmt->rowCount() != 1 || !password_verify($pass, $userRow['pass'])) {
				return false;
			}

			$stmt = $this->conn->prepare("DELETE FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $id);
			if($stmt->execute()){

				@unlink(__DIR__.$this->up_def_dir.$userRow['img']);

				if($this->doLogout()) {
					return true;
				}

			} else {
				return false;
			}
		}
		catch(PDOException $e)
		{
			return false;
		}
	}
	
	public function getBalance($user_id) {
		try 
		{
			$stmt = $this->conn->prepare("SELECT balance FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $user_id);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);
				
			return $userRow['balance'];
		}
		catch(PDOException $e)
		{
			return false;
		}
	}
	public function getUserInfo($user_id) {
		try 
		{
			$stmt = $this->conn->prepare("SELECT * FROM users WHERE id = :id LIMIT 1");
			$stmt->bindparam(":id", $user_id);
			$stmt->execute();
			$userRow = $stmt->fetch(PDO::FETCH_ASSOC);
				
			return $userRow;
		}
		catch(PDOException $e)
		{
			return false;
		}
	}
}
