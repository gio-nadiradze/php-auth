<?php
class Database
{
    private $host = "localhost";
    private $db_name = "db_name";
    private $username = "db_user";
    private $password = "db_pass";
    public $conn;
     
    public function dbConnection()
	  {
     
	      $this->conn = null;    
        try
		    {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name.";charset=utf8", $this->username, $this->password);
			      $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);	
        }
		    catch(PDOException $exception)
		    {
            return false;
        }
         
        return $this->conn;
    }
}
