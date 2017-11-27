<?php
require_once(__DIR__.'/vendor/swift/swift_required.php');
require_once(__DIR__.'/class.html2text.php');

class mailer
{

  private $from_mail = "no-reply@domain.com";
  private $from_name = "From Name";

  private $smtp_host = "host";
  private $smtp_port = "25";
  private $smtp_user = "user@domain.com";
  private $smtp_pass = "smtp_pass";
  private $encryption = "tls";
  private $html2text;

  public function send($text, $subj, $to, $attach = '')
  {
    $plain = new \Html2Text\Html2Text($text);
    $plain = $plain->getText();

    // Create the SMTP configuration
    $transport = Swift_SmtpTransport::newInstance($this->smtp_host, $this->smtp_port, $this->encryption);
    $transport->setUsername($this->smtp_user);
    $transport->setPassword($this->smtp_pass);

	if(!empty($attach)) {
		
		$message = Swift_Message::newInstance()
		->setCharset('UTF-8')
		->setTo($to)
		->setFrom($this->from_mail, $this->from_name)
		->setSubject($subj)
		->setBody($plain)
		->addPart($text, 'text/html')
		->setReplyTo('support@hostbox.ge')
		->attach(Swift_Attachment::fromPath($attach));
			
	} else {
			
		$message = Swift_Message::newInstance()
		->setCharset('UTF-8')
		->setTo($to)
		->setFrom($this->from_mail, $this->from_name)
		->setSubject($subj)
		->setBody($plain)
		->setReplyTo('support@hostbox.ge')
		->addPart($text, 'text/html');
			
	}

    $mailer = Swift_Mailer::newInstance($transport);
    
    if($mailer->send($message)) {
      return true;
    }

  }
}
