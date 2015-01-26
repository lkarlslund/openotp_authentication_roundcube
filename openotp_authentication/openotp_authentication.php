<?php
/*
 RCDevs OpenOTP Plugin for RoundCube Webmail v2.0
 Copyright (c) 2010-2012 RCDevs, All rights reserved.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
  
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

class openotp_authentication extends rcube_plugin {
    public $task = 'login';
    private $state = NULL;
    private $message = NULL;
    private $timeout = NULL;
    private $ldappw = NULL;
    private $domain = NULL;
    private $username = NULL;
	private $error = NULL;
	private $openotp_auth = NULL;
    

    public function init() {
		$this->load_config();
	    $this->add_hook('startup', array($this, 'startup'));
		$this->add_hook('authenticate', array($this, 'authenticate'));
		$this->add_hook('template_object_loginform', array($this, 'login_form'));
	    $rcmail = rcmail::get_instance();
		$this->rc = $rcmail;
	}
	

    public function startup($args)
    {
		
        $include_path = $this->home . PATH_SEPARATOR;
        $include_path .= ini_get('include_path');
        set_include_path($include_path);

		$this->openotp_auth = new openotp($this, "plugins/openotp_authentication");
		
		// Check if config files are available		
		if (!$this->openotp_auth->checkFile('config.inc.php','No OpenOTP config file found')){
			write_log('errors', 'No OpenOTP config file found');
			$this->error = 'No OpenOTP config file found';
			return $args;
		}
		if (!$this->openotp_auth->checkFile('openotp.wsdl','Could not load OpenOTP WSDL file')){
			write_log('errors', 'Could not load OpenOTP WSDL file');
			$this->error = 'Could not load OpenOTP WSDL file';
			return $args;
		}
		// Check SOAP extension is loaded
		if (!$this->openotp_auth->checkSOAPext()){
			write_log('errors', 'Your PHP installation is missing the SOAP extension');
			$this->error = 'Your PHP installation is missing the SOAP extension';
			return $args;
		}
		// require server_url
		if (!$this->openotp_auth->getServer_url()) {
			write_log('errors', 'OpenOTP server URL is not configured');
			$this->error = 'OpenOTP server URL is not configured';
			return $args;
		}
		
        return $args;
    }


    public function login_form($form) {
		
		if ($this->username != NULL && $this->state != NULL && $this->ldappw != NULL){
			$otp_script = $this->openotp_auth->getOverlay($this->otpChallenge, $this->u2fChallenge, $this->message, $this->username, $this->state, $this->timeout, $this->ldappw, $this->domain);
			$rcmail = rcmail::get_instance();
			$rcmail->output->add_header('<script type="text/javascript" src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>');
			$rcmail->output->add_script($otp_script, 'docready');				
		}		
		
		$table = new html_table(array('cols' => 1));
		if ($this->message != NULL) $table->add('title', html::label('openotmessage', '<font color=red>'.$this->message.'</font>'));
		if ($this->error != NULL) $table->add('title', html::label('openotmessage', '<font color=red><b>'.$this->error.'</b></font>'));
		$form['content'] = $table->show().$form['content'];
		
		return $form;
    }
	
	
    
	public function authenticate($data) {

		if ($this->error != NULL){
			$data['valid'] = false;
			return $data;
		}
		
		$username = get_input_value('openotp_username', RCUBE_INPUT_POST) != NULL ? get_input_value('openotp_username', RCUBE_INPUT_POST) : $data['user'];
		$password = get_input_value('openotp_password', RCUBE_INPUT_POST) != NULL ? get_input_value('openotp_password', RCUBE_INPUT_POST) : $data['pass'];
		$u2f = $_POST['openotp_u2f'] != NULL ? $_POST['openotp_u2f'] : "";
		$state = get_input_value('openotp_state', RCUBE_INPUT_POST);
		$ldappw = get_input_value('openotp_ldappw', RCUBE_INPUT_POST);

		
		if (empty($username) || empty($ldappw)) {
			$data['valid'] = false;
			return $data;
		}

		$t_domain = $this->openotp_auth->getDomain($username);
		if (is_array($t_domain)){
			$username = $t_domain['username'];
			$this->domain = $t_domain['domain'];
		}elseif($_POST['openotp_domain'] != NULL) $this->domain = $_POST['openotp_domain'];
		else $this->domain = $t_domain;

		if (!$this->openotp_auth->enableOpenotp_auth()) {
			write_log('errors', 'Plugin OpenOTP authentication configured and disabled');
			return $data;
		}
		
		if ($state != NULL) {
			if (!$ldappw) {
				write_log('errors', 'No LDAP password provided for user '.$data['user']);
				$this->error = 'No LDAP password provided for user '.$data['user'];
				$data['valid'] = false;                                                                                           
				return $data;
			}
			// OpenOTP Challenge
			$resp = $this->openotp_auth->openOTPChallenge($username, $this->domain, $state, $password, $u2f);
		} else {
			// OpenOTP Login
			$resp = $this->openotp_auth->openOTPSimpleLogin($username, $this->domain, utf8_encode($password), $_SERVER['REMOTE_ADDR']);
			if(!$resp){
				write_log('errors', 'Could not load OpenOTP WSDL file');
				$data['valid'] = false;
				return $data;				
			}
		}
		
		if (!$resp || !isset($resp['code'])) {
			write_log('errors', 'Invalid OpenOTP response for user '.$data['user']);
			$this->error = 'Internal system error, please contact administrator';
			$data['valid'] = false;
			return $data;
		}

		switch ($resp['code']) {
			case 0:
				$this->message = $resp['message'];
				$data['abort'] = true;
				break;
			case 1:
				$data['user'] = $username;
				$data['pass'] = isset($ldappw) ? $ldappw : $password;
				$data['valid'] = true;
				break;
			case 2:
				$this->message = $resp['message'];
				$this->state = $resp['session'];
				$this->timeout = $resp['timeout'];
				$this->ldappw = $data['pass'];
				$this->otpChallenge = $resp['otpChallenge'];
				$this->u2fChallenge = $resp['u2fChallenge'];
				$this->username = $username;
				$data['abort'] = true;
				break;
			default:
				write_log('errors', 'Invalid OpenOTP response code '.$resp['code'].' for user '.$data['user']);
				$this->error = 'Internal system error, please contact administrator';
				$data['valid'] = false;
				break;
		}

		return $data;
	}
}

?>