<?php
/*
 RCDevs OpenOTP Plugin for RoundCube Webmail v1.2.3
 Copyright (c) 2010-2016 RCDevs, All rights reserved.
 
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
			rcube::write_log('errors', 'No OpenOTP config file found');
			$this->error = 'No OpenOTP config file found';
			return $args;
		}
		if (!$this->openotp_auth->checkFile('openotp.wsdl','Could not load OpenOTP WSDL file')){
			rcube::write_log('errors', 'Could not load OpenOTP WSDL file');
			$this->error = 'Could not load OpenOTP WSDL file';
			return $args;
		}
		// Check SOAP extension is loaded
		if (!$this->openotp_auth->checkSOAPext()){
			rcube::write_log('errors', 'Your PHP installation is missing the SOAP extension');
			$this->error = 'Your PHP installation is missing the SOAP extension';
			return $args;
		}
		// require server_url
		if (!$this->openotp_auth->getServer_url()) {
			rcube::write_log('errors', 'OpenOTP server URL is not configured');
			$this->error = 'OpenOTP server URL is not configured';
			return $args;
		}
		
        return $args;
    }


    public function login_form($form) {
		
		$rcmail = rcmail::get_instance();

		if ($this->username != NULL && $this->state != NULL && $this->ldappw != NULL){
			$otp_script = $this->openotp_auth->getOverlay($this->otpChallenge, $this->u2fChallenge, $this->message, $this->username, $this->state, $this->timeout, $this->ldappw, $this->domain);
			//$rcmail->output->add_header('<script type="text/javascript" src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>');
			$rcmail->output->add_header('<script type="text/javascript" src="plugins/openotp_authentication/fidou2f.js"></script>');
			$rcmail->output->add_script($otp_script, 'docready');
		}		

		$inline_js = "
			jQuery('#login-form form').submit(function () {
				jQuery(this).prepend(\"<span style='color:white; text-shadow: 0px 1px 1px black; font-size:0.9em;'>Processing request. Please wait...</span>\");
				return true;
			});";

		$rcmail->output->add_script($inline_js, 'docready');
		
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

		// Get context cookie
		$context_name = $this->openotp_auth->getContext_name();
		$context_size = $this->openotp_auth->getContext_size();
		$context_time = $this->openotp_auth->getContext_time();
		
		if (isset($_COOKIE[$context_name])) $context = $_COOKIE[$context_name];
		else $context = NULL;	

		$username = rcube_utils::get_input_value('openotp_username', rcube_utils::INPUT_POST) != NULL ? rcube_utils::get_input_value('openotp_username', rcube_utils::INPUT_POST) : $data['user'];
		$password = rcube_utils::get_input_value('openotp_password', rcube_utils::INPUT_POST) != NULL ? rcube_utils::get_input_value('openotp_password', rcube_utils::INPUT_POST) : $data['pass'];

		$u2f = $_POST['openotp_u2f'] != NULL ? $_POST['openotp_u2f'] : "";
		$state = rcube_utils::get_input_value('openotp_state', rcube_utils::INPUT_POST);
		$ldappw = rcube_utils::get_input_value('openotp_ldappw', rcube_utils::INPUT_POST);

		// Add domain if system is set to do that
		if (!empty($this->rc->config->get("username_domain")) && strpos($username, '@')===false) {
		    $username .= '@'.$this->rc->config->get("username_domain");
		}
		
		if (empty($username)) {
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
			rcube::write_log('errors', 'Plugin OpenOTP authentication configured and disabled');
			return $data;
		}
		
		if ($state != NULL) {
			if (!$ldappw) {
				rcube::write_log('errors', 'No LDAP password provided for user '.$data['user']);
				$this->error = 'No LDAP password provided for user '.$data['user'];
				$data['valid'] = false;                                                                                           
				return $data;
			}
			// OpenOTP Challenge
			$resp = $this->openotp_auth->openOTPChallenge($username, $this->domain, $state, $password, $u2f);
		} else {
			// OpenOTP Login
			$resp = $this->openotp_auth->openOTPSimpleLogin($username, $this->domain, utf8_encode($password), $_SERVER['REMOTE_ADDR'], $context);
			if(!$resp){
				rcube::write_log('errors', 'Could not load OpenOTP WSDL file');
				$data['valid'] = false;
				return $data;				
			}
		}
		
		if (!$resp || !isset($resp['code'])) {
			rcube::write_log('errors', 'Invalid OpenOTP response for user '.$data['user']);
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
				
				// set context cookie
				if (extension_loaded('openssl')) {			
					if (strlen($context) != $context_size) $context = bin2hex(openssl_random_pseudo_bytes($context_size/2));
					setcookie($context_name, $context, time()+$context_time, '/', NULL, true, true);
				}				
				
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
				rcube::write_log('errors', 'Invalid OpenOTP response code '.$resp['code'].' for user '.$data['user']);
				$this->error = 'Internal system error, please contact administrator';
				$data['valid'] = false;
				break;
		}

		return $data;
	}
}

?>