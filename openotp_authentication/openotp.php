<?php
/*
 RCDevs OpenOTP Plugin for RoundCube Webmail v2.0
 Copyright (c) 2010-2013 RCDevs, All rights reserved.
 
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
class openotp {

	private $plugin;
	private $home;
	private $openotp_auth;
	private $server_url;
	private $client_id;
	private $default_domain;
	private $user_settings;                                                                           
	private $proxy_host;                                                                              
	private $proxy_port;                                                                              
	private $proxy_username;
	private $proxy_password;
	private $soap_client;

	public function __construct($openotp_plugin, $home=''){
		
        $this->plugin = $openotp_plugin->rc;
	    $this->home = $home;

		// load config		
		$this->openotp_auth = $this->plugin->config->get('openotp_auth');
		$this->server_url = $this->plugin->config->get('openotp_server_url');
		$this->client_id = $this->plugin->config->get('openotp_client_id');
		$this->default_domain = $this->plugin->config->get('openotp_default_domain');
		$this->user_settings = $this->plugin->config->get('openotp_user_settings');                                                                                   
		$this->proxy_host = $this->plugin->config->get('openotp_proxy_host');                                                                               
		$this->proxy_port = $this->plugin->config->get('openotp_proxy_port');                                                                               
		$this->proxy_username = $this->plugin->config->get('openotp_proxy_username');
		$this->proxy_password = $this->plugin->config->get('openotp_proxy_password');
	}
	
	public function checkFile($file)
	{
		if (!file_exists($this->home . '/'.$file)) {
			return false;
		}
		return true;
	}
	
	public function checkSOAPext()
	{
		if (!extension_loaded('soap')) {
			return false;
		}
		return true;
	}
	
	public function enableOpenotp_auth()
	{
		return $this->openotp_auth;
	}
		
	public function getServer_url()
	{
		return $this->server_url;
	}
		
	public function getDomain($username)
	{
		$pos = strpos($username, "\\");
		if ($pos) {
			$ret['domain'] = substr($username, 0, $pos);
			$ret['username'] = substr($username, $pos+1);
		} else {                                                                                                                      
			$ret = $this->default_domain;
		}
		return $ret;
	}
	
	public function getOverlay($otpChallenge, $u2fChallenge, $message, $username, $session, $timeout, $ldappw, $domain){
		$overlay = <<<EOT
		function addOpenOTPDivs(){
			var overlay_bg = document.createElement("div");
			overlay_bg.id = 'openotp_overlay_bg';
			overlay_bg.style.position = 'fixed'; 
			overlay_bg.style.top = '0'; 
			overlay_bg.style.left = '0'; 
			overlay_bg.style.width = '100%'; 
			overlay_bg.style.height = '100%'; 
			overlay_bg.style.background = 'grey';
			overlay_bg.style.zIndex = "9998"; 
			overlay_bg.style["filter"] = "0.9";
			overlay_bg.style["-moz-opacity"] = "0.9";
			overlay_bg.style["-khtml-opacity"] = "0.9";
			overlay_bg.style["opacity"] = "0.9";
		
			var tokenform = document.getElementsByName("_token")[0].value;
			var overlay = document.createElement("div");
			overlay.id = 'openotp_overlay';
			overlay.style.position = 'absolute'; 
			overlay.style.top = '165px'; 
			overlay.style.left = '50%'; 
			overlay.style.width = '280px'; 
			overlay.style.marginLeft = '-180px';
			overlay.style.padding = '65px 40px 50px 40px';
			overlay.style.background = 'url($this->home/openotp_banner.png) no-repeat top left #E4E4E4';
			overlay.style.border = '5px solid #545454';
			overlay.style.borderRadius = '10px';
			overlay.style.MozBorderRadius = '10px';
			overlay.style.WebkitBorderRadius = '10px';
			overlay.style.boxShadow = '1px 1px 12px #555555';
			overlay.style.WebkitBoxShadow = '1px 1px 12px #555555';
			overlay.style.MozBoxShadow = '1px 1px 12px #555555';
			overlay.style.zIndex = "9999"; 
			overlay.innerHTML = '<a style="position:absolute; top:-12px; right:-12px;" href="./" title="close"><img src="$this->home/openotp_closebtn.png"/></a>'
			+ '<style>'
			+ 'blink { -webkit-animation: blink 1s steps(5, start) infinite; -moz-animation:    blink 1s steps(5, start) infinite; -o-animation:      blink 1s steps(5, start) infinite; animation: blink 1s steps(5, start) infinite; }'
			+ '	@-webkit-keyframes blink { to { visibility: hidden; } }'
			+ '@-moz-keyframes blink { to { visibility: hidden; } }'
			+ '@-o-keyframes blink { to { visibility: hidden; } }'
			+ '@keyframes blink { to { visibility: hidden; } }'
			+ '</style>'				
			+ '<div style="background-color:red; margin:0 -40px 0; height:4px; width:360px; padding:0;" id="count_red"><div style="background-color:orange; margin:0; height:4px; width:360px; padding:0;" id="div_orange"></div></div>'
			+ '<form style="margin-top:30px;" action="./" name="login" id="login-form-otp"  method="POST">'
			+ '<input type="hidden" name="_token" value="'+tokenform+'">'
			+ '<input type="hidden" name="_task" value="login">'
			+ '<input type="hidden" name="_action" value="login">'
			+ '<input type="hidden" name="openotp_state" value="$session">'
			+ '<input type="hidden" name="openotp_domain" value="$domain">'
			+ '<input type="hidden" name="openotp_username" value="$username">'
			+ '<input type="hidden" name="openotp_ldappw" value="$ldappw">'
			+ '<table width="100%">'
			+ '<tr><td style="text-align:center; font-weight:bold; font-size:14px;">$message</td></tr>'
			+ '<tr><td id="timout_cell" style="text-align:center; padding-top:4px; font-weight:bold; font-style:italic; font-size:11px;">Timeout: <span id="timeout">$timeout seconds</span></td></tr>'
EOT;
	
			if( $otpChallenge || ( !$otpChallenge && !$u2fChallenge ) ){
			$overlay .= <<<EOT
			+ '<tr><td id="inputs_cell" style="text-align:center; padding-top:25px;"><input style="border:1px solid grey; background-color:white;" type="text" size=15 name="openotp_password">&nbsp;'
			+ '<input style="padding:3px 10px;" type="submit" value="Ok" class="button mainaction"></td></tr>'
EOT;
			}
			
			if( $u2fChallenge ){		
			$overlay .= "+ '<tr style=\"border:none;\"><td id=\"inputs_cell\" style=\"text-align:center; padding-top:5px; border:none;\"><input type=\"hidden\" name=\"openotp_u2f\" value=\"\">'";
				if( $otpChallenge ){		
					$overlay .= "+ '<b>U2F response</b> &nbsp; <blink id=\"u2f_activate\">[Activate Device]</blink></td></tr>'";
				} else { 
					$overlay .= "+ '<img src=\"" . $this->home . "/u2f.png\"><br><br><blink id=\"u2f_activate\">[Activate Device]</blink></td></tr>'";
				}			
			}		
			
			$overlay .= <<<EOT
			+ '</table></form>';
			
			document.body.appendChild(overlay_bg);    
			document.body.appendChild(overlay); 
		}
		
		addOpenOTPDivs();
		
		/* Compute Timeout */	
		var c = $timeout;
		var base = $timeout;
		function count()
		{
			plural = c <= 1 ? "" : "s";
			document.getElementById("timeout").innerHTML = c + " second" + plural;
			var div_width = 360;
			var new_width =  Math.round(c*div_width/base);
			document.getElementById('div_orange').style.width=new_width+'px';
			
			if(c == 0 || c < 0) {
				c = 0;
				clearInterval(timer);
				document.getElementById("timout_cell").innerHTML = " <b style='color:red;'>Login timedout!</b> ";
				document.getElementById("inputs_cell").innerHTML = "<input style='padding:3px 20px;' type='button' value='Retry' class='button mainaction' onclick='window.location.href=\"./\"'>";
			}
			c--;
		}
		count();
		
		
		function getInternetExplorerVersion() {
		
			var rv = -1;
		
			if (navigator.appName == "Microsoft Internet Explorer") {
				var ua = navigator.userAgent;
				var re = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
				if (re.exec(ua) != null)
					rv = parseFloat(RegExp.$1);
			}
			return rv;
		}
		
		var ver = getInternetExplorerVersion();
		
		if (navigator.appName == "Microsoft Internet Explorer"){
			if (ver <= 10){
				toggleItem = function(){
					
				    var el = document.getElementsByTagName("blink")[0];
				    if (el.style.display === "block") {
				        el.style.display = "none";
				    } else {
				        el.style.display = "block";
				    }
				}
				var t = setInterval(function() {toggleItem; }, 1000);
			}
		}
		
		var timer = setInterval(function() {count();  }, 1000);
EOT;

		if( $u2fChallenge ) $overlay .= " if (typeof u2f !== 'object' || typeof u2f.sign !== 'function'){ var u2f_activate = document.getElementById('u2f_activate'); u2f_activate.innerHTML = '[Not Supported]'; u2f_activate.style.color='red'; }" . "\r\n";
		if( $u2fChallenge ) $overlay .= " else { console.log(".$u2fChallenge.");  u2f.sign([".$u2fChallenge."], function(response) { document.getElementsByName('openotp_u2f')[0].value = JSON.stringify(response); document.getElementById('login-form-otp').submit(); }, $timeout ); }" . "\r\n";

		return $overlay;
	}
	
	private function soapRequest(){
	
		$options = array('location' => $this->server_url);
		if ($this->proxy_host != NULL && $this->proxy_port != NULL) {
			$options['proxy_host'] = $this->proxy_host;
			$options['proxy_port'] = $this->proxy_port;
			if ($this->proxy_username != NULL && $this->proxy_password != NULL) {
				$options['proxy_login'] = $this->proxy_username;
				$options['proxy_password'] = $this->proxy_password;
			}
		}
		ini_set('soap.wsdl_cache_enabled', '0');
		ini_set('soap.wsdl_cache_ttl', '0'); 
			
		$soap_client = new SoapClient(dirname(__FILE__).'/openotp.wsdl', $options);
		if (!$soap_client) {
			return false;
		}
		$this->soap_client = $soap_client;	
		return true;
	}
		
	public function openOTPSimpleLogin($username, $domain, $password, $remote_add){
		echo $user_settings;
		if (!$this->soapRequest()) return false;
		$resp = $this->soap_client->openotpSimpleLogin($username, $domain, $password, $this->client_id, $remote_add, $this->user_settings);
		
		return $resp;
	}
	
	public function openOTPChallenge($username, $domain, $state, $password, $u2f){
		if (!$this->soapRequest()) return false;
		$resp = $this->soap_client->openotpChallenge($username, $domain, $state, $password, $u2f);
		
		return $resp;
	}
}

?>