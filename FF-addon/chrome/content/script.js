var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
                                 .getService(Components.interfaces.nsIConsoleService);
consoleService.logStringMessage("hello");
var prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService);

var isEscrowChecked = false;

var is_accno_entered = false;
var is_sum_entered = false;
var pressed_green_once = false;

setSSLPrefs();
setProxyPrefs();
setMiscPrefs();

//Simply send a HEAD request to the python backend to localhost:2222/blabla. Backend treats "/blabla" not as a path but as an API call
//Backend responds with HTTP headers "response":"blabla" and "value":<value from backend>
function pageMarkedSignal(){
	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	var textbox_sum = document.getElementById("textbox_sum");
	var textbox_accno = document.getElementById("textbox_accno");
	var panel = document.getElementById("panel");
	var label_accno = document.getElementById("label_accno");
	var label_sum = document.getElementById("label_sum");
	var info = document.getElementById("label_info");
	var box = document.getElementById("box");
	
	button_green.hidden = true
	button_grey1.hidden = false

	if (!pressed_green_once) {
		box.removeChild(label_accno)
		var accno_white = document.createElement("label");
		accno_white.setAttribute("value","Account number:");
		accno_white.setAttribute("style", "color:white;")
		box.insertBefore(accno_white, textbox_accno)	

		box.removeChild(label_sum)
		var sum_white = document.createElement("label");
		sum_white.setAttribute("value","Sum:");
		sum_white.setAttribute("style", "color:white;")
		box.insertBefore(sum_white, textbox_sum)	


		textbox_sum.disabled = true
		textbox_accno.disabled = true
		var accno_str = textbox_accno.value
		var sum_str = textbox_sum.value
		pressed_green_once=true
	}
	var request_str = "http://localhost:2222/page_marked"
	//Check if we are testing. In production mode, accno and sum are known in advance of opening FF
	if (accno_str){
		request_str += "?accno="
		request_str += accno_str
		request_str += "&sum="
		request_str += sum_str
	}
	

  reqPageMarked = new XMLHttpRequest();
  reqPageMarked.onload = pageMarkedSignalResponse;
  reqPageMarked.open("HEAD", request_str, true);
  consoleService.logStringMessage("sending page_marked request");
  reqPageMarked.send();
  info.value = "Asking the backend if the page was successfully decrypted"
}

//backend responds to page_marked with either "success" ot "clear_ssl_cache"
function pageMarkedSignalResponse () {
	consoleService.logStringMessage("got page_marked response");
	var query = reqPageMarked.getResponseHeader("response");
	var value = reqPageMarked.getResponseHeader("value");
	var info = document.getElementById("label_info");
	if (query != "page_marked") {
		  info.value = "Internal Error"
		throw "expected page_marked response";
	}
	if (value == "success") {
		info.value = "Success"
	}
	else if (value == "clear_ssl_cache") {
		var yellow_button = document.getElementById("button_yellow");
		yellow_button.hidden = false
		info.value = "Try again. Navigate away and press yellow button."
	}
	else if (value == "failure") {
		info.value = "Failed to decrypt HTML"
	}
	else {
		info.value = "Internal Error"
 		throw "incorrect value header";
	}
	//TODO close this listener
}


function setSSLPrefs() {
	ssl_prefs = prefs.getBranch("security.ssl3.");
	ssl_prefs.setBoolPref("dhe_dss_aes_128_sha",false);
	ssl_prefs.setBoolPref("dhe_dss_aes_256_sha",false);
	ssl_prefs.setBoolPref("dhe_dss_camellia_128_sha",false);
	ssl_prefs.setBoolPref("dhe_dss_camellia_256_sha",false);
	ssl_prefs.setBoolPref("dhe_dss_des_ede3_sha",false);
	ssl_prefs.setBoolPref("dhe_rsa_aes_128_sha",false);
	ssl_prefs.setBoolPref("dhe_rsa_aes_256_sha",false);
	ssl_prefs.setBoolPref("dhe_rsa_camellia_128_sha",false);
	ssl_prefs.setBoolPref("dhe_rsa_camellia_256_sha",false);
	ssl_prefs.setBoolPref("dhe_rsa_des_ede3_sha",false);
	ssl_prefs.setBoolPref("ecdh_ecdsa_aes_128_sha",false);
	ssl_prefs.setBoolPref("ecdh_ecdsa_aes_256_sha",false);
	ssl_prefs.setBoolPref("ecdh_ecdsa_des_ede3_sha",false);
	ssl_prefs.setBoolPref("ecdh_ecdsa_rc4_128_sha",false);
	ssl_prefs.setBoolPref("ecdh_rsa_aes_128_sha",false);
	ssl_prefs.setBoolPref("ecdh_rsa_aes_256_sha",false);
	ssl_prefs.setBoolPref("ecdh_rsa_des_ede3_sha",false);
	ssl_prefs.setBoolPref("ecdh_rsa_rc4_128_sha",false);
	ssl_prefs.setBoolPref("ecdhe_ecdsa_aes_128_sha",false);
	ssl_prefs.setBoolPref("ecdhe_ecdsa_aes_256_sha",false);
	ssl_prefs.setBoolPref("ecdhe_ecdsa_des_ede3_sha",false);
	ssl_prefs.setBoolPref("ecdhe_ecdsa_rc4_128_sha",false);
	ssl_prefs.setBoolPref("ecdhe_rsa_aes_128_sha",false);
	ssl_prefs.setBoolPref("ecdhe_rsa_aes_256_sha",false);
	ssl_prefs.setBoolPref("ecdhe_rsa_des_ede3_sha",false);
	ssl_prefs.setBoolPref("ecdhe_rsa_rc4_128_sha",false);

//Although a non-DH cipher, wireshark wouldn'r decrypt bitcointalk.org which uses a camellia cipher
	ssl_prefs.setBoolPref("rsa_camellia_128_sha",false);
	ssl_prefs.setBoolPref("rsa_camellia_256_sha",false);

	security_prefs = prefs.getBranch("security.");
	security_prefs.setBoolPref("enable_tls_session_tickets",false);
}

function setProxyPrefs(){
	proxy_prefs = prefs.getBranch("network.proxy.");
	proxy_prefs.setIntPref("type", 1);
	proxy_prefs.setCharPref("http","127.0.0.1");
	proxy_prefs.setIntPref("http_port", 8080);
	proxy_prefs.setCharPref("ssl","127.0.0.1");
	proxy_prefs.setIntPref("ssl_port", 8080);
}

function setMiscPrefs(){
//tshark can't dissect spdy
	spdy_prefs = prefs.getBranch("network.http.spdy.");
	spdy_prefs.setBoolPref("enabled",false);
	spdy_prefs.setBoolPref("enabled.v2",false);
	spdy_prefs.setBoolPref("enabled.v3",false);

	cache_disk_prefs = prefs.getBranch("browser.cache.disk.");	
	cache_disk_prefs.setBoolPref("enabled", false)
	
	cache_memory_prefs = prefs.getBranch("browser.cache.memory.");
	cache_memory_prefs.setBoolPref("enabled", false);
	
	cache_prefs = prefs.getBranch("browser.cache.");
	cache_prefs.setBoolPref("disk_cache_ssl", false);
}

function accno_input() {
	if (is_accno_entered){
		return;
	}
	is_accno_entered = true;	
	if (is_sum_entered){
		 var button_green = document.getElementById("button_green");
		 var button_grey1 = document.getElementById("button_grey1");
		 button_grey1.hidden = true;
		 button_green.hidden = false;
	}
}

function sum_input() {
	if (is_sum_entered){
		return;
	}
	is_sum_entered = true;
	if (is_accno_entered){
		 var button_green = document.getElementById("button_green");
		 var button_grey1 = document.getElementById("button_grey1");
		 button_grey1.hidden = true;
		 button_green.hidden = false;
	}
}

function clearSSLCache() {
      	var button_yellow = document.getElementById("button_yellow");
      	var button_grey2 = document.getElementById("button_grey2");
	button_yellow.hidden = true
	button_grey2.hidden = false
	 var sdr = Components.classes["@mozilla.org/security/sdr;1"]
                      .getService(Components.interfaces.nsISecretDecoderRing);
 	 sdr.logoutAndTeardown();
	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	button_grey1.hidden = true
	button_green.hidden = false

	var info = document.getElementById("label_info");
	info.value = "Now open the statement page and press the green button when page finishes loading"
}

function check_default_escrow(){
	var prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService);
    prefs = prefs.getBranch("extensions.lspnr.");
    var escrow_name = prefs.getCharPref("default_escrow")
    var dnsname = prefs.getCharPref("escrow_"+escrow_name+".dnsname")
    var getuserurl = prefs.getCharPref("escrow_"+escrow_name+".getuserurl")
    var listmetricsurl = prefs.getCharPref("escrow_"+escrow_name+".listmetricsurl")
    var describeinstancesurl = prefs.getCharPref("escrow_"+escrow_name+".describeinstancesurl")
    var describevolumesurl = prefs.getCharPref("escrow_"+escrow_name+".describevolumesurl")
    var getconsoleoutputurl = prefs.getCharPref("escrow_"+escrow_name+".getconsoleoutputurl")
    base64string = btoa(getuserurl+" "+listmetricsurl+" "+describeinstancesurl+" "+describevolumesurl+" " + getconsoleoutputurl +" "+ dnsname)

	var reqCheckEscrow = new XMLHttpRequest();
	reqCheckEscrow.onload = responseCheckEscrow;
	reqCheckEscrow.open("HEAD", "http://localhost:2222/check_oracle?"+base64string, true);
	consoleService.logStringMessage("sending check_oracle request");
	reqCheckEscrow.send();
	//give 10 secs for escrow to respond
	setTimeout(checkEscrowResponse, 1000, 0)

}

function responseCheckEscrow(iteration){
	if (typeof iteration == "number"){
		if (iteration > 10){
			alert("Oracle is taking more than 10 seconds to respond. Please try again")
			return
		}
		setTimeout(responseCheckEscrow, 1000, iteration++)
	}
	//else: not a timeout but a response from the server
}

function startTunnel (dns_name, port){
	var reqStartTunnel = new XMLHttpRequest();
	reqStartTunnel.onload = responseStartTunnel;
	reqStartTunnel.open("HEAD", "http://localhost:2222/start_tunnel?"+dns_name+";"+port, true);
	consoleService.logStringMessage("sending start_tunnel request");
	reqStartTunnel.send();
	//give 10 secs for escrow to respond
	setTimeout(responseStartTunnel, 1000, 0)

}

function responseStartTunnel(){
	if (typeof iteration == "number"){
		if (iteration > 10){
			alert("Oracle is taking more than 10 seconds to respond. Please try again")
			return
		}
		setTimeout(responseCheckEscrow, 1000, iteration++)
	}
	//else: not a timeout but a response from the server

}

//OBSOLETE but may be useful in the future

//JS doesn't have a sleep() function due to its single-threadedness
//we check every second if callback which listens for a response from the backend has received such a response and consequently
//set the flag to true. If it didn't happen within timeout seconds, we let the callback know
function waitForResponse(callback, flag, timeout, iteration) {
	if (flag == true) return;
	else {		  
		if (iteration == timeout) {
			callback("timeout")
			return
		}
		iteration++;
  		consoleService.logStringMessage("iteration No");
  		consoleService.logStringMessage(iteration);
		//non-standard setTimeout invocation, FF-specific
		setTimeout(waitForResponse, 1000, callback, flag, timeout, iteration);
	}
}


