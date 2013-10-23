// var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService)
var port = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("FF_to_backend_port")

//Let the backend know that it can remove the splashscreen
var reqStarted = new XMLHttpRequest();
reqStarted.open("HEAD", "http://127.0.0.1:"+port+"/started", true);
reqStarted.send();    

var reqPageMarked
var reqCheckEscrowtrace
var isPageMarkedResponded = false
var isCheckEscrowtraceResponded = false

var browser_prefs = prefs.getBranch("browser.");
browser_prefs.setCharPref("startup.homepage", "chrome://lspnr/content/home.html")
browser_prefs.setBoolPref("shell.checkDefaultBrowser", false)

var is_accno_entered = false;
var is_sum_entered = false;
var pressed_green_once = false;

setSSLPrefs();
setProxyPrefs();
setMiscPrefs();

//Simply send a HEAD request to the python backend to 127.0.0.1:2222/blabla. Backend treats "/blabla" not as a path but as an API call
//Backend responds with HTTP headers "response":"blabla" and "value":<value from backend>
function pageMarked(){
	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")

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
		pressed_green_once=true
	}
	var accno_str = textbox_accno.value
	var sum_str = textbox_sum.value
	var request_str = "http://127.0.0.1:"+port+"/page_marked"
	//Check if we are testing. In production mode, accno and sum are known in advance of opening FF
	if (accno_str){
		request_str += "?accno="
		request_str += accno_str
		request_str += "&sum="
		request_str += sum_str
	}
	
  reqPageMarked = new XMLHttpRequest();
  reqPageMarked.onload = responsePageMarked;
  reqPageMarked.open("HEAD", request_str, true);
  reqPageMarked.send();

  info.value = "Asking backend if page was successfully decrypted"
  branch.setCharPref("msg_ipc", "Asking backend if HTML was successfully decrypted")

  setTimeout(responsePageMarked, 1000, 0)    
}

//backend responds to page_marked with either "success" ot "clear_ssl_cache"
function responsePageMarked (iteration) {
	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")

    if (typeof iteration == "number"){
        if (iteration > 20){
            branch.setCharPref("msg_ipc", "Oracle is taking more than 20 seconds to respond. Please check your internet connection and try again")
            return
        }
        if (!isPageMarkedResponded) setTimeout(responsePageMarked, 1000, ++iteration)
        return
    }
    //else: not a timeout but a response from the server
    isPageMarkedResponded = true
	var query = reqPageMarked.getResponseHeader("response");
	var value = reqPageMarked.getResponseHeader("value");
	var info = document.getElementById("label_info");
	if (query != "page_marked") {
		info.value = "Internal Error"
		branch.setCharPref("msg_ipc", "Internal error. Wrong response header: "+ query)
		return
	}
	if (value == "success") {
		branch.setCharPref("msg_ipc", "HTML was decrypted successfully")
		info.value = "HTML decrypted successfully. Checking escrow's trace now"
		checkEscrowtrace()
	}
	else if (value == "clear_ssl_cache") {
		var yellow_button = document.getElementById("button_yellow");
		yellow_button.hidden = false
		isPageMarkedResponded = false
		branch.setCharPref("msg_ipc", "Try again. Navigate away and press yellow button and AFTER that click open your statement")
		info.value = "Try again. Navigate away and press yellow button."
	}
	else if (value == "failure") {
		info.value = "Failed to decrypt HTML"
		branch.setCharPref("msg_ipc", "Failed to decrypt HTML. Please let the developers know")

	}
	else {
		info.value = "Internal Error"
 		branch.setCharPref("Internal Error. Unexpected value: "+value+". Please let the developers knows")
	}
}

function checkEscrowtrace(){
	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
	var info = document.getElementById("label_info");

    info.value = "Asking for escrow trace"
	branch.setCharPref("msg_ipc", "Asking for escrow trace to see if escrow would decrypt HTML successfully")

	reqCheckEscrowtrace = new XMLHttpRequest();
	reqCheckEscrowtrace.onload = responseCheckEscrowtrace;
	reqCheckEscrowtrace.open("HEAD", "http://127.0.0.1:"+port+"/check_escrowtrace", true);
	reqCheckEscrowtrace.send();

	setTimeout(responseCheckEscrowtrace, 1000, 0)    
}


function responseCheckEscrowtrace (iteration) {
	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
    var info = document.getElementById("label_info");

    if (typeof iteration == "number"){
        if (iteration > 40){
            branch.setCharPref("msg_ipc", "Oracle is taking more than 40 seconds to respond. Please check your internet connection and try again")
            return
        }
        if (!isCheckEscrowtraceResponded) setTimeout(responseCheckEscrowtrace, 1000, ++iteration)
        	return
    }
    //else: not a timeout but a response from the server
    isCheckEscrowtraceResponded = true
	var query = reqCheckEscrowtrace.getResponseHeader("response");
	var value = reqCheckEscrowtrace.getResponseHeader("value");
	if (query != "check_escrowtrace") {
		info.value = "Internal Error"
		branch.setCharPref("msg_ipc", "Internal error. Wrong response header: "+ query)
		return
	}
	if (value == "success") {
		branch.setCharPref("msg_ipc", "Escrow's HTML was decrypted successfully")
		info.value = "Escrow's HTML decrypted successfully"
		alert("Congratulations! Paysty can be used with your bank's website.")
	}
	else if (value == "failure") {
		info.value = "Failed to decrypt escrow's HTML"
		branch.setCharPref("msg_ipc", "Failed to decrypt escrow's HTML. Please let the developers know")
	}
	else {
		info.value = "Internal Error"
 		branch.setCharPref("Internal Error. Unexpected value: "+value+". Please let the developers knows")
	}
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
	var port = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("FF_proxy_port")
	var port_int = parseInt(port)
	proxy_prefs = prefs.getBranch("network.proxy.");
	proxy_prefs.setIntPref("type", 1);
	proxy_prefs.setCharPref("http","127.0.0.1");
	proxy_prefs.setIntPref("http_port", port_int);
	proxy_prefs.setCharPref("ssl","127.0.0.1");
	proxy_prefs.setIntPref("ssl_port", port_int);
}

function setMiscPrefs(){
//tshark can't dissect spdy
	spdy_prefs = prefs.getBranch("network.http.spdy.");
	spdy_prefs.setBoolPref("enabled",false);
	spdy_prefs.setBoolPref("enabled.v2",false);
	spdy_prefs.setBoolPref("enabled.v3",false);

	cache_disk_prefs = prefs.getBranch("browser.cache.disk.");	
	cache_disk_prefs.setBoolPref("enable", false)
	
	cache_memory_prefs = prefs.getBranch("browser.cache.memory.");
	cache_memory_prefs.setBoolPref("enable", false);
	
	cache_prefs = prefs.getBranch("browser.cache.");
	cache_prefs.setBoolPref("disk_cache_ssl", false);

	network_http_prefs = prefs.getBranch("network.http.");
	network_http_prefs.setBoolPref("use-cache", false);
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
	Components.classes["@mozilla.org/security/sdr;1"].getService(Components.interfaces.nsISecretDecoderRing).logoutAndTeardown();
	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	button_grey1.hidden = true
	button_green.hidden = false

	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
	var info = document.getElementById("label_info");
	info.value = "Now open the statement page and press the green button when page finishes loading"
	branch.setCharPref("msg_ipc", "SSL cache has been cleared ")
}


//pin the addon tab on first run. It should remain pinned on subsequent runs
setTimeout(function(){
	var lspnr_prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
    if (lspnr_prefs.getCharPref("first_run") != "true"){
    	//FF always opens a home page even though our tab is pinned
    	gBrowser.removeCurrentTab()
    	return
    }
    lspnr_prefs.setCharPref("first_run", "false")
	var tab = gBrowser.addTab("chrome://lspnr/content/home.html")
	gBrowser.pinTab(tab)
    gBrowser.removeCurrentTab()

}, 2000)
