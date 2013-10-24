// var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService)
var port = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("FF_to_backend_port")
Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.").setCharPref("start_new_session", "false")
var first_window = Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).get("FF_first_window")
//let all subsequent windows know that they are not the first window, so they could skip some initialization
Components.classes["@mozilla.org/process/environment;1"].getService(Components.interfaces.nsIEnvironment).set("FF_first_window", "false")

var reqPageMarked
var reqCheckEscrowtrace
var isPageMarkedResponded = false
var isCheckEscrowtraceResponded = false
var is_accno_entered = false;
var is_sum_entered = false;
var pressed_green_once = false;
var was_clearcache_called = false;

if (first_window == 'true'){
	//Let the backend know that it can remove the splashscreen
	var reqStarted = new XMLHttpRequest();
	reqStarted.open("HEAD", "http://127.0.0.1:"+port+"/started", true);
	reqStarted.send();    

	//do this first and foremost to avoid being nagged
	var browser_prefs = prefs.getBranch("browser.");
	browser_prefs.setCharPref("startup.homepage", "chrome://lspnr/content/home.html")
	browser_prefs.setBoolPref("shell.checkDefaultBrowser", false)

	if (Components.classes["@mozilla.org/preferences-service;1"]
	                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.").getCharPref("first_run") == "true"){
		setSSLPrefs();
		setMiscPrefs();
	}
	setProxyPrefs();
}


//Simply send a HEAD request to the python backend to 127.0.0.1:2222/blabla. Backend treats "/blabla" not as a path but as an API call
//Backend responds with HTTP headers "response":"blabla" and "value":<value from backend>
function pageMarked(){
	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	var textbox_sum = document.getElementById("textbox_sum");
	var textbox_accno = document.getElementById("textbox_accno");
	var panel = document.getElementById("panel");
	var label_accno = document.getElementById("label_accno");
	var label_accno_white = document.getElementById("label_accno_white");
	var label_sum = document.getElementById("label_sum");
	var label_sum_white = document.getElementById("label_sum_white");
	var info = document.getElementById("label_info");
	
	button_green.hidden = true
	button_grey1.hidden = false

	if (!pressed_green_once) {
		label_accno.hidden = true
		label_accno_white.hidden = false
		label_sum.hidden = true
		label_sum_white.hidden = false
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
	if (was_clearcache_called){
		request_str += "&was_clearcache_called=yes"
	}
	else{
		request_str += "&was_clearcache_called=no"
	}
	
  reqPageMarked = new XMLHttpRequest();
  reqPageMarked.onload = responsePageMarked;
  reqPageMarked.open("HEAD", request_str, true);
  reqPageMarked.send();

  	log("Finding HTML in our data")
	isPageMarkedResponded = false
  	setTimeout(responsePageMarked, 1000, 0)    
}

//backend responds to page_marked with either "success" ot "clear_ssl_cache"
function responsePageMarked (iteration) {
    if (typeof iteration == "number"){
        if (iteration > 20){
            log("Oracle is taking more than 20 seconds to respond. Please check your internet connection and try again")
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
		log("Internal error. Wrong response header: "+ query)
	}
	if (value == "success") {
		log("SUCCESS finding HTML. Now finding the same HTML in escrow's data")
		setTimeout(checkEscrowtrace, 1000)
	}
	else if (value == "clear_ssl_cache") {
		//var yellow_button = document.getElementById("button_yellow");
		//yellow_button.hidden = false
		clearSSLCache()
		log("Please refresh this page and press blue button again")
	}
	else if (value == "failure") {
		log("FAILURE finding HTML. Please let the developers know")
		terminate()
	}
	else {
 		log("Internal Error. Unexpected value: "+value+". Please let the developers knows")
 		terminate()
	}
}

function checkEscrowtrace(){
	log("Asking for escrow's data in order to find HTML there")

	reqCheckEscrowtrace = new XMLHttpRequest();
	reqCheckEscrowtrace.onload = responseCheckEscrowtrace;
	reqCheckEscrowtrace.open("HEAD", "http://127.0.0.1:"+port+"/check_escrowtrace", true);
	reqCheckEscrowtrace.send();

	setTimeout(responseCheckEscrowtrace, 1000, 0)    
}


function responseCheckEscrowtrace (iteration) {
    if (typeof iteration == "number"){
        if (iteration > 40){
            log("Oracle is taking more than 40 seconds to respond. Please check your internet connection and try again")
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
		log("Internal error. Wrong response header: "+ query)
		terminate()
	}
	if (value == "success") {
		log("SUCCESS finding HTML in escrow's data")
		alert("Congratulations! Paysty can be used with your bank's website. You can start a new testing session on the Paysty's tab or close Firefox")
		terminate()
	}
	else if (value == "failure") {
		log("FAILURE finding HTML in escrow's data. Please let the developers know")
		terminate()
	}
	else {
 		log("Internal Error. Unexpected value: "+value+". Please let the developers knows")
 		terminate()
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
 //    var button_yellow = document.getElementById("button_yellow");
 //    var button_grey2 = document.getElementById("button_grey2");
	// button_yellow.hidden = true
	// button_grey2.hidden = false
	Components.classes["@mozilla.org/security/sdr;1"].getService(Components.interfaces.nsISecretDecoderRing).logoutAndTeardown();
	was_clearcache_called = true
	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	button_grey1.hidden = true
	button_green.hidden = false
}

function log(string){
	var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
	var info = document.getElementById("label_info");
	info.value = string
	branch.setCharPref("msg_ipc", string)
}


//Check if user wants to start a new banking session
checkNewSession()
function checkNewSession() {
    var branch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.lspnr.")
    var value = branch.getCharPref("start_new_session")
    if (value != "true"){
        setTimeout(checkNewSession, 1000);
        return
    }
   	var button_green = document.getElementById("button_green");
	var button_grey1 = document.getElementById("button_grey1");
	var textbox_sum = document.getElementById("textbox_sum");
	var textbox_accno = document.getElementById("textbox_accno");
	var label_accno = document.getElementById("label_accno");
	var label_accno_white = document.getElementById("label_accno_white");
	var label_sum = document.getElementById("label_sum");
	var label_sum_white = document.getElementById("label_sum_white");
	
	button_green.hidden = true
	button_grey1.hidden = false

	label_accno.hidden = false
	label_accno_white.hidden = true
	label_sum.hidden = false
	label_sum_white.hidden = true
	textbox_sum.disabled = false
	textbox_sum.value = ""
	textbox_accno.disabled = false
	textbox_accno.value = ""
	pressed_green_once=false

	is_accno_entered = false
	is_sum_entered = false

    branch.setCharPref("start_new_session", "false")
    setTimeout(checkNewSession, 1000);
}

function terminate(){
    reqTerminate = new XMLHttpRequest();
    reqTerminate.open("HEAD", "http://127.0.0.1:"+port+"/terminate", true);
    reqTerminate.send();    
}

if (first_window == "true"){
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

	}, 1000)
}
