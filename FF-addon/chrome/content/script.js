var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
                                 .getService(Components.interfaces.nsIConsoleService);
consoleService.logStringMessage("hello");
var prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService);

var tempdir = "";
var is_tempdir_received = false;
var reqTempDir;

//main ()
function startSSLSession(){
  getTempDir();
  setSSLPrefs();
  setProxyPrefs();
  waitForResponse(0);
//After backend responds, continue_after_tempdir_received() is called from within waitForResponse()
}

//Simply send a HEAD request to the python backend to localhost:2222/blabla. Backend treats "/blabla" not as a path but as an API call
//Backend responds with HTTP headers "response":"blabla" and "value":<value from backend>
function getTempDir () {
  is_tempdir_received = false;
  reqTempDir = new XMLHttpRequest();
  reqTempDir.onload = reqTempDirListener;
  reqTempDir.open("HEAD", "http://localhost:2222/tempdir", true);
  consoleService.logStringMessage(reqTempDir);
  consoleService.logStringMessage("sending TEMPDIR request");
  reqTempDir.send()
}

function reqTempDirListener () {
  consoleService.logStringMessage("got TEMPDIR response");
  var query = reqTempDir.getResponseHeader("response");
  var value = reqTempDir.getResponseHeader("value");
  if (query != "tempdir") throw "expected TEMPDIR response";
  if (value.length == 0) throw "TEMPDIR value is zero"
  tempdir = value;
  is_tempdir_received = true;
//TODO close this listener
}

//Give backend 5 seconds to respond before giving up
//JS doesn't have a sleep() function.
function waitForResponse(iteration) {
	consoleService.logStringMessage("waitForResponse hit");
	if (is_tempdir_received == true) continue_after_tempdir_received();
	else {		  
		if (iteration == 5) throw "no TEMPDIR response";
		iteration++;
  		consoleService.logStringMessage("iteration No");
  		consoleService.logStringMessage(iteration);
		//non-standard setTimeout invocation, FF-specific
		setTimeout(waitForResponse,1000,iteration);
	}
}

function continue_after_tempdir_received() {
	viewsource_prefs = prefs.getBranch("view_source.editor.");
//FF will first write the source file into a "TMP" env.var. and then try to invoke "path" on it
//We only need it to write the source file into a TMP dir and silently fail to invoke a "path" program 
	viewsource_prefs.setBoolPref("external", true); 
//any existing dummyfile will make FF silently fail to open the source viewer 
	viewsource_prefs.setCharPref("path",tempdir);
}

function stopSSLSession(){
  reqStop = new XMLHttpRequest();
  reqStop.onload = reqStopListener;
  reqStop.open("HEAD", "http://localhost:2222/finished", true);
  consoleService.logStringMessage(reqTempDir);
  consoleService.logStringMessage("sending FINISHED request");
  reqStop.send()
}

function reqStopListener () {
  consoleService.logStringMessage("got FINISHED response");
  var query = reqTempDir.getResponseHeader("response");
  var value = reqTempDir.getResponseHeader("value");
  if (query != "finished") throw "expected FINISHED response";
  if (value != "ok") throw "incorrect FINISHED value"
//TODO close this listener
}



//sendStatus() not in use yet
function sendStatus () {
  var oReqPost = new XMLHttpRequest();
  oReqPost.onload = reqListener2;
  oReqPost.open("HEAD", "http://localhost:2222/status", true);
  consoleService.logStringMessage(oReqPost);
  consoleService.logStringMessage("sending STATUS request");
  oReqPost.send()
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

	security_prefs = prefs.getBranch("security.");
	security_prefs.setBoolPref("enable_tls_session_tickets",false);
	
	spdy_prefs = prefs.getBranch("network.http.spdy.");
	spdy_prefs.setBoolPref("enabled",false);
	spdy_prefs.setBoolPref("enabled.v2",false);
	spdy_prefs.setBoolPref("enabled.v3",false);



}

function setProxyPrefs(){
	proxy_prefs = prefs.getBranch("network.proxy.");
	proxy_prefs.setIntPref("type", 1)
	proxy_prefs.setCharPref("http","127.0.0.1")
	proxy_prefs.setIntPref("http_port", 8080)
	proxy_prefs.setCharPref("ssl","127.0.0.1")
	proxy_prefs.setIntPref("ssl_port", 8080)
}
