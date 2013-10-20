from __future__ import print_function

import sys
import subprocess
import shutil
import os
import signal
import hashlib
import base64
import requests
import BaseHTTPServer, SimpleHTTPServer
import threading
import time
import signal
import inspect
import traceback
from bitcoinrpc import authproxy

#--------------------Begin customizable variables-------------------------------------

#THIS MUST BE CHANGED to point to a escrow's server IP which is running sshd. You can use localhost for testing
escrow_ssh_host = '' #e.g. '1.2.3.4'  NB! '127.0.0.1' may not work, use localhost instead
#the port is an arbtrary port on the escrow's server. Unless there is a port conflict, no need to change it.
escrow_dumpcap_port = 0
escrow_e2b_port = 1001
escrow_e2s_port = 1002
#an existing username and password used to connect to sshd on escrow's server. For testing you can give your username if sshd ir run locally
escrow_ssh_user = 'username' #e.g. 'ssllog_user' 
escrow_ssh_pass = 'password'
escrow_ssh_port = 22
escrow_http_host = ''
escrow_http_port = 12344
buyer_stunnel_accept_port = 8080
buyer_http_port = 2222
seller_http_port = 4445

#transaction ref number that buyer has to see in his HTML
ref_string = '2013'

#ssllog_installdir is the dir from which main.py is run
currfile = inspect.getfile(inspect.currentescrow_random_portframe())
installdir = os.path.dirname(os.path.realpath(__file__))

#read some preferences from an external file
if os.path.isfile(os.path.join(installdir,'preferences.py')):
    sys.path.append(installdir)
    import preferences
    escrow_ssh_host = preferences.escrow_host
    escrow_dumpcap_port = preferences.escrow_random_port
    escrow_ssh_user = preferences.escrow_ssh_user
    escrow_ssh_pass = preferences.escrow_ssh_pass
    escrow_ssh_port = preferences.escrow_ssh_port

#---------------------You can modify these paths if some programs are not in your $PATH------------------
#DONT USE the version of stunnel that comes with Ubuntu - it is a ridiculously old incompatible version
stunnel_exepath = '/home/default2/Desktop/sslxchange/stunnel-4.56/src/stunnel'
ssh_exepath = '/usr/bin/ssh'
sshpass_exepath = '/usr/bin/sshpass'
squid3_exepath = '/usr/sbin/squid3'
firefox_exepath = '/home/default2/Desktop/firefox20/firefox'
#BITCOIND IS USUALLY NOT IN YOUR PATH
bitcoind_exepath = '/home/default2/Desktop/bitcoin-qt/bitcoin-0.8.2-linux/bin/64/bitcoind'
tshark_exepath = '/usr/local/bin/tshark'
#editcap,dumpcap come together with wireshark package
editcap_exepath = '/usr/local/bin/editcap'
# NB!! dumpcap has to be given certain capabilities on Linux
# run --> sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/local/bin/dumpcap
dumpcap_exepath = '/usr/local/bin/dumpcap'
capinfos_exepath = '/usr/local/bin/capinfos'
mergecap_exepath = '/usr/local/bin/mergecap'
wireshark_configdir = '/home/default2/.wireshark'

#where buyer's dumpcap puts its traffic capture file
buyer_dumpcap_capture_file= os.path.join(installdir, 'dumpcap', 'buyer_dumpcap.pcap')
#where seller's dumpcap puts its traffic capture file
seller_dumpcap_capture_file= os.path.join(installdir, 'dumpcap', 'seller_dumpcap.pcap')
#where escrow's dumpcap puts its traffic capture file
escrow_dumpcap_capture_file= os.path.join(installdir, 'dumpcap', 'escrow_dumpcap.pcap')
#for buyer and seller: location of the escrow's trace
escrowtrace_from_escrow_buyer  = os.path.join(installdir,'dumpcap','escrowtrace_buyer.pcap')
escrowtrace_from_escrow_seller = os.path.join(installdir,'dumpcap','escrowtrace_seller.pcap')
seller_stunnelkey =  os.path.join(installdir,'stunnel','seller.key')
buyer_stunnelkey = os.path.join(installdir, 'stunnel','buyer_stunnel.key')
#where Firefox saves html files when user marks them
htmldir = os.path.join(installdir,'htmldir')
sslkeylogfile = os.path.join(installdir, 'dumpcap', 'sslkeylog')

#bitcond user/pass are already in bitcon.conf that comes with this installation
#these bitcond handlers can be initialized even before bitcoind starts
buyer_bitcoin_rpc = authproxy.AuthServiceProxy("http://ssllog_user:ssllog_pswd@127.0.0.1:8338")
seller_bitcoin_rpc = authproxy.AuthServiceProxy("http://ssllog_user:ssllog_pswd@127.0.0.1:8339")

#--------------End of customizable variables------------------------------------------------
stunnelkey = ''
stunnelkeyhash = ''


#handle only paths we are interested and let python handle the response headers
#class "object" in needed to access super()
class buyer_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"
    
    
    def collate(self):
        #TODO write an awesome function
        #first find HTML in sellertrace
        buyer_find_htmlframe(reference_string)
        
        #failing the above, collate against escrowtrace
        #find as many TCP correlations as possible
        
        send_http_request(escrow_http_host, escrow_http_port, '/instructions_BE')
        
    
    def do_GET(self):
        super(buyer_HandlerClass, self).do_GET()
    #Firefox addon speaks with HEAD
    def do_HEAD(self):
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        if self.path == '/status':
            self.send_response(200)
            self.send_header("response", "status")
            self.send_header("value", "pending")
            super(buyer_HandlerClass, self).do_HEAD()
        elif self.path == '/tempdir':
            self.send_response(200)
            self.send_header("response", "tempdir")
            self.send_header("value", os.path.join(installdir, 'firefox', 'dummy'))
            super(buyer_HandlerClass, self).do_HEAD()
            
        elif self.path == '/finished':
            #ask seller to stop dumpcap first. Then continue.
            #TODO wrap this in try/except
            response = requests.head("http://127.0.0.1:"+str(seller_http_port)+"/stopsquid", proxies={"http":"http://127.0.0.1:"+str(buyer_stunnel_accept_port)})
            if response.status_code != 200:
                print ("Unable to stop squid",end='\r\n')
                cleanup_and_exit()         
            self.send_response(200)
            self.send_header("response", "finished")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
            self.server.stop = True
            
        elif self.path.startswith == '/decrypt_escrowtrace=':
            self.send_response(200)
            self.send_header("response", "decrypt_escrowtrace")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
            escrowtrace_path = self.path[len('/decrypt_escrowtrace='):]
            response = send_http_request('get',escrow_http_host,escrow_http_port,escrowtrace_path)
            escrowtrace_from_escrow = open(escrowtrace_from_escrow_buyer,'w')
            escrowtrace_from_escrow.write(response.content)
            escrowtrace_from_escrow.close()
            is_subset = find_ssl_in_escrowtrace(self.ssl_hashes)
            send_http_request(escrow_http_host,escrow_http_port, '/escrow_hashes_matched_buyer='+"true" if is_subset else "false")

            #not in use yet
        elif self.path.startswith == '/get_tcpstream_and_sslkey':
            self.send_response(200)
            self.send_header("response", "get_tcpstream_and_sslkey")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
            
        elif self.path.startswith == '/collate':
            self.send_response(200)
            self.send_header("response", "collate")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
                               
        elif self.path == '/getstunnelkey':
            fd = open(buyer_stunnelkey, 'w')
            data = fd.read()
            fd.close()
            key = data.__str__()
            base64_message = base64.b64encode(key)
            self.send_response(200)
            self.send_header("response", "getstunnelkey")
            self.send_header("value", base64_message)
            super(seller_HandlerClass, self).do_HEAD()

        elif self.path == '/getstunnelkeyhash':
            fd = open(buyer_stunnelkey, 'w')
            data = fd.read()
            fd.close()
            key = data.__str__()
            stunnelkeyhash = hashlib.md5(key).hexdigest()
            self.send_response(200)
            self.send_header("response", "getstunnelkeyhash")
            self.send_header("value", stunnelkeyhash)
            super(seller_HandlerClass, self).do_HEAD()
            
        elif self.path == '/gettraces':
            self.send_response(200)
            self.send_header("response", "gettraces")
            self.send_header("value", 'ok')
            super(seller_HandlerClass, self).do_HEAD()
            sellertrace = send_http_request('get', escrow_http_host, escrow_http_port, '/temp/escrows_seller_dumpcap.pcap')
            escrowtrace = send_http_request('get', escrow_http_host, escrow_http_port, '/dumpcap/escrow_dumpcap.pcap')
            result = self.collate()
            if result:
                buyer_prepare_tcpstream_and_sslkeylog()
            else:
                

                        
    #logging messes up the terminal, disabling
    def log_message(self, format, *args):
        return
    
            
#handle only paths we are interested and let python handle the response headers
#class "object" in needed to access super()
class seller_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"
    ssl_hashes = []
    def do_GET(self):
        print ("Received an unexpected GET request. Please investigate",end='\r\n')
        cleanup_and_exit()           
    def do_HEAD(self):
        print ('http server: received request '+self.path+' ',end='\r\n')
        if self.path == '/certificate':
            print ("Buyer has requested the stunnel certificate",end='\r\n')
            message = seller_get_certificate_verify_message()
            #base64-encode because HTTP headers don't allow newlines which are present in the certificate
            base64_message = base64.b64encode(message)
            self.send_response(200)
            self.send_header("response", "certificate")
            self.send_header("value", base64_message)
            super(seller_HandlerClass, self).do_HEAD() 
            
        elif self.path.startswith('/sslkeylogfile='):
            print ("Received SSL keys from the buyer",end='\r\n')
            base64_sslkeylog_str = self.path[len('/sslkeylogfile='):]
            sslkeylog_str = base64.b64decode(base64_sslkeylog_str)
            with open (os.path.join(installdir,'escrow','sslkeylogfile'), "w") as file:
                file.write(sslkeylog_str)
            self.send_response(200)
            self.send_header("response", "sslkeylogfile")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            
        elif self.path.startswith('/hashes='):
            print ("Received hashes of SSL segments from the escrow",end='\r\n')
            self.ssl_hashes = self.path[len('/hashes='):].split(';')[1:]
            self.send_response(200)
            self.send_header("response", "hashes")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            is_found = seller_check_hashes_present(self.ssl_hashes)
            #send search result to the escrow
            send_http_request(escrow_http_host, escrow_http_port,"/sellersearchresult="+ "true" if is_found else "false")
            #self.server.stop = True
            
        elif self.path.startswith('/stopsquid'):
            #TODO actually stop squid before responding
            self.send_response(200)
            self.send_header("response", "stopsquid")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            
        elif self.path.startswith == '/decrypt_escrowtrace=':
            self.send_response(200)
            self.send_header("response", "decrypt_escrowtrace")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
            escrowtrace_path = self.path[len('/decrypt_escrowtrace='):]
            response = send_http_request('get',escrow_http_host,escrow_http_port,escrowtrace_path)
            escrowtrace_from_escrow = open(escrowtrace_from_escrow_seller,'w')
            escrowtrace_from_escrow.write(response.content)
            escrowtrace_from_escrow.close()
            is_subset = find_ssl_in_escrowtrace(self.ssl_hashes)
            send_http_request(escrow_http_host,escrow_http_port, '/escrow_hashes_matched_seller='+"true" if is_subset else "false")

        elif self.path.startswith('/instructionsES='):
            instructions = self.path[len('/instructionsES='):]
            self.send_response(200)
            self.send_header("response", "instructionsES")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            
            result = seller_reorder_traces(instructions)
            send_http_request(escrow_http_host,escrow_http_port, '/buyers_instructions_response='+"true" if result else "false")
        
        
        elif self.path == '/getstunnelkey':
            fd = open(seller_stunnelkey, 'w')
            data = fd.read()
            fd.close()
            key = data.__str__()
            base64_message = base64.b64encode(key)
            self.send_response(200)
            self.send_header("response", "getstunnelkey")
            self.send_header("value", base64_message)
            super(seller_HandlerClass, self).do_HEAD()
     
        elif self.path == '/getstunnelkeyhash':
            fd = open(seller_stunnelkey, 'w')
            data = fd.read()
            fd.close()
            key = data.__str__()
            stunnelkeyhash = hashlib.md5(key).hexdigest()
            self.send_response(200)
            self.send_header("response", "getstunnelkeyhash")
            self.send_header("value", stunnelkeyhash)
            super(seller_HandlerClass, self).do_HEAD()

            
    #logging messes up the terminal, disabling
    #def log_message(self, format, *args):
        #return
    
#handle only paths we are interested and let python handle the response headers
#class "object" in needed to access super()
class escrow_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.0"
    buyerhashes = []
    #TODO make sure these bools are not changed by two different threads at the same time
    hashes_match_seller = False
    hashes_match_buyer = False
    buyer_responded_with_hashes_check = False
    seller_responded_with_hashes_check = False
    instructions = ''

    def check_buyer_seller_responses(self):
        if self.hashes_match_buyer and self.hashes_match_seller:
            self.get_buyer_stream()
        elif not self.hashes_match_buyer and not self.hashes_match_seller:
            send_http_request('127.0.0.1', escrow_e2b_port, '/collate')
        elif self.hashes_match_buyer or self.hashes_match_seller:
            stunnelkey_base64 = send_http_request('127.0.0.1', escrow_e2b_port, '/getstunnelkey')
            stunnelkey = base64.decode(stunnelkey_base64)
            stunnelkeyhash = send_http_request('127.0.0.1', escrow_e2s_port, '/getstunnelkeyhash')
            if hashlib.md5(stunnelkey).hexdigest != stunnelkeyhash:
                print ("One of the parties sent fake key/keyhash",end='\r\n')
                cleanup_and_exit()
            fd = open(os.path.join(installdir,'temp','escrows_stunnel.key'), 'w')
            fd.write(stunnelkey)
            fd.close()
            result = subprocess.check_output(['tshark','-r',escrow_dumpcap_capture_file,'-Y','ssl','-T','fields','-e', 'ssl.segment.data', '-o', 'http.ssl.port:443', '-o', 'ssl.keys_list:127.0.0.1,33310,http,'+(os.path.join(installdir,'temp','escrows_stunnel.key'))])
            if result == '':
                print ("Couldn't decrypt escrotrace. Please investigate",end='\r\n')
                cleanup_and_exit()
            result.rstrip()
            result = result.replace(',','\n')
            segs = result.split('\n')
            decrypted_hashes = []
            for segment in segs:
                if segment == '':
                    continue
                segment = segment.replace(':',' ')r
                newhash = hashlib.md5(bytearray.fromhex(segment)).hexdigest()
                decrypted_hashes.append(newhash)
            if set(self.buyerhashes).issubset(set(decrypted_hashes)):
                print ('Seller ' if not self.hashes_match_seller else 'Buyer ' + 'lied to not have found all SSL hashes in escrowtrace')
                cleanup_and_exit()
            else:
                print ('Seller ' if self.hashes_match_seller else 'Buyer ' + 'lied to have found all SSL hashes in escrowtrace. But why?')
                cleanup_and_exit()
            
    def get_buyer_stream():
        stream = send_http_request('get', '127.0.0.1',escrow_e2b_port,'/temp/buyer_stream.pcap')
        sslkey = send_http_request('get', '127.0.0.1',escrow_e2b_port,'/temp/buyer_single_key')
        fd = open(os.path.join(installdir,'temp','escrows_buyer_stream.pcap'), 'w')
        fd.write(stream.content)
        fd.close()
        fd2 = open(os.path.join(installdir,'temp','escrows_buyer_key'), 'w')
        fd2.write(sslkey.content)
        fd2.close()
        print ("Successfully received the stream pcap and sslkey from buyer. Please examine them manually",end='\r\n')
        #TODO tell everyone to finish
        
    def repeat_buyers_instruction():
        #TODO 
        
    def do_GET(self):
        super(escrow_HandlerClass, self).do_GET()
    def do_HEAD(self):
        print ('http server: received request '+self.path+' ',end='\r\n')
        
        if self.path == '/hashes=':
            print ("Buyer has submtted SSL hashes",end='\r\n')
            hashes_str = self.path[len('/hashes='):]
            self.buyerhashes = hashes_str.split(';')[1:]
            self.send_response(200)
            self.send_header("response", "hashes")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            #send hashes to the seller
            send_http_request('127.0.0.1', escrow_e2s_port, "/hashes"+hashes_str)
            
        elif self.path == '/buyer_html_not_found':
            self.send_response(200)
            self.send_header("response", "buyer_html_not_found")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            #request sellertrace and send seller+escrowtraces to buyer
            sellertrace = send_http_request('get','127.0.0.1', escrow_e2s_port, '/dumpcap/seller_dumpcap.pcap')
            fd = open(os.path.join(installdir, 'temp', 'escrows_seller_dumpcap.pcap'), 'w')
            fd.write(sellertrace.content)
            fd.close()
            send_http_request('127.0.0.1', escrow_e2b_port, '/gettraces')
            
        elif self.path == '/instructions_BE=':
            self.instructions = self.path[len('/instructions_BE='):]
            self.send_response(200)
            self.send_header("response", "hashes")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            #send hashes to the seller
            send_http_request('127.0.0.1', escrow_e2s_port, "/instructionsES="+instructions)
            
        elif self.path == '/buyers_instructions_response=':
            result = self.path[len('/buyers_instructions_response='):]
            self.send_response(200)
            self.send_header("response", "buyers_instructions_response")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            if result == 'true':
                self.get_buyer_stream()                
            else:
                result = repeat_buyers_instruction()
                if result:
                    #Seller was lying
                    print ("Seller fraud detected",end='\r\n')
                    cleanup_and_exit()
                else:
                    #Buyer was lying
                    print ("Buyer fraud detected",end='\r\n')
                    cleanup_and_exit()
            
        elif self.path.startswith('/sellersearchresult='):
            print ("Received search result from seller ",end='\r\n')
            result = self.path[len('/sellersearchresult='):]     
            self.send_response(200)
            self.send_header("response", "sellersearchresult")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            if result == 'true':
                self.get_buyer_stream()                
            elif result == 'false':
                #give buyer and seller a link to escrowtrace
                try:
                    os.kill(pid['dumpcap'], signal.SIGTERM)
                except Exception,e:
                    print ('Exception while killing dumpcap', e,end='\r\n')
                    cleanup_and_exit()
                #TODO find a more reliable way to know that dumpcap finished writing into the pcap file
                time.sleep(1)
                #these imports are only needed for escrow
                import random
                import string
                randomname = ''.join(random.choice(string.ascii_lowercase) for x in range(8))
                shutil.copy(escrow_dumpcap_capture_file, os.path.join(installdir,'tempdir',randomname))    
                
                send_http_request('127.0.0.1', escrow_e2b_port, "/decrypt_escrowtrace="+"/tempdir"+randomname)
                send_http_request('127.0.0.1', escrow_e2s_port, "/decrypt_escrowtrace="+"/tempdir"+randomname)
           
        elif self.path.startswith('/stopsquid'):
            #TODO actually stop squid before responding
            self.send_response(200)
            self.send_header("response", "stopsquid")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            
        elif self.path.startswith('/escrow_hashes_matched_seller='):
            result = self.path[len('/escrow_hashes_matched_seller='):]
            self.hashes_match_seller = True if result == 'true' else False
            seller_responded_with_hashes_check = True
            self.send_response(200)
            self.send_header("response", "escrow_hashes_matched_seller")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            if buyer_responded_with_hashes_check == True:
                self.check_buyer_seller_responses()
                
            
        elif self.path.startswith('/escrow_hashes_matched_buyer='):
            result = self.path[len('/escrow_hashes_matched_buyer='):]
            self.hashes_match_seller = True if result == 'true' else False
            buyer_responded_with_hashes_check = True
            self.send_response(200)
            self.send_header("response", "escrow_hashes_matched_buyer")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            if seller_responded_with_hashes_check == True:
                self.check_buyer_seller_responses()
  
                
class StoppableHttpServer (BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        while not self.stop:
                self.handle_request()
        return self.retval;
    
class ThreadWithRetval(threading.Thread):
    retval = ''
 
class HTTPFinishedException(Exception):
    pass
 

def find_ssl_in_escrowtrace(ssl_hahses):
    result = subprocess.check_output(['tshark','-r',escrowtrace_from_escrow,'-Y','ssl','-T','fields','-e', 'ssl.segment.data', '-o', 'http.ssl.port:443', '-o', 'ssl.keys_list:127.0.0.1,33310,http,/home/default2/Desktop/sslxchange/stunnel/seller.key'])
    result.rstrip()
    result = result.replace(',','\n')
    segs = result.split('\n')
    escrow_hashes = []
    for segment in segs:
        if segment == '':
            continue
        segment = segment.replace(':',' ')
        newhash = hashlib.md5(bytearray.fromhex(segment)).hexdigest()
        escrow_hashes.append(newhash)
    is_subset = set(ssl_hahses).issubset(set(escrow_hashes))
    
    print 'Produced ' + str(len(escrow_hashes)) + ' hashes'
    if is_subset:
        print 'Success!!! Buyer-provided hashes are a subset of escrow hashes'
    else:
        print 'Failure!!! Buyer-provided hashes are NOT a subset of escrow hashes'
        
    return is_subset

    
    
    
    
    
    

            
#send all the hashes in an HTTP HEAD request    
def buyer_send_sslhashes(sslhashes):
    print ("Sending hashes of SSL segments to the escrow",end='\r\n')
    hashes_string = ''
    for hash in sslhashes:
        hashes_string += ';'+hash
    escrow_contacted = False
    for i in range(10):
        try:
            message = requests.head("http://"+escrow_http_host+":"+str(escrow_http_port)+"/buyerhashes="+hashes_string)
            escrow_contacted = True
            break
        except Exception,e:
            print ('Sleeping ' + str(i+1) + ' sec while trying to connect to the escrow',end='\r\n')
            time.sleep(1)
    if not escrow_contacted:
        print ("Can't connect to the escrow",end='\r\n')
        cleanup_and_exit()  
    elif message.status_code != 200:
        print ("Unable to send SSL hashes to the escrow",end='\r\n')
        cleanup_and_exit()

#send sslkeylog to escrow. For testing purposes we can send it to seller.
#NB! There is probably a limit on header size in python
def buyer_send_sslkeylogfile():
    print ("Sending SSL keys to the escrow",end='\r\n')
    #with open (os.path.join(installdir, 'capture', 'sslkeylog'), "r") as file:
        #data = file.read()
    #keylogfile_ascii = data.__str__()
    ##base64-encode because HTTP headers don't allow newlines
    #base64_keylogfile_ascii = base64.b64encode(keylogfile_ascii)
    #message = requests.head("http://127.0.0.1:4444/sslkeylogfile="+base64_keylogfile_ascii, proxies={"http":"http://127.0.0.1:"+str(buyer_stunnel_accept_port)})
    #if message.status_code != 200:
       #print  "Unable to send SSL keylogfile to escrow"
       #cleanup_and_exit()
    
    #For local testing - just copy it into the escrow folder
    shutil.copy(os.path.join(installdir, 'dumpcap', 'sslkeylog'), os.path.join(installdir,'escrow','sslkeylog'))    
    
def buyer_start_stunnel_with_certificate(skip_capture):
    global pids
    print ('Restarting stunnel with the new certificate',end='\r\n')
    try:
        stunnel_proc = subprocess.Popen([stunnel_exepath, os.path.join(installdir, 'stunnel', 'buyer.conf')], cwd=os.path.join(installdir, 'stunnel'), stdout=open(os.path.join(installdir, 'stunnel', 'stunnel_buyer.stdout'),'w'), stderr=open(os.path.join(installdir, 'stunnel', 'stunnel_buyer.stderr'),'w'))
    except Exception,e:
        print ('Error starting stunnel',e,end='\r\n')
        cleanup_and_exit()
    #give it a couple seconds to start properly and create the pid file
    time.sleep(2)
        
    if skip_capture == False:
        print ('Making a test connection to example.org using the new certificate',end='\r\n')
        #make a test request to see if stunnel setup is working
        seller_contacted = False
        for i in range(10):
            try:
                response = requests.get("http://example.org", proxies={"http":"http://127.0.0.1:"+str(buyer_stunnel_accept_port)})
                seller_contacted = True
                break
            except Exception,e:
                print ('Sleeping ' + str(i+1) + ' sec while trying to connect to the seller',end='\r\n')
                time.sleep(1)
        if not seller_contacted:
            print ("Can't connect to the seller",end='\r\n')
            cleanup_and_exit()  
        elif response.status_code != 200:
            print ("Unable to make a test connection through seller's proxy",end='\r\n')
            cleanup_and_exit()
    #stunnel changes PID after launch, use pidfile
    pidfile = open('/tmp/stunnel.pid', 'r')
    pid = int(pidfile.read().strip())
    pids['stunnel'] = pid

def send_logs_to_escrow(ssl_hashes):
    print ("Findind SSL segments in captured traffic",end='\r\n')
    if len(ssl_hashes) < 1:
        print ('No SSL hashes provided',end='\r\n')
        cleanup_and_exit()
        
    hashes_to_keep = ssl_hashes[:]
    hashes_to_remove = []
    post_hashes_present = False
    if ssl_hashes.count('POST') == 1:
        post_hashes_present = True
        hashes_to_remove = ssl_hashes[ssl_hashes.index('POST')+1:]
        hashes_to_keep = ssl_hashes[:ssl_hashes.index('POST')]
           
    #we're only concerned with SSL frames which don't contain handshakes but application data
    try:
        frames_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'frame.number'])
    except Exception,e:
        print ('Exception in tshark',e,end='\r\n')
        cleanup_and_exit()
    frames_str = frames_str.rstrip()
    ssl_frames = frames_str.split('\n')
    ssl_frames.reverse()
    print ('need to process SSL frames:', len(ssl_frames),end='\r\n')
    
    try:
        app_data_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'ssl.app_data'])
    except Exception,e:
        print ('Exception in tshark',e)
        cleanup_and_exit()
    app_data_str = app_data_str.rstrip()
    app_data = app_data_str.split('\n')
    app_data.reverse()
    if len(app_data) != len(ssl_frames):
        print ('Mismatch in number of frames and application data items',end='\r\n')
        cleanup_and_exit()
      
    break_out = False
    frames_to_keep = []
    #the list is reversed() to search from it's end and finish the loop faster
    for index,appdata in enumerate(app_data):
        print ('Processing frame ' + str(index+1) + ' out of total ' + str(len(ssl_frames)),end='\r\n')        
        #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
        segments = appdata.split(',')
        for one_segment in segments:
            one_segment = one_segment.replace(':',' ')
            ssl_md5 = hashlib.md5(bytearray.fromhex(one_segment)).hexdigest()
            if ssl_md5 in hashes_to_keep:
                print ("found hash", ssl_md5)
                frames_to_keep.append(ssl_frames[index])
                if len(frames_to_keep) == len(hashes_to_keep):
                    break_out = True
                    break            
        if break_out == True:
            break
            
    if len (frames_to_keep) != len(hashes_to_keep):
        print ("Couldn't find all SSL frames with given hashes. Frames found:"+str(len(frames_to_keep))+" out of:"+str(len(hashes_to_keep)),end='\r\n')
        cleanup_and_exit()
    else:      
        #sanity check: the whole scheme hinges on the assumption that all the found SSL segments belong to the same TCP stream
        print ('Checking that all frames belong to the same TCP stream',end='\r\n')
        tshark_arg = 'frame.number=='+frames_to_keep[0]
        for frame in frames_to_keep[1:]:
            tshark_arg += ' or frame.number=='+frame
        try:
            tcpstreams_str =  subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', tshark_arg, '-T', 'fields', '-e', 'tcp.stream'])
        except Exception,e:
            print ('Error starting tshark',e,end='\r\n')
            cleanup_and_exit()
        tcpstreams_str = tcpstreams_str.rstrip()
        tcpstreams = tcpstreams_str.split('\n')
        #the amount of elements with the value of element [0] should be equal to the size of list
        if tcpstreams.count(tcpstreams[0]) != len(tcpstreams):
            print ("A very serious issue encountered. Not all SSL segments belong to the same TCP stream. Please contact the developers",end='\r\n')
            cleanup_and_exit()
            
    print ("Cutting off all frames following the last SSL frame",end='\r\n')
    #This is needed so that the escrow could be sure that the last HTML file in the TCP stream is the target
    cut_off_point = sorted(frames_to_keep)[-1]   
    try:
        subprocess.call([editcap_exepath, seller_dumpcap_capture_file, seller_dumpcap_capture_file+'1', '-r', '0-'+cut_off_point])
    except Exception,e:
        print ('Exception in editcap',e,end='\r\n')
        cleanup_and_exit()
        
        
    print ("All SSL segments found, removing all confidential information from the captured traffic",end='\r\n')
    
    #-------------------------------------------------------------------------------------------------
    #Obsolete code left here just in case
    #[frames_to_purge.remove(item) for item in frames_wanted if item in frames_to_purge]
    #----------------------------------------------------------------------------------------------
    
    #Leave only the TCP stream of the SSL segments we need to keep
    try:
        frames_to_keep_str =  subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file+'1', '-Y', 'tcp.stream=='+tcpstreams[0], '-T', 'fields', '-e', 'frame.number'])
    except Exception,e:
        print ('Error starting tshark',e,end='\r\n')
        cleanup_and_exit()
    frames_to_keep_str = frames_to_keep_str.rstrip()
    frames_to_keep = frames_to_keep_str.split('\n')
    
    frames_in_chunk = 500
    if len(frames_to_keep) > frames_in_chunk:
        #editcap can't handle editing more than 512 frames in one invocation, hence the workaround
        prev_last_frame = '0'
        #max amount of ssl frames in one chunk that gets processed by editcap
        for iteration in range(len(frames_to_keep)/frames_in_chunk + 1):
            frame_chunk = frames_to_keep[frames_in_chunk*iteration:frames_in_chunk*(iteration+1)]
            last_frame = frame_chunk[-1]
            partname = 'part' + str(iteration+1)
            subprocess.call([editcap_exepath, seller_dumpcap_capture_file+'1', seller_dumpcap_capture_file+'2', '-r', '0-'+last_frame])
            editcap_args = [editcap_exepath, seller_dumpcap_capture_file+'2', seller_dumpcap_capture_file+partname, '-r']
            for frame in frame_chunk:
                editcap_args.append(frame)
            try:
                subprocess.call(editcap_args)
            except Exception,e:
                print ('Exception in editcap',e,end='\r\n')
                cleanup_and_exit()
            prev_last_frame = last_frame
            
        mergecap_args = [mergecap_exepath, '-a', '-w', seller_dumpcap_capture_file+'final']
        for iteration in range(len(frames_to_keep)/frames_in_chunk + 1):
            mergecap_args.append(seller_dumpcap_capture_file+'part'+ str(iteration+1))
            subprocess.call(mergecap_args)
            
    else:
        editcap_args = [editcap_exepath, seller_dumpcap_capture_file+'1', seller_dumpcap_capture_file+'final', '-r']
        for frame in frames_to_keep:
            editcap_args.append(frame)
        try:
            subprocess.call(editcap_args)
        except Exception,e:
            print ('Exception in editcap', e,end='\r\n')
            cleanup_and_exit() 
            
    #if there were any POST requests to remove, find them in the newly edited cap
    if post_hashes_present == True:
        frames_to_remove = []
        try:
            frames_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file+'final', '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'frame.number'])
        except Exception,e:
            print ('Exception in tshark',e,end='\r\n')
            cleanup_and_exit()
        frames_str = frames_str.rstrip()
        ssl_frames = frames_str.split('\n')
        print ('Need to process another SSL frames:', len(ssl_frames),end='\r\n')
        
        try:
            app_data_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file+'final', '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'ssl.app_data'])
        except Exception,e:
            print ('Exception in tshark',e)
            cleanup_and_exit()
        app_data_str = app_data_str.rstrip()
        app_data = app_data_str.split('\n')
        if len(app_data) != len(ssl_frames):
            print ('Mismatch in number of frames and application data items',end='\r\n')
            cleanup_and_exit()
            
        break_out = False
        for index,appdata in enumerate(app_data):
            print ('Processing frame ' + str(index+1) + ' out of total ' + str(len(ssl_frames)), end='\r\n')        
            #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
            segments = appdata.split(',')
            
            for one_segment in segments:
                one_segment = one_segment.replace(':',' ')
                ssl_md5 = hashlib.md5(bytearray.fromhex(one_segment)).hexdigest()
                if ssl_md5 in hashes_to_remove:
                    print ("found hash", ssl_md5, end='\r\n')
                    frames_to_remove.append(ssl_frames[index])
                    #'POST' is an item of ssl_frames list, subtract it when comparing list sizes
                    if len(frames_to_remove) == len(hashes_to_remove):
                        break_out = True
                        break
            if break_out == True:
                break
                
        if len(frames_to_remove) != len(hashes_to_remove):
            print ("Couldn't find all SSL frames with given hashes. Frames found:"+str(len(frames_to_remove))+" out of:"+str(len(hashes_to_remove)),end='\r\n')
            cleanup_and_exit()
            
        #Remove the frames
        editcap_args = [editcap_exepath, seller_dumpcap_capture_file+'final', seller_dumpcap_capture_file+'final2']
        for frame in frames_to_remove:
            editcap_args.append(frame)
        try:
            subprocess.call(editcap_args)
        except Exception,e:
            print ('Exception in editcap',e,end='\r\n')
            cleanup_and_exit()
                  
    #at this point, send the capture to escrow. For testing, save it locally.
    #don't forget to base64 encode it if sending via http head
    shutil.copy(seller_dumpcap_capture_file+('final2' if post_hashes_present else 'final' ), os.path.join(installdir,'escrow','escrow.pcap'))
        

#the return value will be placed into HTTP header and sent to buyer. Python has a 64K limit on header size
#NB. seller sends his stunnel.key to be used after the banking session is over to decrypt escrowtrace
def seller_get_certificate_verify_message():
    global stunnelkey
    global stunnelkeyhash
    
    print ("Preparing and sending the certificate+key together with a signature to the buyer",end='\r\n')
    with open (os.path.join(installdir, "stunnel", "seller.pem"), "r") as certfile:
        certdata = certfile.read()
    certificate = certdata.__str__()
    with open (os.path.join(installdir, "stunnel", "seller.key"), "r") as keyfile:
        keydata = keyfile.read()
    key = keydata.__str__()
 
    #bitcond needs about 10 sec to initialize an empty dir when launched for the first time
    #check if it is finished initializing and is ready for queries. Try 4 times with an interval of 5 sec
    for i in range(4):
        try:
            retval = ''
            retval = seller_bitcoin_rpc.getinfo()
            if retval != '':
                break
        except:
            if i == 3:
                print ("Aborting.Couldn't connect to bitcoind",end='\r\n')
                cleanup_and_exit()
            else:
                print ('Failed to connect to bitcoind on try '+ str(i+1) +'of4. Sleeping 5 sec.',end='\r\n')
                time.sleep(5)
    #Since the datadir has just been created, we need to create a new address to sign with
    #This is only done in the testing mode
    #In real-life though, the address would have already been created and used to perform the 2-of-3 transaction
    try:
        seller_btc_address = seller_bitcoin_rpc.getaccountaddress('seller')
    except Exception, e:
        print ("Error while invoking getaccountaddress", e,end='\r\n')
        cleanup_and_exit()
    try:
        cert_signature = seller_bitcoin_rpc.signmessage(seller_btc_address, certificate)
        key_signature = seller_bitcoin_rpc.signmessage(seller_btc_address, key)
    except Exception, e:
        print ("Error while invoking signmessage. Did you indicate a valid BTC address?", e,end='\r\n')
        cleanup_and_exit()
    return key + ';' + key_signature + ';' + certificate + ';' + cert_signature + ';' + seller_btc_address    

def seller_start_bitcoind_stunnel_sshpass_dumpcap_squid(skip_capture):
    global pids
    
    if skip_capture == False:
        print ("Starting bitcoind in offline mode. No part of blockchain will be downloaded",end='\r\n')
        try:
           #start bitcoind in offline mode
           bitcoind_proc = subprocess.Popen([bitcoind_exepath, '-datadir=' + os.path.join(installdir, 'bitcoind', "datadir_seller"), '-maxconnections=0', '-server', '-listen=0', '-rpcuser=ssllog_user', '-rpcpassword=ssllog_pswd', '-rpcport=8339'], stdout=open(os.path.join(installdir, 'bitcoind', "bitcoind_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'bitcoind', "bitcoind_seller.stderr"),'w'))
        except:
            print ('Exception starting bitcoind',end='\r\n')
            cleanup_and_exit()
        pids['bitcoind']  = bitcoind_proc.pid
        
        print ("Starting ssh connection to escrow's server",end='\r\n')
        try:
            sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_ssh_host, '-p', str(escrow_ssh_port), '-R', str(escrow_dumpcap_port)+':localhost:33310'], stdout=open(os.path.join(installdir, 'ssh', "ssh_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'ssh', "ssh_seller.stderr"),'w'))
        except:
            print ('Exception connecting to sshd',end='\r\n')
            cleanup_and_exit()
        pids['sshpass']  = sshpass_proc.pid
    
    print ("Starting stunnel",end='\r\n')
    try:
        stunnel_proc = subprocess.Popen([stunnel_exepath, os.path.join(installdir, 'stunnel', 'seller.conf')], cwd=os.path.join(installdir, 'stunnel'), stdout=open(os.path.join(installdir, 'stunnel', 'stunnel_seller.stdout'),'w'), stderr=open(os.path.join(installdir, 'stunnel', 'stunnel_seller.stderr'),'w'))
    except:
        print ('Exception starting stunnel',end='\r\n')
        cleanup_and_exit()
    #stunnel changes PID after launch, use pidfile
    #give it some time to create the pid file
    pid_file_found = False
    for i in range(20):
        try:
            pidfile = open('/tmp/stunnel2.pid', 'r')
            pid_file_found = True
            break
        except Exception,e:
            print ('Sleeping ' + str(i+1) + ' secs while stunnel pid file is being created',end='\r\n')
            time.sleep(1)
    if not pid_file_found:
        print (e,end='\r\n')
        cleanup_and_exit()
    
    pid = int(pidfile.read().strip())
    pids['stunnel'] = pid
    
    print ("Starting squid3",end='\r\n')
    try:
        squid3_proc = subprocess.Popen([squid3_exepath, '-f', os.path.join(installdir, 'squid', 'squid.conf')], stdout=open(os.path.join(installdir, 'squid', 'squid.stdout'),'w'), stderr=open(os.path.join(installdir, 'squid', 'squid.stderr'),'w'))
    except:
        print ('Exception starting squid',end='\r\n')
        cleanup_and_exit()
    pids['squid3'] = squid3_proc.pid
        
    if skip_capture == False:
        print ("Starting dumpcap capture of loopback traffic",end='\r\n')
        try:
            #todo: don't assume that 'lo' is the loopback, query it
            #listen in-between stunnel and squid, filter out all the rest of loopback traffic
            dumpcap_proc = subprocess.Popen([dumpcap_exepath, '-i', 'lo', '-B', '10', '-f', 'tcp port 3128', '-w', seller_dumpcap_capture_file ], stdout=open(os.path.join(installdir, 'dumpcap', "dumpcap_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'dumpcap', "dumpcap_seller.stderr"),'w'))
        except Exception,e:
            print ('Exception dumpcap',e,end='\r\n')
            cleanup_and_exit()
        pids['dumpcap'] = dumpcap_proc.pid    
    
def buyer_get_and_verify_seller_cert():
    global stunnelkey
    global stunnelkeyhash
    #receive signature and plain_cert as ";" delimited string
    print ('Requesting the certificate from the seller',end='\r\n')
    seller_contacted = False
    for i in range(10):
        try:
            response = requests.head("http://127.0.0.1:"+str(seller_http_port)+"/certificate", proxies={"http":"http://127.0.0.1:"+str(buyer_stunnel_accept_port)})
            seller_contacted = True
            break
        except Exception,e:
            print ('Sleeping ' + str(i+1) + ' sec while trying to connect to the seller',end='\r\n')
            time.sleep(1)
    if not seller_contacted:
        print ("Can't connect to the seller",end='\r\n')
        cleanup_and_exit()  
    elif response.status_code != 200:
        print ("Unable to get seller's certificate",end='\r\n')
        cleanup_and_exit()
    base64_message = response.headers['value']
    message = base64.b64decode(base64_message)
    items = message.split(';')
    key = items[0]
    key_sig =items[1]
    cert = items[2]
    cert_sig = items[3]
    seller_btc_address = items[4]
    
    print ("Verifying seller's certificate with bitcoind",end='\r\n')
    #bitcond needs about 10 sec to initialize an empty dir when launched for the first time
    #check if it is finished initializing and is ready for queries. Try 4 times with an interval of 10 sec
    for i in range(4):
        try:
            buyer_bitcoin_rpc.getinfo()
        except:
            if i == 3:
                print ("Aborting.Couldn't connect to bitcoind",end='\r\n')
                cleanup_and_exit()
            else:
                print ('Failed to connect to bitcoind on try '+ str(i+1) +'of4. Sleeping 10 sec.',end='\r\n')
                time.sleep(10)
        
                
    print ("Verifying seller's certificate for stunnel",end='\r\n')
    try:
        if buyer_bitcoin_rpc.verifymessage(seller_btc_address, cert_sig, cert) != True :
            print ("Failed to verify seller's certificate",end='\r\n')
            cleanup_and_exit()
        if buyer_bitcoin_rpc.verifymessage(seller_btc_address, key_sig, key) != True :
            print ("Failed to verify seller's key",end='\r\n')
            cleanup_and_exit()
    except Exception,e:
        print ('Exception while calling verifymessage',e,end='\r\n')
        cleanup_and_exit()
    
    print ('Successfully verified sellers certificate, writing it to disk',end='\r\n')
    with open (os.path.join(installdir, "stunnel","verifiedcert.pem"), "w") as certfile:
        certfile.write(cert)
    with open (buyer_stunnelkey), "w") as keyfile:
        keyfile.write(key)
        
    

#start processes and return their PIDs for later SIGTERMing
def buyer_start_bitcoind_stunnel_sshpass_dumpcap(skip_capture):
    global pids
    global ppid
    
    if skip_capture == False:
        print ('Starting bitcoind',end='\r\n')     
        try:
            #start bitcoind in offline mode
            bitcoind_proc = subprocess.Popen([bitcoind_exepath, '-datadir=' + os.path.join(installdir, 'bitcoind', "datadir_buyer"), '-maxconnections=0', '-server', '-listen=0', '-rpcuser=ssllog_user', '-rpcpassword=ssllog_pswd', '-rpcport=8338'], stdout=open(os.path.join(installdir, 'bitcoind', "bitcoind_buyer.stdout"),'w'), stderr=open(os.path.join(installdir, 'bitcoind', "bitcoind_buyer.stderr"),'w'))
        except:
            print ('Exception starting bitcoind',end='\r\n')
            cleanup_and_exit()
        pids['bitcoind'] = bitcoind_proc.pid
    
    print ('Starting ssh connection',end='\r\n')
    try:
        sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_ssh_host, '-p', str(escrow_ssh_port), '-L', '33309:localhost:'+str(escrow_dumpcap_port)], stdout=open(os.path.join(installdir, 'ssh','ssh_buyer.stdout'),'w'),  stderr=open(os.path.join(installdir, 'ssh','ssh_buyer.stderr'),'w'))
    except:
        print ('Exception connecting to sshd',end='\r\n')
        cleanup_and_exit()
    pids['sshpass'] = sshpass_proc.pid
      
    if skip_capture == False:            
        print ('Starting stunnel',end='\r\n')
    #1st invocation of stunnel serves only the purpose of getting the certifcate from the seller
    #after receiving the certificate, stunnel is terminated and restarted with the new certfcate
    #stunnel finds paths in .conf relative to working dir
        try:
            #stunnel parses its config against a current working directory (cwd)
            stunnel_proc = subprocess.Popen([stunnel_exepath, os.path.join(installdir, 'stunnel', 'buyer_pre.conf')], cwd=os.path.join(installdir, 'stunnel'), stdout=open(os.path.join(installdir, 'stunnel', 'stunnel_buyer_pre.stdout'),'w'), stderr=open(os.path.join(installdir, 'stunnel', 'stunnel_buyer_pre.stderr'),'w') )
        except:
            print ('Exception starting stunnel',end='\r\n')
            cleanup_and_exit()
        #stunnel changes PID after launch, use pidfile
        #give it some time to create the pid file
        pid_file_found = False
        for i in range(20):
            try:
                pidfile = open('/tmp/stunnel.pid', 'r')
                pid_file_found = True
                break
            except Exception,e:
                print ('Sleeping ' + str(i+1) + ' secs while stunnel pid file is being created',end='\r\n')
                time.sleep(1)
        if not pid_file_found:
            print (e,end='\r\n')
            cleanup_and_exit()
        pid = int(pidfile.read().strip())
        pids['stunnel'] = pid
            
        print ('Making a test connection to example.org through the tunnel',end='\r\n')
        #make a test request to see if stunnel setup is working. Two attempts with a 5 sec interval (in case seller hasn't yet caught up with his initialization)
        seller_contacted = False
        for i in range(10):
            try:
                response = requests.get("http://example.org", proxies={"http":"http://127.0.0.1:"+str(buyer_stunnel_accept_port)})
                seller_contacted = True                
                break
            except Exception,e:
                print ('Sleeping ' + str(i+1) + ' sec while trying to connect to the seller',end='\r\n')
                time.sleep(1)
        if not seller_contacted:
            print ("Can't connect to the seller",e,end='\r\n')
            cleanup_and_exit()  
        elif response.status_code != 200:
            print ("Error while making a test connection",end='\r\n')
            print (response.text,end='\r\n')
            cleanup_and_exit()
         
        print ('Starting dumpcap in capture mode',end='\r\n')
        try:
            #todo: don't assume that 'lo' is the loopback, query it
            #listen in-between Firefox and stunnel, filter out all the rest of loopback traffic
            dumpcap_proc = subprocess.Popen([dumpcap_exepath, '-i', 'lo', '-B', '10', '-f', 'tcp port '+str(buyer_stunnel_accept_port), '-w', buyer_dumpcap_capture_file ], stdout=open(os.path.join(installdir, 'dumpcap', "dumpcap_buyer.stdout"),'w'), stderr=open(os.path.join(installdir, 'dumpcap', "dumpcap_buyer.stderr"),'w'))
        except Exception,e:
            print ('Exception starting dumpcap',e,end='\r\n')
            cleanup_and_exit()
        pids['dumpcap'] = dumpcap_proc.pid

#use miniHTTP server to receive commands from Firefox addon and respond to them
def buyer_start_minihttp_thread():
    print ('Starting mini http server to communicate with Firefox plugin',end='\r\n')
    try:
        httpd = StoppableHttpServer(('127.0.0.1', buyer_http_port), buyer_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        cleanup_and_exit()
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    httpd.serve_forever()
    
#use miniHTTP server to send certificate and receive SSL hashes
def seller_start_minihttp_thread(retval):
    print ("Starting mini http server and waiting for buyer's queries",end='\r\n')
    try:
        #don't forget to change host from 0.0.0.0 to 127.0.0.1
        httpd = StoppableHttpServer(('0.0.0.0', seller_http_port), seller_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        cleanup_and_exit()
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    sslhashes = httpd.serve_forever()
    #print ('Returning from HTTP server, sslhashes:',sslhashes,end='\r\n')
    #pass retval down to the thread instance
    retval.append(sslhashes)
    
def escrow_start_minihttp_thread(retval):
    print ("Starting mini http server and waiting for buyer's response",end='\r\n')
    try:
        httpd = StoppableHttpServer(('127.0.0.1', 7777), escrow_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        cleanup_and_exit()
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    sslhashes = httpd.serve_forever()
    #pass retval down to the thread instance
    #retval.append(sslhashes)
    
def start_firefox():
    #we could ask user to run Firefox with -ProfileManager and create a new profile themselves
    #but to be as user-friendly as possible, we add a new Firefox profile behind the scenes
    
    homedir = os.path.expanduser("~")
    if homedir == "~":
        print ("Couldn't find user's home directory",end='\r\n')
        cleanup_and_exit()
    #todo allow user to specify firefox profile dir manually 
    ff_user_dir = os.path.join(homedir, ".mozilla", "firefox")   
    # skip this step if "ssllog" profile already exists
    if (not os.path.isdir(os.path.join(ff_user_dir, "ssllog_profile"))):
        print ("Copying plugin files into Firefox's plugin directory",end='\r\n')
       
        try:
            inifile = open(os.path.join(ff_user_dir, "profiles.ini"), "r+a")
        except Exception,e: 
            print ('Could not open profiles.ini. Make sure it exists and you have sufficient read/write permissions',e,end='\r\n')
            cleanup_and_exit()
        text = inifile.read()
   
        #get the last profile number and increase it by 1 for our profile
        our_profile_number = int(text[text.rfind("[Profile")+len("[Profile"):].split("]")[0]) +1
    
        try:
            inifile.write('[Profile' +str(our_profile_number) + ']\nName=ssllog\nIsRelative=1\nPath=ssllog_profile\n\n')
        except Exception,e:
            print ('Could not write to profiles.ini. Make sure you have sufficient write permissions',e,end='\r\n')
            cleanup_and_exit()
        inifile.close()
    
        #create an extension dir and copy the extension files
        #we are not distributing our extension as xpi, but rather as a directory with files
        os.mkdir(os.path.join(ff_user_dir, 'ssllog_profile'))
        ff_extensions_dir = os.path.join(ff_user_dir, "ssllog_profile", "extensions")
        os.mkdir(ff_extensions_dir)
        #todo handle mkdir exception
        
        try:
            mfile = open (os.path.join(ff_extensions_dir, "sample@example.net"), "w+")
        except Exception,e:
            print ('File open error', e,end='\r\n')
            cleanup_and_exit()
        #todo print line number in error messages
        
        #write the path into the file
        try:
            mfile.write(os.path.join(ff_extensions_dir, "ssllog_addon"))
        except Exception,e:
            print ('File write error', e,end='\r\n')
            cleanup_and_exit()
        
        try:    
            shutil.copytree(os.path.join(installdir,"FF-addon"), os.path.join(ff_extensions_dir, "ssllog_addon"))
        except Exception,e:
            print ('Error copying addon from installdir',e,end='\r\n') 
            cleanup_and_exit()
    
    #empty html files from previous session
    for the_file in os.listdir(htmldir):
        file_path = os.path.join(htmldir, the_file)
        try:
            if os.path.isdir(file_path): 
                shutil.rmtree(file_path)
            else:
                os.unlink(file_path)
        except Exception, e:
            print ('Error while removing html files from previous session',e,end='\r\n')
            cleanup_and_exit()

    #create an empty dummy file
    dummy = open (os.path.join(installdir, "firefox", 'dummy'), "w+")
    dummy.close()

    #SSLKEYLOGFILE
    sslkeylogfile_path = os.path.join(installdir, 'dumpcap', 'sslkeylog')
    os.putenv("SSLKEYLOGFILE", sslkeylogfile_path)
    #TMP is where the html files are going to be saved
    os.putenv("TMP", os.path.join(installdir, 'htmldir'))
    print ("Starting a new instance of Firefox with a new profile",end='\r\n')
    try:
        subprocess.Popen([firefox_exepath,'-new-instance', '-P', 'ssllog'], stdout=open(os.path.join(installdir, 'firefox', "firefox.stdout"),'w'), stderr=open(os.path.join(installdir, 'firefox', "firefox.stderr"), 'w'))
    except Exception,e:
        print ("Error starting Firefox", e,end='\r\n')
        cleanup_and_exit()
    

#the tempdir contains html files as well as folders with js,png,css. Ignore the folders
def buyer_find_htmlframe(reference_string):
    print ("Finding and hashing any saved html files",end='\r\n')
    onlyfiles = [f for f in os.listdir(htmldir) if os.path.isfile(os.path.join(htmldir,f))]
    htmlhashes = []
    if len(onlyfiles) != 0:
        for file in onlyfiles:
            htmlhashes.append(hashlib.md5(open(os.path.join(htmldir, file), 'r').read()).hexdigest())
    else: 
        print ('No HTML files have been found in htmldir',end='\r\n')
    
    #Look for the reference string in decrypted HTML

    #get frame numbers of all non-empty html responses that came from the bank (ignore codes such as 204:No Content, 302:Found, 304:Not Modified, because there is no useful html in them )
    try:
        frames_str = subprocess.check_output([tshark_exepath, '-r', buyer_dumpcap_capture_file, '-Y', 'ssl and http.content_type contains html  and http.response.code == 200', '-T', 'fields', '-e', 'frame.number', '-o', 'ssl.keylog_file: '+sslkeylogfile])
    except Exception,e:
        print ('Error starting tshark', e,end='\r\n')
        cleanup_and_exit()
    frames_str = frames_str.rstrip()
    frames = frames_str.split('\n')
    if frames == ['']:
        print ('No HTML pages found in the capture file',end='\r\n')
        return -1
        
    found_frame = 0
    #process HTML frames from last to first, because it is very likely that the last page is the page chosen by the buyer for escrow
    for index,frame in enumerate(reversed(frames)):
        print ('Processing HTML frame ' + str(index+1) + ' out of total ' + str(len(frames)) + ' frames',end='\r\n')
        # "-x" dumps ascii info of the SSL frame, de-fragmenting SSL segments, decrypting them, ungzipping (if necessary) and showing plain HTML
        try:
            ascii_dump = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'frame.number==' + frame, '-x', '-o', 'ssl.keylog_file: '+sslkeylogfile])
        except Exception,e:
            print ('Error starting tshark', e,end='\r\n')
            cleanup_and_exit()
        html_binary = get_htmlhash_from_asciidump(ascii_dump)
        if html_binary == 0:
            print ("Expected to find HTML, but none found in frame " + str(frame) + " Please investigate",end='\r\n')
            continue        
        if html_binary.lower().find(reference_string.lower()) != -1:        
            found_frame = frame
            print ("found HTML containing reference string in frame No " + frame,end='\r\n')
            #for statistics
            if len(htmlhashes)>0:
                if htmlhashes[0] == hashlib.md5(binary_html).hexdigest():
                    print ('HTML saved by Firefox and HTML found in the tracefile matched!',end='\r\n')
            break       
    if not found_frame:            
        print ("Couldn't find HTML containing reference string ",end='\r\n')
        return -1
        
    return found_frame

#return the hashes of HTML-forming SSL-segments
def buyer_get_sslhashes(capturefile, html_frame):
    sslhashes = []
             
    #collect other possible SSL segments which are part of HTML page. 
    segments = [html_frame]
    try:
        segments_str =  subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'frame.number==' + html_frame, '-T', 'fields', '-e', 'ssl.segment', '-o', 'ssl.keylog_file: '+sslkeylogfile])
    except Exception, e:
        print ('Error starting tshark', e,end='\r\n')
        cleanup_and_exit()
    segments_str = segments_str.rstrip()
    if segments_str != '':
        segments += segments_str.split(',')
    if len(segments) < 1:
        print ('zero SSL segments, should be at least one. Please investigate',end='\r\n')
        cleanup_and_exit()
    #there can be multiple SSL segments in the same packet, so remove duplicates
    segments = list(set(segments))
      
    #sanity check: the whole scheme hinges on the assumption that all the found SSL segments belong to the same TCP stream
    tshark_arg = 'frame.number=='+segments[0]
    for segment in segments[1:]:
        tshark_arg += ' or frame.number=='+segment
    try:
        tcpstreams_str =  subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', tshark_arg, '-T', 'fields', '-e', 'tcp.stream'])
    except Exception,e:
        print ('Error starting tshark',e,end='\r\n')
        cleanup_and_exit()
    tcpstreams_str = tcpstreams_str.rstrip()
    tcpstreams = tcpstreams_str.split('\n')
    #the amount of elements with the value of element [0] should be equal to the size of list
    if tcpstreams.count(tcpstreams[0]) != len(tcpstreams):
        print ("A very serious issue encountered. Not all SSL segments belong to the same TCP stream. Please contact the developers",end='\r\n')
        cleanup_and_exit()
        
    print ('Extracting hex data from ' + str(len(segments)) + ' SSL segments',end='\r\n')
    frame_argument = 'frame.number=='+segments[0]
    for segment in sorted(segments[1:]):
        frame_argument += ' or frame.number==' + segment            
    try:
        frames_ssl_hex = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', frame_argument, '-T', 'fields', '-e', 'ssl.app_data'])
    except Exception,e:
        print ('Error starting tshark',e,end='\r\n')
        cleanup_and_exit()
    frames_ssl_hex = frames_ssl_hex.rstrip()
    frames_ssl_hex = frames_ssl_hex.split('\n')
    for frame_hex in frames_ssl_hex:
        #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
        frame_segments = frame_hex.split(',')
        for one_segment in frame_segments:
            #get rid of commas and colons
            one_segment = one_segment.replace(':',' ')
            if one_segment == ' ':
                print ('empty frame hex. Please investigate',end='\r\n')
                cleanup_and_exit()
            sslhashes.append(hashlib.md5(bytearray.fromhex(one_segment)).hexdigest())
    return tcpstreams[0], sslhashes
            
                                     
    # For good measure instruct the seller to remove any packets containing HTTP POST requests
    # This way we guarantee that no login credentials will ever get accidentally submitted to escrow
    #Don't remove POSTs which follow the found SSL frame, because the seller will cut off everything following the found SSL frame anyway
    try:
        post_requests_str = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'ssl and tcp.stream=='+tcpstreams[0]+' and http.request.method==POST and frame.number<'+found_frame, '-T', 'fields', '-e', 'frame.number'])
    except Exception,e:
        print ('Error starting tshark',e,end='\r\n')
        cleanup_and_exit()
    post_requests_str = post_requests_str.rstrip()
    post_requests = post_requests_str.split('\n')
    if post_requests != ['']:
        print ('Found a POST request. Making sure the seller will remove it',end='\r\n')
        sslhashes.append('POST')
        for request in post_requests:
            try:
                frames_ssl_hex = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'frame.number=='+request, '-T', 'fields', '-e', 'ssl.app_data'])
            except Exception,e:
                print ('Error starting tshark',e,end='\r\n')
                cleanup_and_exit()
            frames_ssl_hex = frames_ssl_hex.rstrip()
            frames_ssl_hex = frames_ssl_hex.split('\n')
            for frame_hex in frames_ssl_hex:
                #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
                frame_segments = frame_hex.split(',')
                for one_segment in frame_segments:
                    #get rid of colons
                    one_segment = one_segment.replace(':',' ')
                    if one_segment == ' ':
                        print ('empty frame hex. Please investigate',end='\r\n')
                        cleanup_and_exit()
                    sslhashes.append(hashlib.md5(bytearray.fromhex(one_segment)).hexdigest())
                            
    #The buyer has to process the capture file just like the seller will
    #The buyer has to ensure that HTML is readable and any POSTs are not present   
    return sslhashes

#look at tshark's ascii dump to better understand the parsing taking place
def get_htmlhash_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        cleanup_and_exit()
        return

    #We are interested in "Uncompressed entity body" for compressed HTML. If not present, then
    #the very last entry of "De-chunked entity body" for no-compression no-chunks HTML. If not present, then
    #the very last entry of "Reassembled SSL" for no-compression no-chunks HTML in multiple SSL segments (very rare),
    #and finally, the very last entry of "Decrypted SSL data" for no-compression no-chunks HTML in a single SSL segment.
    already_found = False
    dechunked_pos = -1
    reassembled_pos = -1
    decrypted_pos = -1
    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        already_found = True
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                m_array = bytearray.fromhex(line[6:54])
                binary_html += m_array
            else:
                break
            
    if uncompr_pos == -1 and not already_found:
        dechunked_pos = ascii_dump.rfind('De-chunked entity body')
        if dechunked_pos != -1:
            already_found = True
            for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
                #convert ascii representation of hex into binary
                #only deal with lines where first 4 chars are hexdigits
                if all(c in hexdigits for c in line [:4]):
                    m_array = bytearray.fromhex(line[6:54])
                    binary_html += m_array
                else:
                    break
                
    if dechunked_pos == -1 and not already_found:
        reassembled_pos = ascii_dump.rfind('Reassembled SSL')
        if reassembled_pos != -1:
            already_found = True
            #skip the HTTP header and find where the HTTP body starts
            #The delimiter of header from body '0d 0a 0d 0a' can be spanned over two lines
            #Hence the workaround
            
            lines = ascii_dump[reassembled_pos:].split('\n')
            line_length = len(lines[1])+1
            line_numbering_length = len(lines[1].split()[0])
            hexlist = [line.split()[1:17] for line in lines[1:]]
            #flatten the nested lists acc.to http://stackoverflow.com/questions/952914/making-a-flat-list-out-of-list-of-lists-in-python
            flathexlist = [item for sublist in hexlist for item in sublist]
            #convert the list into a single string
            hexstring = ''.join(flathexlist)
            start_pos_in_hex = hexstring.find('0d0a0d0a')+len('0d0a0d0a')
            #Knowing that there are 16 2-char hex numbers in a single line, calculate absolute position
            start_line_in_ascii = start_pos_in_hex/32
            line_offset_in_ascii = (start_pos_in_hex % 32)/2
                     
            #The very first hex is line numbering,it is followed by 2 spaces
            #each hex number in a line takes up 2 alphanum chars + 1 space char
            #we skip the very first line 'Reassembled SSL ...' by finding a newline.
            newline_offset = ascii_dump[reassembled_pos:].find('\n')
            body_start = reassembled_pos+newline_offset+1+start_line_in_ascii*line_length+line_numbering_length+2+line_offset_in_ascii*3
            if body_start == -1:
                print ('Could not find HTTP body',end='\r\n')
                cleanup_and_exit()
                return
            lines = ascii_dump[body_start:].split('\n')
            #treat the first line specially
            binary_html += bytearray.fromhex(lines[0][:-16])
            for line in lines[1:]:
                #convert ascii representation of hex into binary
                #only deal with lines where first 4 chars are hexdigits
                if all(c in hexdigits for c in line [:4]):
                    m_array = bytearray.fromhex(line[6:54])
                    binary_html += m_array
                else:
                    break
                
    if reassembled_pos == -1 and not already_found:
        decrypted_pos = ascii_dump.rfind('Decrypted SSL data')
        if decrypted_pos != -1:  
            already_found = True   
            #skip the HTTP header and find where the HTTP body starts
            #The delimiter of header from body '0d 0a 0d 0a' can be spanned over two lines
            #Hence the workaround
            
            lines = ascii_dump[decrypted_pos:].split('\n')
            line_length = len(lines[1])+1
            line_numbering_length = len(lines[1].split()[0])
            hexlist = [line.split()[1:17] for line in lines[1:]]
            #flatten the nested lists acc.to http://stackoverflow.com/questions/952914/making-a-flat-list-out-of-list-of-lists-in-python
            flathexlist = [item for sublist in hexlist for item in sublist]
            #convert the list into a single string
            hexstring = ''.join(flathexlist)
            start_pos_in_hex = hexstring.find('0d0a0d0a')+len('0d0a0d0a')
            #Knowing that there are 16 2-char hex numbers in a single line, calculate absolute position
            start_line_in_ascii = start_pos_in_hex/32
            line_offset_in_ascii = (start_pos_in_hex % 32)/2
                     
              #The very first hex is line numbering,it is followed by 2 spaces
            #each hex number in a line takes up 2 alphanum chars + 1 space char
            #we skip the very first line 'Reassembled SSL ...' by finding a newline.
            newline_offset = ascii_dump[decrypted_pos:].find('\n')
            body_start = decrypted_pos+newline_offset+1+start_line_in_ascii*line_length+line_numbering_length+2+line_offset_in_ascii*3            
            
            if body_start == -1:
                print ('Could not find HTTP body',end='\r\n')
                cleanup_and_exit()
                return
            lines = ascii_dump[body_start:].split('\n')
            #treat the first line specially
            binary_html += bytearray.fromhex(lines[0][:-16])
            for line in lines[1:]:
                #convert ascii representation of hex into binary
                #only deal with lines where first 4 chars are hexdigits
                if all(c in hexdigits for c in line [:4]):
                    m_array = bytearray.fromhex(line[6:54])
                    binary_html += m_array
                else:
                    break
                    
    if decrypted_pos == -1 and not already_found:
        #
        #
        #TODO Fix a corner case where strings being searched are spanned over two lines
        #
        #
        
        #example.org's response going through squid ends up as ungzipped, unchunked HTML
        page_end = ascii_dump.rfind('.\n\n')
        if page_end == -1:
            print ("Could not find page's end",end='\r\n')
            return 0
        
        page_start = ascii_dump.rfind('0d 0a 0d 0a')
        #skip the HTTP header and find where the HTTP body starts
        #The delimiter of header from body '0d 0a 0d 0a' can be spanned over two lines
        #Hence the workaround
        
        lines = ascii_dump.split('\n')
        hexlist = [line.split()[1:17] for line in lines]
        #flatten the nested lists acc.to http://stackoverflow.com/questions/952914/making-a-flat-list-out-of-list-of-lists-in-python
        flathexlist = [item for sublist in hexlist for item in sublist]
        #convert the list into a single string
        hexstring = ''.join(flathexlist)
        delimiter_pos = hexstring.rfind('0d0a0d0a')
        if delimiter_pos == -1:
            print ("Could not find page's start",end='\r\n')
            return 0                
        start_pos_in_hex = delimiter_pos +len('0d0a0d0a')
        #Knowing that there are 16 2-char hex numbers in a single line, calculate absolute position
        start_line_in_ascii = start_pos_in_hex/32
        line_offset_in_ascii = (start_pos_in_hex % 32)/2                 
        #an ascii line is 73 chars long, each hex number takes up 2 alphanum chars + 1 space char
        #There are 6 line number chars (including spaces) at the start of each line
        page_start = start_line_in_ascii*73+6+line_offset_in_ascii*3
              
        if page_end < page_start:
            print ("Could not find HTML page",end='\r\n')
            return 0
        lines = ascii_dump[page_start:page_end+len('.\n\n')].split('\n')
        #treat the first line specially
        binary_html += bytearray.fromhex(lines[0][:-16])
        for line in lines[1:]:
            #convert ascii representation of hex into binary
            #only deal with lines where first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                m_array = bytearray.fromhex(line[6:54])
                binary_html += m_array
            else:
                break    
                   
    if len(binary_html) == 0:
        print ('empty binary array',end='\r\n')
        cleanup_and_exit()
        return
    #FF's view source  (against which we are comparing) makes certain changes to the original HTML. It replaces
    #    '\r\n' with '\n'
    #and '\r'   with '\n'
    binary_html2 = binary_html.replace('\r\n','\n')
    binary_html3 = binary_html2.replace('\r','\n')
    return binary_html3
   

def rearrange_outoforder_frames(capture_file):
#This function analyzes a wireshark capture searching for a pattern of out-of-order frames
#The corrected capture file with the prefix "new_" will be placed in the same dir as the original capture file

#Looking for a pattern in a wireshark capture:
#1. some packet != [TCP Previous segment not captured]
#2. some packet
#3. [TCP Previous segment not captured]
#4. some packet
#5. [TCP out-of-order]
#6. some packet
#7. some packet != [TCP out-of-order] and != [TCP Retransmission]

#if 1st packet is [TCP Prev...] then frames 1-5 need to be rearranged, likewise
#if 7th packet is [TCP ...] then frames 3-7 need to be rearranged
#This function ignores such patterns. It only aims at rearranging frames 3-5
        
    #FINACK,SYN,SYNACK - the recepient must add 1 to TCP ack upon receipt of special flags
    special_flags = ["0x0011","0x0002","0x0012"]
    
    global installdir
    capturedir = os.path.join(installdir, 'dumpcap')
    #backup the original capture file
    new_capture_file = os.path.join(capturedir, 'new_' + os.path.basename(capture_file))
    shutil.copyfile(capture_file, new_capture_file)
    
    # -M is needed to prevent displaying rounded frame count like 24k instead of 24350
    last_frame_no = subprocess.check_output([capinfos_exepath,'-c', '-M', capture_file]).strip().split()[-1]
  
    ooo_frames_str = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'tcp.analysis.out_of_order', '-T', 'fields', '-e', 'frame.number'])
    if ooo_frames_str == '':
        raise Exception('No out-of-order frames found')
        
    ooo_frames_str = ooo_frames_str.strip()
    ooo_frames = ooo_frames_str.split('\n')
    
    lost_frames_str = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'tcp.analysis.lost_segment', '-T', 'fields', '-e', 'frame.number'])
    lost_frames_str = lost_frames_str.strip()
    lost_frames = lost_frames_str.split('\n')
    
    retr_frames_str = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'tcp.analysis.retransmission', '-T', 'fields', '-e', 'frame.number'])
    retr_frames_str = retr_frames_str.strip()
    retr_frames = retr_frames_str.split('\n')
    
    print ('Total ooo frames '+ str(len(ooo_frames)),end='\r\n')
    rearrange_unknown_error_count = 0
    rearrange_expected_error_count = 0
    rearrange_success_count = 0
    
    for index1,frame in enumerate(ooo_frames):
        print ('Processing frame '+ str(index1),end='\r\n')
        if not (str(int(frame)-2) in lost_frames and str(int(frame)-4) not in lost_frames and str(int(frame)+2) not in ooo_frames and str(int(frame)+2) not in retr_frames):
            continue
        
        #make sure that all the 7 packets belong to the same stream, ie they are not two streams intermingled    
        #get the frame's tcp.stream
        stream = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'frame.number=='+frame, '-T', 'fields', '-e', 'tcp.stream'])
        stream = stream.strip()
        #get all frames of the stream
        frames_str = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'tcp.stream=='+stream, '-T', 'fields', '-e', 'frame.number'])
        frames_str = frames_str.strip()
        frames_in_stream = frames_str.split('\n')
        #get the ooo frame's index
        ooo_index = frames_in_stream.index(frame)
        
        #make sure there are at least 4 packets before and 2 after the ooo frame
        if ooo_index < 4 or ooo_index > len(frames_in_stream)-3:
            print ('Expected error! Not enough frames before or after '+ frame,end='\r\n')
            rearrange_expected_error_count += 1
            continue
            
        #make sure that the 3 frames to be rearranged and the 2 encompassing frames are consecutive, ie there are no other frames between them. This is needed to simplify cutting/merging later.
        #It is possible in theory that some other frames may end up in between the 5 frames, but since wireshark is logging only a single SSL banking session, that is unlikely enough not be considered
        if not (int(frames_in_stream[ooo_index+1])-1 == int(frames_in_stream[ooo_index]) and int(frames_in_stream[ooo_index])-1 == int(frames_in_stream[ooo_index-1]) and int(frames_in_stream[ooo_index-1])-1 == int(frames_in_stream[ooo_index-2]) and int(frames_in_stream[ooo_index-2])-1 == int(frames_in_stream[ooo_index-3])):
            print ('Expected error! The frames to be rearranged are not sequential around frame '+ frame,end='\r\n')
            rearrange_expected_error_count += 1
            continue
            
        #make sure that the order of the stream matches the pattern being looked for
        if not (frames_in_stream[ooo_index-2] in lost_frames and frames_in_stream[ooo_index-4] not in lost_frames and frames_in_stream[ooo_index+2] not in ooo_frames and frames_in_stream[ooo_index+2] not in retr_frames):
            print ('Expected error! Our TCP stream appears to be intermingled with another one around frame '+ frame,end='\r\n')
            rearrange_expected_error_count += 1
            continue
            
        #now do the actual rearranging
        
        #query useful data for the 3 frames that need to be rearranged plus the two encompassing frames
        return_string = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'frame.number=='+frames_in_stream[ooo_index-3]+' or frame.number=='+frames_in_stream[ooo_index-2]+' or frame.number=='+frames_in_stream[ooo_index-1]+' or frame.number=='+frames_in_stream[ooo_index]+' or frame.number=='+frames_in_stream[ooo_index+1], '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.flags', '-e', 'ip.src', '-e', 'tcp.ack', '-e', 'tcp.seq', '-e', 'tcp.len'])
        return_string = return_string.rstrip()
        frames = return_string.split('\n')
        five_frames = []
        for frame in frames:
            frame_number, tcp_flags, ip_src, tcp_ack, tcp_seq, tcp_len = frame.split('\t')
            #make sure we put 0 where there is an empty string
            five_frames.append({'frame_number':frame_number, 'flag': 1 if tcp_flags in special_flags else 0, 'ip.src':ip_src, 'tcp.ack':int(tcp_ack) if tcp_ack != '' else 0, 'tcp.seq':int(tcp_seq) if tcp_seq != '' else 0, 'tcp.len':int(tcp_len) if tcp_len != '' else 0})
        
        #work from the highest frame to the lowest one
        nextframe = five_frames[-1]
        found_frames = []
        three_frames = five_frames[1:-1]
        #we only rearrange 3 frames out of 5
        rearrange_failure = False
        expected_failure = False
        while len(found_frames) < 3:
            success = False
            for index2,frame in enumerate(three_frames):
                if frame['ip.src'] == nextframe['ip.src']:
                    if frame['tcp.ack'] == nextframe['tcp.ack'] and frame['tcp.seq']+frame['tcp.len'] == nextframe['tcp.seq']:
                        nextframe = three_frames.pop(index2)
                        found_frames.insert(0, nextframe)
                        success = True
                        break
                else:
                    if frame['tcp.ack'] == nextframe['tcp.seq'] and frame['tcp.seq']+frame['tcp.len']+frame['flag'] == nextframe['tcp.ack']:
                        nextframe = three_frames.pop(index2)
                        found_frames.insert(0, nextframe)                
                        success = True
                        break
            if success == False:
                retval = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'frame.number=='+five_frames[-1]['frame_number'], '-T', 'fields', '-e', 'tcp.analysis.duplicate_ack'])
                retval = retval.strip()
                if retval == '1':
                    #expected behaviour, don't treat as an error
                    #TODO:in theory we should just skip this dup_ack and start checking against the higher frame
                    #for now, just skip this frame and continue onto the next one
                    expected_failure = True
                    break
                else:
                    print ("Couldn't find the previous frame while rearranging",end='\r\n')
                    print ('Failed to rearrange around frame '+ five_frames[1]['frame_number'],end='\r\n')
                    rearrange_failure = True
                    break
        if rearrange_failure == True:
            rearrange_unknown_error_count += 1
            continue
        elif expected_failure == True:
            rearrange_expected_error_count += 1
            continue
                       
        #make sure that frame 1 of 5 has correct tcp seq/ack
        frame = five_frames[0]
        nextframe = found_frames[0]
        #this is a one-liner for what was done above in a while loop
        if not (frame['ip.src'] == nextframe['ip.src'] and frame['tcp.ack'] == nextframe['tcp.ack'] and frame['tcp.seq']+frame['tcp.len'] == nextframe['tcp.seq']) and not (frame['ip.src'] != nextframe['ip.src'] and frame['tcp.ack'] == nextframe['tcp.seq'] and frame['tcp.seq']+frame['tcp.len']+frame['flag'] == nextframe['tcp.ack']):
            retval = subprocess.check_output([tshark_exepath, '-r', capture_file, '-Y', 'frame.number=='+frame['frame_number'], '-T', 'fields', '-e', 'tcp.analysis.duplicate_ack'])
            retval = retval.strip()
            if retval == '1':
                #expected behaviour, don't treat as an error
                #TODO:in theory we should just skip dup_ack and check against the preceding frame
                rearrange_expected_error_count += 1
                continue 
            else:
                print ('Wrong TCP SEQ/ACK between frames 0/5 and 1/5',end='\r\n')
                print ('Failed to rearrange around frame '+ five_frames[1]['frame_number'],end='\r\n')
                rearrange_failure_count += 1
                continue
        
        rearrange_success_count += 1
   
        
        #save all out-of-order frames for future merging (the name of file corresponds to frame number)
        for frame in found_frames:
            subprocess.call([editcap_exepath, new_capture_file, os.path.join(capturedir,frame['frame_number']), '-r', frame['frame_number']], stdout=open(os.devnull,'w'))
            
        #split into 2 large parts omitting the ooo frames
        subprocess.call([editcap_exepath, new_capture_file, os.path.join(capturedir,'part1'), '-r', '0-'+five_frames[0]['frame_number']], stdout=open(os.devnull,'w'))
        subprocess.call([editcap_exepath, new_capture_file, os.path.join(capturedir,'part2'), '-r', five_frames[4]['frame_number']+'-'+last_frame_no], stdout=open(os.devnull,'w'))
        #merge in the correct order
        subprocess.call([mergecap_exepath, '-a', '-w', new_capture_file, os.path.join(capturedir,'part1'), os.path.join(capturedir,found_frames[0]['frame_number']), os.path.join(capturedir,found_frames[1]['frame_number']), os.path.join(capturedir,found_frames[2]['frame_number']), os.path.join(capturedir,'part2')], stdout=open(os.devnull,'w'))
        for frame in found_frames:
            os.remove(os.path.join(capturedir, frame['frame_number']))                
        #for debugging
        new_last_frame_no = subprocess.check_output([capinfos_exepath,'-c', '-M', new_capture_file]).strip().split()[-1]
        if int(new_last_frame_no) != int(last_frame_no):
            raise ('Frame number mismatch') 
        os.remove(os.path.join(capturedir,'part1'))
        os.remove(os.path.join(capturedir,'part2'))
    
    print ('Out of total ' + str(len(ooo_frames)) + ' out-of-order frames',end='\r\n')
    print (str(rearrange_expected_error_count + rearrange_unknown_error_count + rearrange_success_count) + ' matched the pattern: ',end='\r\n')
    print ('Failed to rearrange due to unknown error ' + str(rearrange_unknown_error_count) + '<<-- if this is not 0, please report, this script needs more polish',end='\r\n')
    print ('Failed to rearrange due to expected error ' + str(rearrange_expected_error_count),end='\r\n')
    print ('Total times succeeded to rearrange ' + str(rearrange_success_count),end='\r\n')
    return new_capture_file
    
def buyer_create_directories():
    if os.path.isdir(os.path.join(installdir, 'bitcoind')) == False:
        os.makedirs(os.path.join(installdir, 'bitcoind'))
    if os.path.isdir(os.path.join(installdir, 'bitcoind', 'datadir_buyer')) == False:
        os.makedirs(os.path.join(installdir, 'bitcoind', 'datadir_buyer'))
            
    if os.path.isdir(os.path.join(installdir, 'ssh')) == False:
        os.makedirs(os.path.join(installdir, 'ssh'))
        
    if os.path.isdir(os.path.join(installdir, 'dumpcap')) == False:
        os.makedirs(os.path.join(installdir, 'dumpcap'))
        
    if os.path.isdir(os.path.join(installdir, 'firefox')) == False:
        os.makedirs(os.path.join(installdir, 'firefox'))
    
    if os.path.isdir(os.path.join(installdir, 'htmldir')) == False:
        os.makedirs(os.path.join(installdir, 'htmldir'))
            
    
def seller_create_directories():
    if os.path.isdir(os.path.join(installdir, 'bitcoind')) == False:
        os.makedirs(os.path.join(installdir, 'bitcoind'))
    if os.path.isdir(os.path.join(installdir, 'bitcoind', 'datadir_seller')) == False:
        os.makedirs(os.path.join(installdir, 'bitcoind', 'datadir_seller'))
            
    if os.path.isdir(os.path.join(installdir, 'ssh')) == False:
        os.makedirs(os.path.join(installdir, 'ssh'))
        
    if os.path.isdir(os.path.join(installdir, 'dumpcap')) == False:
        os.makedirs(os.path.join(installdir, 'dumpcap'))

#Establish a channel via which escrow can send requests to buyer   
def buyer_establish_e2b_channel():
    print ('Establishing ssh channel from escrow to buyer',end='\r\n')
    try:
        sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_ssh_host, '-p', str(escrow_ssh_port), '-R', str(escrow_e2b_port)+':localhost:'+str(buyer_http_port)], stdout=open(os.path.join(installdir, 'ssh','ssh_e2b_buyer.stdout'),'w'),  stderr=open(os.path.join(installdir, 'ssh','ssh_e2b_buyer.stderr'),'w'))
    except:
        print ('Exception connecting to sshd',end='\r\n')
        cleanup_and_exit()
    pids['sshpass'] = sshpass_proc.pid
    
def seller_establish_e2s_channel():
    print ('Establishing ssh channel from escrow to seller',end='\r\n')
    try:
        sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_ssh_host, '-p', str(escrow_ssh_port), '-R', str(escrow_e2s_port)+':localhost:'+str(seller_http_port)], stdout=open(os.path.join(installdir, 'ssh','ssh_e2s_seller.stdout'),'w'),  stderr=open(os.path.join(installdir, 'ssh','ssh_e2s_seller.stderr'),'w'))
    except:
        print ('Exception connecting to sshd',end='\r\n')
        cleanup_and_exit()
    pids['sshpass'] = sshpass_proc.pid
    
#get hashes of all SSL segments           
def seller_check_hashes_present(buyer_hashes):
    seller_hashes = []
    try:
        sslappdata_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'ssl,app_data' '-T', 'fields', '-e', 'ssl,app_data'])
    except Exception,e:
        print ('Error starting tshark', e,end='\r\n')
        cleanup_and_exit()
    sslappdata_str = sslappdata_str.rstrip()
    sslappdata = sslappdata_str.split(',')
    print ('Generatin hashes of '+str(len(sslappdata))+' SSL frames', end='\r\n')
    for segment in sslappdata:
        segment.replace(':',' ')
        seller_hashes.append(hashlib.md5(bytearray.fromhex(segment)).hexdigest())
    for buyer_hash in buyer_hashes:
        if seller_hashes.count(buyer_hash) != 1:            
            print ('Seller could not find all buyer hashes',end='\r\n')
            return False
    print ('Seller successfully found all buyer hashes',end='\r\n')
    return True

def send_http_request(request='head', host, port, data):
    destination_contacted = False
    if request == 'head':
        requests_cmd = requests.head
    elif request == 'get':
        requests_cmd = requests.get
    else:
        print ("Invalid request argument",end='\r\n')
        cleanup_and_exit()  
    for i in range(10):
        try:
            response = requests_cmd(host+":"+str(port)+data)
            destination_contacted = True
            break
        except Exception,e:
            print ('Sleeping ' + str(i+1) + ' sec while trying to connect',end='\r\n')
            time.sleep(1)
    if not destination_contacted:
        print ("Can't connect to the destination",end='\r\n')
        cleanup_and_exit()  
    elif message.status_code != 200:
        print ("Destination returned invalid HTTP response",end='\r\n')
        cleanup_and_exit()
    return response if request == 'head' else response.headers['value']
        
def escrow_start_dumpcap():
    print ('Starting dumpcap in capture mode',end='\r\n')
    try:
        #todo: don't assume that 'lo' is the loopback, query it
        #listen on the port which bridges buyer's and seller's ssh. filter out all the rest of loopback traffic
        dumpcap_proc = subprocess.Popen([dumpcap_exepath, '-i', 'lo', '-B', '10', '-f', 'tcp port '+str(escrow_dumpcap_port), '-w', escrow_dumpcap_capture_file ], stdout=open(os.path.join(installdir, 'dumpcap', "dumpcap_escrow.stdout"),'w'), stderr=open(os.path.join(installdir, 'dumpcap', "dumpcap_escrow.stderr"),'w'))
    except Exception,e:
        print ('Exception starting dumpcap',e,end='\r\n')
        cleanup_and_exit()
    pids['dumpcap'] = dumpcap_proc.pid

def buyer_prepare_tcpstream_and_sslkeylog(tcpstream, sslhashes):
    try:
        subprocess.call([tshark_exepath, '-r', buyer_dumpcap_capture_file, '-Y', 'tcp.stream==' + tcpstream, '-w', os.path.join(installdir, 'temp','buyer_stream.pcap')])
    except Exception, e:
        print ('Error starting tshark', e,end='\r\n')
        cleanup_and_exit()
    #TODO: fill up all irrelevant TCP frames with random data
        
        
    #Try every single line until we get some decryption results
    fd = open(sslkeylogfile,'r')
    sslkeylog = fd.read()
    fd.close()
    keys = sslkeylog.split('\n')
    keys.reverse()
    single_key_file = os.path.join(installdir, 'temp', 'buyer_single_key')
    decrypted_hashes = []
    found_key = False
    for key in keys:
        if key.startswith('CLIENT_RANDOM '):
            mastersecret = key[len('CLIENT_RANDOM '):]
            fd = open(single_key_file, 'w')
            fd.write(mastersecret)
            fd.close()
            output = subprocess.check_output([tshark_exepath, '-r', os.path.join(installdir, 'temp','buyer_stream.pcap'), '-Y', 'ssl.segment.data', '-o', 'ssl.keylog_file: '+ single_key_file])
            #if the key didn't match, the output will be blank
            if output != '':
                found_key = True
                output = output.rstrip()
                output = output.replace(',','\n')
                segments = output.split('\n')
                for segment in segments:
                    segment = segment.replace(':',' ')
                    if segment == ' ':
                        print ('empty frame hex. Please investigate',end='\r\n')
                        cleanup_and_exit()
                    decrypted_hashes.append(hashlib.md5(bytearray.fromhex(segment)).hexdigest())
                break
    if not found_key:
        print ('Failed to find a key. Please investigate',end='\r\n')
        cleanup_and_exit()
        
    #sanity check
    if not set(sslhashes).issubset(set(decrypted_hashes)):
        print ('Provided hashes are not a subset of decrypted hashes. Please investigate',end='\r\n')
        cleanup_and_exit()
        
    
def cleanup_and_exit():
    print ('Cleaning up and exitting',end='\r\n')
    global pids
    trace = traceback.format_exc().split('\n')
    for line in trace:
        print (line,end='\r\n')
    for pid in [item[1] for item in pids.items()]:
        os.kill(pid, signal.SIGTERM)
    #don't quit straight away, so we could examine the stack in debugger
    #raise Exception('Exception')
    os._exit(1) # <--- a hackish way to kill process from a thread
    #os.kill(os.getpid(), signal.SIGINT) <-- didn't work
    #sys.exit(1)
    #sys.exit doesn't work if this function is invoked from a thread - only the thread stops, not the main process

def sighandler(signal, frame):
    cleanup_and_exit()

pids = dict()
ppid = 0
if __name__ == "__main__":
    print ('Installdir and current file:', installdir, currfile,end='\r\n')
    if len(sys.argv) < 2:
        print ('Please provide one of the arguments: "buyer","seller",or "escrow" and optional "skip"',end='\r\n')
        exit()
    role = sys.argv[1]
    if role != 'buyer' and role != 'seller' and role != 'escrow':
        print ('Unknown argument. Please provide one of the arguments: "buyer" or "seller" and optionall "skip"',end='\r\n')
        exit()
    skip_capture = False
    if len(sys.argv) > 2 and sys.argv[2] == 'skip':
        skip_capture = True
        print ('Skipping the capture phase and going straight to finding hashes of HTML files',end='\r\n')
    #making this process a leader of the process group
    print ('----------------------------MY PID IS ', os.getpid(), '----------------------------',end='\r\n')
    print ('Terminate me with "kill '+str(os.getpid())+'"',end='\r\n')
    signal.signal(signal.SIGTERM, sighandler)
    
    if role=='buyer':
        #global pids
        buyer_create_directories()
        buyer_start_bitcoind_stunnel_sshpass_dumpcap(skip_capture)
        
        if skip_capture == False:
            buyer_get_and_verify_seller_cert()
            os.kill(pids['bitcoind'], signal.SIGTERM)
            pids.pop('bitcoind')
            os.kill(pids['stunnel'], signal.SIGTERM)
            pids.pop('stunnel')
            #let stunnel terminate properly before restarting it
            time.sleep(2)
        buyer_start_stunnel_with_certificate(skip_capture)
        if skip_capture == False:
            thread = threading.Thread(target= buyer_start_minihttp_thread)
            thread.start()
            start_firefox()
            #wait for minihttp server shutdown. The shutdown means that user has finished the SSL session
            while thread.isAlive():
                time.sleep(2)
            print ("User has finished the SSL session",end='\r\n')
            #todo: inform the seller at this stage that we are finished with the SSL session
            print ("Terminating dumpcap",end='\r\n')
            os.kill(pids['dumpcap'], signal.SIGTERM)
            pids.pop('dumpcap')
        
        buyer_establish_e2b_channel()
        html_frame = buyer_find_htmlframe(ref_string)
        if html_frame == -1:
            send_http_request(escrow_http_host,escrow_http_port,'/buyer_html_not_found')
        else:
            tcpstream, sslhashes = buyer_get_sslhashes(buyer_dumpcap_capture_file, html_frame)
            buyer_prepare_tcpstream_and_sslkeylog(tcpstream, sslhashes)
            buyer_send_sslhashes(sslhashes)
        
        if skip_capture == False:
            print ("Terminating sshpass and stunnel",end='\r\n')
            os.kill(pids['sshpass'], signal.SIGTERM)
            os.kill(pids['stunnel'], signal.SIGTERM)
            pids.pop('sshpass')
            pids.pop('stunnel')
        
    elif role == 'seller':
        #global pids
        seller_create_directories()
        seller_start_bitcoind_stunnel_sshpass_dumpcap_squid(skip_capture)
        seller_establish_e2s_channel()
        
        #minihttp is responsible for sending the certificate and receiving ssl hashes
        retval = []
        thread = ThreadWithRetval(target= seller_start_minihttp_thread, args=(retval,))
        thread.start()
        while True:
            thread.join(2)
            if not thread.isAlive():
                break
        #sslhashes have been received, minihttp server stopped. sslhahses are returned through thread's retval
        
        #stop tshark,ssh,stunnel,squid (if active) and process hashes
        print ("Terminating bitcoind, dumpcap, squid, sshpass, and stunnel",end='\r\n')
        try:
            for pid in [item for item in pids.items() if item[0] in ['bitcoind','dumpcap','squid3','sshpass','dumpcap']]:
                os.kill(pid[1], signal.SIGTERM)
                pids.pop(pid[0])
        except Exception,e:
            print ('Exception while processing', pid[0], pid[1], e,end='\r\n')
            cleanup_and_exit()
        #print ('Thread returned:', retval,end='\r\n')
            
        hashes = [hash for hash in retval[0].split(';') if len(hash)>0]
        send_logs_to_escrow(hashes)
        
    elif role == 'escrow':
        escrow_start_dumpcap()
        retval = []
        thread = ThreadWithRetval(target= escrow_start_minihttp_thread, args=(retval,))
        thread.start()
        while True:
            thread.join(2)
            if not thread.isAlive():
                break