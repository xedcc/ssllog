#!/usr/bin/env python
from __future__ import print_function

import base64
import BaseHTTPServer
import binascii
import codecs
import ctypes
import hashlib
from hashlib import sha1
import hmac
import multiprocessing
import os
import platform
import Queue
import random
import re
import shutil
import signal
import SimpleHTTPServer
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
import urllib2
from xml.dom import minidom
import zipfile

TESTING = False
#ALPHA_TESTING means the users have to enter accno and sum themselves via FF addon
#whereas in a production environment these values will be sourced from the contract between buyer and seller
ALPHA_TESTING = True

installdir = os.path.dirname(os.path.realpath(__file__))
platform = platform.system()
if platform == 'Windows':
    OS = 'win'
    #rsa module for ssh2 to putty's ppk format conversion
    import rsa
elif platform == 'Linux':OS = 'linux'
    
datadir = os.path.join(installdir, "data")
logdir = os.path.join(datadir, 'stcppipe_buyerlog')
sslkeylog = os.path.join(datadir, 'sslkeylog')
sslkey = os.path.join(datadir, 'sslkey')
ssh_logfile = os.path.join(datadir, 'ssh.log')
alphatest_key = os.path.join(installdir, 'alphatest.txt')
alphatest_ppk = os.path.join(installdir, 'alphatest.ppk')
#on older tshark versions on Linux this option can be "-R"
tshark_display_filter_option = "-Y"

if OS=='win':
    stcppipe_exepath = os.path.join(datadir,'stcppipe', 'stcppipe.exe')
    tshark_exepath = os.path.join(datadir,'wireshark', 'tshark.exe')
    mergecap_exepath = os.path.join(datadir,'wireshark', 'mergecap.exe')
    plink_exepath = os.path.join(datadir, 'plink.exe')    
if OS=='linux':
    stcppipe_exepath = os.path.join(datadir,'stcppipe', 'stcppipe')
    tshark_exepath = 'tshark'
    mergecap_exepath = 'mergecap'
    #detect an older tshark version which will throw an exception when -Y is used
    try:
        subprocess.check_output([tshark_exepath, '-r', os.path.join(datadir,'tsharktest'), '-Y', "tcp"])
    except:
        tshark_display_filter_option = '-R'
    
firefox_exepath = 'firefox'
ssh_exepath = 'ssh'

#local port for ssh's port forwarding. Will be randomly chosen upon starting the tunnel
random_ssh_port = 0
#random TCP port on which firefox extension communicates with python backend
FF_to_backend_port = 0
#random port which FF uses as proxy port. Local stcppipe listens on this port and forwards traffic to random_ssh_port
FF_proxy_port = 0
#ID of a public snapshot on Amazon EC2. How this snapshot was created is outlined in oracle/INSTALL
oracle_snapID = ['snap-81a54469', 'snap-ed30cdfc']
amis = ['ami-35258228','ami-8e987ef9']

accno = None
sum_ = None
#subprocess Objects
stcppipe_proc = ssh_proc = None
html_hash = None
#the remote port on oracle for ssh port forwarding. By default it is 2134 and gets re-assigned on first connection to oracle
assigned_port = None
username = "ubuntu"
is_ff_started = False
is_ssh_session_active = False
preferred_escrow = None

#a thread which returns a value. This is achieved by passing self as the first argument to a called function
#the calling function can then set self.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,))
    retval = ''

class StoppableHttpServer (BaseHTTPServer.HTTPServer):
    """http server that reacts to self.stop flag"""
    retval = ''
    def serve_forever (self):
        """Handle one request at a time until stopped. Optionally return a value"""
        self.stop = False
        while not self.stop:
                self.handle_request()
        return self.retval;
    

#Receive HTTP HEAD requests from FF extension. This is how the extension communicates with python backend.
class buyer_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"      
    
    def do_HEAD(self):
        global ssh_proc
        global stcppipe_proc
        global is_ssh_session_active        
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/page_marked?accno=12435678&sum=1234.56&time=1383389835"        
        if self.path.startswith('/page_marked'):
            #the buyer has selected a page which he wants the escrow to see
            if ALPHA_TESTING:
                params = []
                for param_str in self.path.split('?')[1].split('&'):
                    paralist = param_str.split('=')
                    params.append({paralist[0]:paralist[1]})
                global accno
                global sum_
                accno = params[0]['accno']
                sum_ = params[1]['sum']
                click_time = params[2]['time']
            result = find_page(accno, sum_, click_time)
            if result[0] != 'success':
                if is_ssh_session_active:
                    os.kill(stcppipe_proc.pid, signal.SIGTERM)
                    ssh_proc.stdin.write("exit\n")
                    ssh_proc.stdin.flush()
                    is_ssh_session_active = False                            
                print ('sending failure. Reason: '+result[0] ,end='\r\n')
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "failure")
                self.end_headers()
                return
            filename = result[1]
            click_time = result[2]
            #else
            retval = extract_ssl_key(filename, click_time)
            if retval != 'success':
                if is_ssh_session_active: 
                    os.kill(stcppipe_proc.pid, signal.SIGTERM)
                    ssh_proc.stdin.write("exit\n")
                    ssh_proc.stdin.flush()
                    is_ssh_session_active = False                                
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "failure")
                self.end_headers()
                return
            if retval == 'success':
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "success")
                self.end_headers()
                return            

        if self.path.startswith('/check_oracle'):
            base64str = self.path.split('?')[1]
            arg_str = base64.b64decode(base64str)
            args = arg_str.split()
            if not TESTING:
                retval = check_oracle_urls(*args)
            else:
                retval = "success"
            print ('Sending back: '+retval)
            self.send_response(200)
            self.send_header("response", "check_oracle")
            self.send_header("value", retval)
            self.end_headers()
            return
            
        if self.path.startswith('/start_tunnel'):
            arg_str = self.path.split('?')[1]
            args = arg_str.split(";")
            if ALPHA_TESTING:
                key_name = "alphatest.txt"
            global assigned_port
            assigned_port = args[1]
            retval = start_tunnel(key_name, args[0])
            print ('Sending back: '+retval + assigned_port)
            if retval == 'reconnect':
                self.send_response(200)
                self.send_header("response", "start_tunnel")
                #assigned_port now contains the new port which sshd wants us to reconnect to
                self.send_header("value", "reconnect;"+assigned_port)
                self.end_headers()                
            if retval != 'success':
                print ('Error while setting up a tunnel: '+retval, end='\r\n')
            self.send_response(200)
            self.send_header("response", "start_tunnel")
            self.send_header("value", retval)
            self.end_headers()
            return
        
            #ALPHA only, request the tarball from oracle; check whether escrow would also decrypt HTML            
        if self.path.startswith('/check_escrowtrace'):
            if is_ssh_session_active:
                #stcppipe needs to quit now, otherwise if FF sends further requests, it will confuse httpd on oracle
                #which is standing by to serve the tarball of escrow trace
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                #sshd will exit as soon as it sends the tarball, so no need for ssh to send "exit" signal
                is_ssh_session_active = False            
            result = decrypt_escrowtrace()
            if result == "success":    
                self.send_response(200)
                self.send_header("response", "check_escrowtrace")
                self.send_header("value", "success")
                print ('sending success',end='\r\n')
                self.end_headers()
                return
            else:
                self.send_response(200)
                self.send_header("response", "check_escrowtrace")
                self.send_header("value", result)
                print ('sending failure',end='\r\n')
                self.end_headers()
                return     
        
        if self.path.startswith('/terminate'):
            if is_ssh_session_active: 
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                ssh_proc.stdin.write("exit\n")
                ssh_proc.stdin.flush()
                is_ssh_session_active = False              
            self.send_response(200)
            self.send_header("response", "terminate")
            self.send_header("value", "success")
            self.end_headers()
            time.sleep(2)
            return      
            
        if self.path.startswith('/started'):
            global is_ff_started
            is_ff_started = True
            self.send_response(200)
            self.send_header("response", "started")
            self.send_header("value", "success")
            self.send_header("preferred_escrow", preferred_escrow)
            self.end_headers()
            return                
    
#ALPHA only - fetch the tarball from the oracle, which in production env. the escrow would fetch
#make sure the escrow would find the HTML page in the trace
def decrypt_escrowtrace():    
    escrowtracedir = os.path.join(datadir, "escrowtrace")
    ssh_proc.stdin.write('sslkey \n')
    #give oracle some time to create the tarball and launch an httpd which waits to serve the tarball
    time.sleep(5)
    #send request to ssh's local forwarding port which gets forwarded to oracle's remote port
    try:
        oracle_url = urllib2.urlopen("http://127.0.0.1:"+str(random_ssh_port)+"/the/name/doesnt/matter/because/the/oracle/will/serve/the/correct/file/anyway", timeout=30)
    except:
        ssh_proc.stdin.write('exit failure\n')    
        return "Failed to fetch tarball from oracle"
    print ("Fetched escrow's data. Analyzing...",end='\r\n')
    data = oracle_url.read()
    tarball = open(os.path.join(datadir, "escrowtrace.tar"), 'wb')
    tarball.write(data)
    tarball.close()
    if os.path.isdir(escrowtracedir): shutil.rmtree(escrowtracedir)
    os.mkdir(escrowtracedir)
    tar_object = tarfile.open(os.path.join(datadir, "escrowtrace.tar"))
    tar_object.extractall(escrowtracedir)
    tar_object.close()
      
    filelist = os.listdir(escrowtracedir)
    mergecap_args = [mergecap_exepath, '-w', 'merged'] + filelist
    #it was observed that mergecap may return before the output file was written entirely. We must give the OS some time to flush everything to disk:
    time.sleep(1)
    try:
        subprocess.call(mergecap_args, cwd=escrowtracedir)
    except:
        ssh_proc.stdin.write('exit failure\n')
        print ('Mergecap error',  end='\r\n')
        return 'Mergecap error'
    #hard-coded port 3128 is squid's port on oracle
    output = subprocess.check_output([tshark_exepath, '-r', os.path.join(escrowtracedir, 'merged'), tshark_display_filter_option, 'ssl and http.content_type contains html', '-C', 'paysty', '-o', 'ssl.keylog_file:'+ sslkey, '-o',  'http.ssl.port:3128', '-x'])
    if output == '': 
        ssh_proc.stdin.write('exit failure\n')    
        return "Failed to find HTML in escrowtrace"
    
    #output may contain multiple frames with HTML, we examine them one-by-one
    separator = re.compile('Frame ' + re.escape('(') + '[0-9]{2,7} bytes' + re.escape(')') + ':')
    #ignore the first split element which is always an empty string
    frames = re.split(separator, output)[1:]   
    
    was_match_found = False
    for frame in frames:    
        html = get_html_from_asciidump(frame)
        if html == -1:
            ssh_proc.stdin.write('exit failure\n')            
            return "Failed to find HTML in ascii dump"
        if html_hash == hashlib.md5(html).hexdigest() :
            was_match_found = True
            break
    if not was_match_found:
        ssh_proc.stdin.write('exit failure\n')            
        return "Escrowtrace's HTML doesn't match ours"
    
    ssh_proc.stdin.write('exit success\n')    
    return "success"
    
    

#look at tshark's ascii dump (option '-x') to better understand the parsing taking place
def get_html_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        return -1

    #We are interested in
    # "Uncompressed entity body" for compressed HTML (both chunked and not chunked). If not present, then
    # "De-chunked entity body" for no-compression, chunked HTML. If not present, then
    # "Reassembled SSL" for no-compression no-chunks HTML in multiple SSL segments, If not present, then
    # "Decrypted SSL data" for no-compression no-chunks HTML in a single SSL segment.
    
    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #if first 4 chars are not hexdigits, we reached the end of the section
                break
        return binary_html
    
    #else      
    dechunked_pos = ascii_dump.rfind('De-chunked entity body')
    if dechunked_pos != -1:
        for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                break
        return binary_html
            
    #else
    reassembled_pos = ascii_dump.rfind('Reassembled SSL')
    if reassembled_pos != -1:
        for line in ascii_dump[reassembled_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

    #else
    decrypted_pos = ascii_dump.rfind('Decrypted SSL data')
    if decrypted_pos != -1:       
        for line in ascii_dump[decrypted_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

#Examine the local trace of a banking session and find an HTML statement page containing account number and sum of payment 
#click_time is the time when user click the button to mark the page whereupon Firefox cleared SSL cache and refreshed the page
#We only search for HTML in packets AFTER click_time
def find_page(accno, amount, click_time):
    global html_hash
    
    #if chars were not ascii, FF extension sent it to us in url-encoded unicode
    accno = urllib2.unquote(accno).strip()
    amount = urllib2.unquote(amount).strip()
    months = {"1":"Jan", "2":"Feb","3":"Mar","4":"Apr","5":"May","6":"Jun","7":"Jul","8":"Aug","9":"Sep","10":"Oct","11":"Nov","12":"Dec"}
    month = time.strftime("%m", time.localtime(int(click_time)))
    click_time_formatted = time.strftime( months[month]+" %d, %Y %H:%M:%S.000", time.localtime(int(click_time)))
    
    #try to find the HTML twice, becauce sometimes FF reports that page finished loading when in fact it hasn't
    for i in range(2):
        print ("Attempt no:"+ str(i+1) +" to find HTML in our trace")
        #give some time for the page to finish loading completely if no HTML was found on the first iteration
        time.sleep(i*15)
        if os.path.isfile(os.path.join(logdir, 'merged')): os.remove(os.path.join(logdir, 'merged'))
        filelist = os.listdir(logdir)
        mergecap_args = [mergecap_exepath, '-w', 'merged'] + filelist
        subprocess.call(mergecap_args, cwd=logdir)
        time.sleep(1)
        
        #find all HTML pages after click_time
        output = subprocess.check_output([tshark_exepath, '-r', os.path.join(logdir, 'merged'), tshark_display_filter_option, 'ssl and http.content_type contains html and http.response.code == 200 and frame.time > "' + click_time_formatted + '"', '-C', 'paysty', '-o', 'ssl.keylog_file:'+ sslkeylog, '-o', 'http.ssl.port:'+str(random_ssh_port), '-x'])
        
        #we need source and desftination port so that we could later determine which acp file the stream belongs to
        ports = subprocess.check_output([tshark_exepath, '-r', os.path.join(logdir, 'merged'), tshark_display_filter_option, 'ssl and http.content_type contains html and http.response.code == 200 and frame.time > "' + click_time_formatted + '"', '-C', 'paysty','-o' , 'ssl.keylog_file:'+ sslkeylog, '-o', 'http.ssl.port:'+str(random_ssh_port), '-T', 'fields', '-e', 'tcp.srcport', '-e', 'tcp.dstport'])
        
        #output may contain multiple frames with HTML, we examine them one-by-one        
        separator = re.compile('Frame ' + re.escape('(') + '[0-9]{2,7} bytes' + re.escape(')') + ':')
        #ignore the first split element which is always an empty string
        frames = re.split(separator, output)[1:]
        for index,frame in enumerate(frames):
            html = get_html_from_asciidump(frame)
            if html == -1:
                print ('Error processing ascii dump in file:'+filename, end='\r\n')
                return ['Error processing ascii dump in file:'+filename]
            if html.find(accno) == -1:
                print ('Accno not found in HTML', end='\r\n')
                continue
            if html.find(amount) == -1:
                print ('Amount not found in HTML', end='\r\n')
                continue
            #ALPHA only: save the hash to later compare to the hash of HTML found in escrow's trace
            html_hash = hashlib.md5(html).hexdigest()
            #building an acp filename
            port_list = ports.split()
            sport = port_list[2*i]
            dport = port_list[2*i+1]
            filename = '127.0.0.1.'+dport+'-127.0.0.1.'+sport+'_1.acp'
            return ['success', filename, click_time_formatted]
    return ['Data not found in HTML']

#get all those sslkeylog entries which were generated AFTER the user pressed the button to mark a page for escrow
#The resulting file will be sent to escrow 
#NB: The escrow will be able to ONLY decrypt pages which were displayed AFTER the user clicked the button
def extract_ssl_key(filename, click_time):
    sslkey_fd = open(sslkeylog, 'r')
    keys_data = sslkey_fd.read()
    sslkey_fd.close()
    #first copy will be reverse to speed up searching
    keys = keys_data.rstrip().split('\n')
    keys.reverse()    
    #second copy will remain untouched
    keys_orig = keys_data.rstrip().split('\n')
    
    print ('SSL keys total in sslkeylogfile :' + str(len(keys)), end='\r\n')
    is_key_found = False
    for index,key in enumerate(keys):
        print ('Processing key number:' + str(index+1), end='\r\n')
        #commented out because tshark 1.6.7 looks for lines starting with RSA. TODO: investigate why.
        #if not key.startswith('CLIENT_RANDOM'): continue
        tmpkey_fd = open(sslkey, 'w')
        tmpkey_fd.write(key+'\n')
        tmpkey_fd.flush()
        tmpkey_fd.close()
        #check if this key can decrypt the HTML
        output = subprocess.check_output([tshark_exepath, '-r', os.path.join(logdir, filename), tshark_display_filter_option, 'ssl and http.content_type contains html and frame.time > "' + click_time + '"', '-o', 'ssl.keylog_file:'+ sslkey, '-C', 'paysty', '-o', 'http.ssl.port:'+str(random_ssh_port)])
        if output == '': continue
        #else
        is_key_found = True
        break
    if not is_key_found:
        print ('FAILURE could not find ssl key', end='\r\n')
        return 'FAILURE could not find ssl key'        
        
    master_secret = key.split()[2]
    #find index of the first line containing the master secret (multiple lines may contain the same master secret but different CLIENT_RANDOM)
    #This line was generated AFTER the user clicked the button
    #It is safe to give escrow all the lines which follow
    first_index = min(i for i,line in enumerate(keys_orig) if master_secret in line)
    tmpkey_fd = open(sslkey, 'w')
    for key in keys_orig[first_index:]:            
        tmpkey_fd.write(key+'\n')
        tmpkey_fd.flush()                
    tmpkey_fd.close()
              
    print ('SUCCESS ssl key found', end='\r\n')
    return 'success'
        
       
#use miniHTTP server to receive commands from Firefox addon and respond to them
def buyer_start_minihttp_thread(parentthread):
    global FF_to_backend_port
    print ('Starting mini http server to communicate with Firefox plugin',end='\r\n')
    try:
        httpd = StoppableHttpServer(('127.0.0.1', FF_to_backend_port), buyer_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        exit(1)
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    retval = httpd.serve_forever()


def start_firefox():    
    if not os.path.isdir(os.path.join(datadir, 'firefox')): os.mkdir(os.path.join(datadir, 'firefox'))
    if not os.path.isfile(os.path.join(datadir, 'firefox', 'firefox.stdout')): open(os.path.join(datadir, 'firefox', 'firefox.stdout'), 'w').close()
    if not os.path.isfile(os.path.join(datadir, 'firefox', 'firefox.stderr')): open(os.path.join(datadir, 'firefox', 'firefox.stderr'), 'w').close()    
    if not os.path.isfile(os.path.join(datadir, 'FF-profile', 'extensions.ini')):
    #FF rewrites extensions.ini on first run, so we allow FF to create it, then we kill FF, rewrite the file and start FF again
        try:
            ff_proc = subprocess.Popen([firefox_exepath,'-no-remote', '-profile', os.path.join(datadir, 'FF-profile')], stdout=open(os.path.join(datadir, 'firefox', "firefox.stdout"),'w'), stderr=open(os.path.join(datadir, 'firefox', "firefox.stderr"), 'w'))
        except Exception,e:
            print ("Error starting Firefox", e,end='\r\n')
            return ["Error starting Firefox"]
        
        while 1:
            time.sleep(0.5)
            if os.path.isfile(os.path.join(datadir, 'FF-profile', 'extensions.ini')):
                ff_proc.kill()
                break
            
        try:
            #enable extension                            
            with codecs.open (os.path.join(datadir, 'FF-profile', 'extensions.ini'), "w") as f1:
                f1.write("[ExtensionDirs]\nExtension0=" + os.path.join(datadir, 'FF-profile', "extensions", "lspnr@lspnr") + "\n")
            #show addon bar
            with codecs.open(os.path.join(datadir, 'FF-profile', 'localstore.rdf'), 'w') as f2:
                f2.write('<?xml version="1.0"?><RDF:RDF xmlns:NC="http://home.netscape.com/NC-rdf#" xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><RDF:Description RDF:about="chrome://browser/content/browser.xul"><NC:persist RDF:resource="chrome://browser/content/browser.xul#addon-bar" collapsed="false"/></RDF:Description></RDF:RDF>')    
        except Exception,e:
            print ('File open error', e,end='\r\n')
            return ['File open error'] 
          
    if os.path.isfile(sslkeylog): os.remove(sslkeylog)
    open(sslkeylog,'w').close()
    os.putenv("SSLKEYLOGFILE", sslkeylog)
    os.putenv("FF_to_backend_port", str(FF_to_backend_port))
    os.putenv("FF_proxy_port", str(FF_proxy_port))
    #used to prevent addon's confusion when certain sites open new FF windows
    os.putenv("FF_first_window", "true")
    
    print ("Starting a new instance of Firefox with Paysty's profile",end='\r\n')
    try:
        ff_proc = subprocess.Popen([firefox_exepath,'-no-remote', '-profile', os.path.join(datadir, 'FF-profile')], stdout=open(os.path.join(datadir, 'firefox', "firefox.stdout"),'w'), stderr=open(os.path.join(datadir, 'firefox', "firefox.stderr"), 'w'))
    except Exception,e:
        print ("Error starting Firefox", e,end='\r\n')
        return ["Error starting Firefox"]   
    return ['success', ff_proc]



#using AWS query API make sure oracle meets the criteria
#the rationale behind these checks is addressed in oracle/INSTALL
def check_oracle_urls (GetUserURL, ListMetricsURL, DescribeInstancesURL, DescribeVolumesURL, GetConsoleOutputURL, oracle_dns):
    try:
        di_url = urllib2.urlopen(DescribeInstancesURL)
        di_xml = di_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return 'error in urllib'
    try:
        di_dom = minidom.parseString(di_xml)
        if len(di_dom.getElementsByTagName('ErrorResponse')) > 0: return 'bad oracle'

        is_dns_found = False
        dns_names = di_dom.getElementsByTagName('dnsName')
        for one_dns_name in dns_names:
            if one_dns_name.firstChild == None:
                continue
            if one_dns_name.firstChild.data != oracle_dns:
                continue
            is_dns_found = True
            break
        if not is_dns_found:
            return 'bad oracle'
        instance = one_dns_name.parentNode
    
        if instance.getElementsByTagName('imageId')[0].firstChild.data not in amis or\
        instance.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].firstChild.data != 'running' or\
        instance.getElementsByTagName('rootDeviceName')[0].firstChild.data != '/dev/sda1':
            return 'bad oracle'
        launchTime = instance.getElementsByTagName('launchTime')[0].firstChild.data
        instanceId = instance.getElementsByTagName('instanceId')[0].firstChild.data
        ownerId = instance.parentNode.parentNode.getElementsByTagName('ownerId')[0].firstChild.data
        
        volumes = instance.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item')
        if len(volumes) > 1: return 'bad oracle'
        if volumes[0].getElementsByTagName('deviceName')[0].firstChild.data != '/dev/sda2': return 'bad oracle'
        if volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].firstChild.data != 'attached': return 'bad oracle'
        instance_volumeId = volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].firstChild.data
        attachTime = volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].firstChild.data
        #example of aws time string 2013-10-12T21:17:31.000Z
        if attachTime[:17] != launchTime[:17]:
            return 'bad oracle'
        if int(attachTime[17:19])-int(launchTime[17:19]) > 3:
            return 'bad oracle'
    except Exception,e:
        print(e, end='\r\n')
        return 'bad data from Amazon'
    
    try:
        dv_url = urllib2.urlopen(DescribeVolumesURL)
        dv_xml = dv_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return 'error in urllib'
    try:
        dv_dom = minidom.parseString(dv_xml)
        if len(dv_dom.getElementsByTagName('ErrorResponse')) > 0: return 'bad oracle'

        is_volumeID_found = False
        volume_IDs = dv_dom.getElementsByTagName('volumeId')
        for one_volume_ID in volume_IDs:
            if one_volume_ID.firstChild.data != instance_volumeId:
                continue
            is_volumeID_found = True
            break
        if not is_volumeID_found:
            return 'bad oracle'
        volume = one_volume_ID.parentNode
    
        if volume.getElementsByTagName('snapshotId')[0].firstChild.data not in oracle_snapID or\
        volume.getElementsByTagName('status')[0].firstChild.data != 'in-use' or\
        volume.getElementsByTagName('volumeType')[0].firstChild.data != 'standard':
            return 'bad oracle'
        createTime = volume.getElementsByTagName('createTime')[0].firstChild.data
        
        attached_volume = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item')[0]
        if attached_volume.getElementsByTagName('volumeId')[0].firstChild.data != instance_volumeId or\
        attached_volume.getElementsByTagName('instanceId')[0].firstChild.data != instanceId or\
        attached_volume.getElementsByTagName('device')[0].firstChild.data != '/dev/sda2' or\
        attached_volume.getElementsByTagName('status')[0].firstChild.data != 'attached' or\
        attached_volume.getElementsByTagName('attachTime')[0].firstChild.data[:-4] != attachTime[:-4] or\
        attached_volume.getElementsByTagName('attachTime')[0].firstChild.data[:-4] != createTime[:-4]:
            return 'bad oracle'
    except Exception,e:
        print(e, end='\r\n')
        return 'bad data from Amazon'
    
    try:
        gco_url = urllib2.urlopen(GetConsoleOutputURL)
        gco_xml = gco_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return 'error in urllib'
    try:
        gco_dom = minidom.parseString(gco_xml)
        base64output = gco_dom.getElementsByTagName('output')[0].firstChild.data
        logdata = base64.b64decode(base64output)
        if len(gco_dom.getElementsByTagName('ErrorResponse')) > 0: return 'bad oracle'
        if gco_dom.getElementsByTagName('instanceId')[0].firstChild.data != instanceId:
            return 'bad oracle'

        #Only xvda2 is allowed to be in the log and no other string matchin the regex xvd*
        if re.search('xvd[^a] | xvda[^2]', logdata) != None:
            return 'bad oracle'
    except Exception,e:
        print(e, end='\r\n')
        return 'bad data from Amazon'
    
    #The ListMetrics criterion will only be used in production env. as it requires that the whole Amazon AWS account runs only the oracle
    #and has no other volumes or instances
    if not ALPHA_TESTING:
        try:
            lm_url = urllib2.urlopen(ListMetricsURL)
            lm_xml = lm_url.read()
        except Exception,e:
            print(e, end='\r\n')
            return 'error in urllib'
        try:
            lm_dom = minidom.parseString(lm_xml)
            if len(lm_dom.getElementsByTagName('ErrorResponse')) > 0: return 'bad oracle'
        
            names = lm_dom.getElementsByTagName('Name')
            for one_name in names:
                if (one_name.firstChild.data == 'VolumeId' and one_name.parentNode.getElementsByTagName('Value')[0].firstChild.data != instance_volumeId) or (one_name.firstChild.data == 'InstanceId' and one_name.parentNode.getElementsByTagName('Value')[0].firstChild.data != instanceId):
                    print ('Too many volumes or instances detected', end='\r\n')
                    return 'bad oracle'
        except Exception,e:
            print(e, end='\r\n')
            return 'bad data from Amazon'
         
         
    try:
        gu_url = urllib2.urlopen(GetUserURL)
        gu_xml = gu_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return 'error in urllib'
    try:
        gu_dom = minidom.parseString(gu_xml)
        if len(gu_dom.getElementsByTagName('ErrorResponse')) > 0: return 'bad oracle'
    
        names = gu_dom.getElementsByTagName('UserId')
        if len(names) > 1: return 'bad oracle'
        arn = gu_dom.getElementsByTagName('Arn')[0].firstChild.data
        if not arn.endswith(ownerId+":root"): return 'bad oracle'
    except Exception,e:
        print(e, end='\r\n')
        return 'bad data from Amazon'
    
    #make sure the same root's AccessKey was used for all URLs
    try:
        AccessKeyId = GetUserURL.split('/?AWSAccessKeyId=')[1].split('&')[0]
        for url in (ListMetricsURL, DescribeInstancesURL, DescribeVolumesURL, GetConsoleOutputURL):
            if AccessKeyId != url.split('/?AWSAccessKeyId=')[1].split('&')[0] : return 'bad oracle'
    except Exception,e:
        print(e, end='\r\n')
        return 'bad data from Amazon'
       
    return 'success'

#aux function used in convert_key()
def long_to_bytes(n):
    s = ''
    n = long(n)
    while n > 0:
        s = struct.pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000'[0]:
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    return s

#Convert the regular privkey file format into Putty's own PPK format
#adapted from https://github.com/AdamISZ/ssllog/blob/master/userkeymgmt.py
def convert_key():
    global alphatest_key
    global alphatest_ppk
    try:
        with open(alphatest_key, 'r') as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read())
    except:
        return 'Error reading the key in ' + alphatest_key +'. Make sure the key exists and its data is not corrupted'
    
    pkps=[]
    for a in [privkey.d,privkey.p,privkey.q,privkey.coef]:
        ab = long_to_bytes(a)
        if ord(ab[0]) & 0x80: ab=chr(0x00)+ab
        pkps.append(ab)
    privkeystring = ''.join([struct.pack(">I",len(pkp))+pkp for pkp in pkps])
    priv_repr = binascii.b2a_base64(privkeystring)[:-1]
    
    #generate pubkey from privkey material, see https://bitbucket.org/sybren/python-rsa/src/509b1d657cb8eb942587be862aef10587b5ea2af/rsa/key.py?at=default#cl-592
    pubkey = rsa.PublicKey(privkey.n, privkey.e)
    
    eb = long_to_bytes(pubkey.e)
    nb = long_to_bytes(pubkey.n)
    if ord(eb[0]) & 0x80: eb=chr(0x00)+eb
    if ord(nb[0]) & 0x80: nb=chr(0x00)+nb
    keyparts = [ 'ssh-rsa', eb, nb ]
    keystring = ''.join([ struct.pack(">I",len(kp))+kp for kp in keyparts]) 
    public_repr = binascii.b2a_base64(keystring)[:-1]
    
    macdata = ''
    for s in ['ssh-rsa','none','imported-openssh-key',keystring, privkeystring]:
        macdata += (struct.pack(">I",len(s)) + s)
    
    HMAC_key = 'putty-private-key-file-mac-key'
    HMAC_key2 = hashlib. sha1(HMAC_key).digest()
    HMAC2 = hmac.new(HMAC_key2,macdata,sha1)
    
    with open(alphatest_ppk,'wb') as f:
        f.write('PuTTY-User-Key-File-2: ssh-rsa\r\n')
        f.write('Encryption: none\r\n')
        f.write('Comment: imported-openssh-key\r\n')
        
        f.write('Public-Lines: '+str(int((len(public_repr)+63)/64))+'\r\n')
        for i in range(0,len(public_repr),64):
            f.write(public_repr[i:i+64])
            f.write('\r\n')        
            
        f.write('Private-Lines: '+str(int((len(priv_repr)+63)/64))+'\r\n')
        for i in range(0,len(priv_repr),64):
            f.write(priv_repr[i:i+64])
            f.write('\r\n')    
            
        f.write('Private-MAC: ')
        f.write(HMAC2.hexdigest())
        f.write('\r\n')
    return 'success'


#a thread to work around Windows' blocking on stderr.readline in start_tunnel
def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()
    

#Launch stcppipe and ssh in such a way that traffic from Firefox travels in this manner:
#FF --> local stcppipe --> local ssh --> oracle sshd --> oracle stcppipe --> oracle squid --> bank

#privkey server as a password in order to use the oracle and should be given to user by escrow
def start_tunnel(privkey_file, oracle_address):
    global assigned_port
    global random_ssh_port    
    global stcppipe_proc
    global ssh_proc
    global is_ssh_session_active
    
    if not os.path.isfile(alphatest_key): return 'Please make sure alphatest.txt is in your installation directory'
    
    if OS=='win':
        retval = convert_key()
        if retval != 'success':
            return retval
    if OS=='linux':
        os.chmod(alphatest_key, stat.S_IRUSR | stat.S_IWUSR)
        
    if os.path.isdir(logdir) : shutil.rmtree(logdir)
    os.mkdir(logdir)
    
    random_ssh_port = random.randint(1025,65535)
    stcppipe_proc = subprocess.Popen([stcppipe_exepath, '-d', logdir, '-b', '127.0.0.1', str(random_ssh_port), str(FF_proxy_port)])
    time.sleep(1)
    if stcppipe_proc.poll() != None:
        return 'stcppipe error'
    if OS=='linux':        
        ssh_proc = subprocess.Popen([ssh_exepath, '-i', alphatest_key, '-o', 'StrictHostKeyChecking=no',  '-o', 'IdentitiesOnly=yes', username+'@'+oracle_address, '-L', str(random_ssh_port)+':localhost:'+assigned_port, '-p', '22'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        is_ssh_session_active = True
    elif OS=='win':
        ssh_proc = subprocess.Popen([plink_exepath, '-i', alphatest_ppk,  username+'@'+oracle_address, '-L', str(random_ssh_port)+':localhost:'+assigned_port, '-P', '22'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        is_ssh_session_active = True
        q = Queue.Queue()
        t = threading.Thread(target=enqueue_output, args=(ssh_proc.stderr, q))
        t.daemon = True # thread dies with the program
        t.start()                
    
    #give sshd 20 secs to respond with 'Tunnel ready'
    first_run = False
    waiting_started = time.time()
    sshlog_fd = open(ssh_logfile, 'w')
    while 1:
        cmd = ''
        #Linux doesn't block on readlne here, whereas Windows does
        if OS=='linux':
            cmd = ssh_proc.stderr.readline()
        elif OS=='win':
            try:  
                cmd = q.get_nowait()
            except Queue.Empty:
                pass
        if not cmd:
            if time.time() - waiting_started > 20:
                os.kill(ssh_proc.pid, signal.SIGTERM)
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                is_ssh_session_active = False
                sshlog_fd.close()
                return 'sshd was taking too long to stat the tunnel'        
            if ssh_proc.poll() != None:
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                sshlog_fd.close()   
                is_ssh_session_active = False
                if first_run: return 'Server timed out. This happens when you log in for the first time. Please try again'
                else: return 'ssh exited abruptly'
            continue
        sshlog_fd.write(cmd+'\n')
        sshlog_fd.flush()
        if OS=='win':
            if cmd.startswith("connection."):
                #only happens on first run plink is adding host keys to windows registry
                #because of this delay we may fail to make the 3 seconds window allowed to finish logging in
                ssh_proc.stdin.write("y\r\n")
                ssh_proc.stdin.flush()
                first_run = True
                continue
        if cmd.startswith('Session finished. Please reconnect and use port '):
            #happens when the remote forwarding port on oracle is already in use
            newport = cmd[len('Session finished. Please reconnect and use port '):].split()[0]
            if len(newport) < 4 or len(newport)>5:
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                sshlog_fd.close()
                is_ssh_session_active = False
                return 'newport length error'
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            sshlog_fd.close()
            assigned_port = newport
            is_ssh_session_active = False
            return 'reconnect'
        if cmd.startswith('Session finished.'): 
            os.kill(stcppipe_proc.pid, signal.SIGTERM)            
            sshlog_fd.close()
            is_ssh_session_active = False
            return 'session finished'
        if cmd.startswith('Tunnel ready'): 
            sshlog_fd.close()
            return 'success'
    
    
if __name__ == "__main__": 
    if OS=='win':
        MessageBox = ctypes.windll.user32.MessageBoxA        
         
    if os.path.isfile(os.path.join(datadir, "firstrun")):
        print ('Running for the first time. Initializing...',end='\r\n')
        if OS=='linux':
            #check that ssh, gcc, tshark, mergecap, and firefox are installed
            try:
                subprocess.check_output(['which', 'ssh'])
            except:
                print ('Please make sure ssh is installed and in your PATH',end='\r\n')
                exit(1)
            try:
                subprocess.check_output(['which', 'gcc'])
            except:
                print ('Please make sure gcc is installed and in your PATH', end='\r\n')
                exit(1)    
            try:
                subprocess.check_output(['which', 'tshark'])
            except:
                print ('Please make sure tshark is installed and in your PATH', end='\r\n')
                exit(1)
            try:
                subprocess.check_output(['which', 'mergecap'])
            except:
                print ('Please make sure mergecap is installed and in your PATH', end='\r\n')
                exit(1)            
            try:
                subprocess.check_output(['which', 'firefox'])
            except:
                print ('Please make sure firefox is installed and in your PATH', end='\r\n')
                exit(1)               
    
            #on first run, check stcppipe.zip's hash and compile it
            #stcppipe by Luigi Auriemma http://aluigi.altervista.org/mytoolz/stcppipe.zip v.0.4.8b
            sp_fd = open(os.path.join(datadir,"stcppipe.zip"), 'r')
            sp_bin = sp_fd.read()
            sp_fd.close()
            if (hashlib.sha256(sp_bin).hexdigest() != "3fe9e52633d923733841f7d20d1c447f0ec2e85557f68bac3f25ec2824b724e8"):
                exit(1)
            zfile = zipfile.ZipFile(os.path.join(datadir, "stcppipe.zip"))
            zfile.extractall(os.path.join(datadir, "stcppipe"))      
            try:
                subprocess.check_output(['gcc', '-o', 'stcppipe', 'stcppipe.c', '-DDISABLE_SSL', '-DACPDUMP_LOCK', '-lpthread'], cwd=os.path.join(datadir, "stcppipe"))
            except:
                print ('Error compiling stcppipe. Please let the developers know', end='\r\n')
                exit(1)            
            os.remove(os.path.join(datadir, "firstrun"))
            
        if OS=='win':
            #check hash and unzip stcppipe
            #stcppipe by Luigi Auriemma http://aluigi.altervista.org/mytoolz/stcppipe.zip v.0.4.8b
            sp_fd = open(os.path.join(datadir,"stcppipe.zip"), 'rb')
            sp_bin = sp_fd.read()
            sp_fd.close()
            if (hashlib.sha256(sp_bin).hexdigest() != "3fe9e52633d923733841f7d20d1c447f0ec2e85557f68bac3f25ec2824b724e8"):
                print ('Wrong stcppipe.zip hash')
                MessageBox(None, 'Wrong stcppipe.zip hash', 'Error', 0)                       
                exit(1)
            zfile = zipfile.ZipFile(os.path.join(datadir, "stcppipe.zip"))
            zfile.extractall(os.path.join(datadir, "stcppipe"))
            print ('stcppipe extracted...',end='\r\n')            
                        
            #plink v0.63.0.0 (part of Putty suite) http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html
            pl_fd = open(os.path.join(datadir,"plink.exe"), 'rb')
            pl_bin = pl_fd.read()
            pl_fd.close()
            if (hashlib.sha256(pl_bin).hexdigest() != "fe465e89b87dfb17441053149133e0413dafea81ea36fa3caaca3a72445bc475"):
                print('Wrong plink.exe hash')
                MessageBox(None, 'Wrong plink.exe hash', 'Error', 0)                                       
                exit(1)
                
            #python 2.7 
            # http://www.python.org/ftp/python/2.7.5/python-2.7.5.msi
            # signature for this file from python.org
            #-----BEGIN PGP SIGNATURE-----
            #Version: GnuPG v2.0.14 (MingW32)
            
            #iEYEABECAAYFAlGT9rUACgkQavBT8H2dyNLtLACZARE3lxDyOn378PmwN/bpB4VM
            #E8IAn0D2+4M2cp1bI3f7YL/BdiBQZNFk
            #=XXA9
            #-----END PGP SIGNATURE----- 
            #All unnecessary components were deleted
            #msvcr*90.dll files for winXP compatibility from:
            #http://portablepython.com/wiki/PortablePython2.7.5.1  (SHA1 - deb49e5d9a82f192eaab1e6786156fc6a5368c03)
            hashlist = []
            for root, dirs, files in os.walk(os.path.join(datadir, "Python27")):
                for file in files:
                    if file.endswith('.pyc'): continue
                    with open((os.path.join(root,file)), 'rb') as f:
                        hashlist.append(hashlib.sha256(f.read()).hexdigest())
            hashlist.sort()
            if hashlib.sha256(','.join(hashlist)).hexdigest() != '160c6d97c0d0ce3bab388d7242eb4499f98841aab001462951e664cb6103fac9':
                print ('Wrong hash for files in Python27 dir')
                MessageBox(None, 'Wrong hash for files in Python27 dir', 'Error', 0)                                                       
                exit(1)
                           
            # tshark and mergecap v1.10.2 (part of Wireshark suite)
            # http://wiresharkdownloads.riverbed.com/wireshark/win32/WiresharkPortable-1.10.2.paf.exe or
            # http://sourceforge.net/projects/wireshark/files/win32/WiresharkPortable-1.10.2.paf.exe/download
            hashlist = []                        
            for root, dirs, files in os.walk(os.path.join(datadir, "wireshark")):
                for file in files:
                    with open((os.path.join(root,file)), 'rb') as f:
                        hashlist.append(hashlib.sha256(f.read()).hexdigest())
            hashlist.sort()
            if hashlib.sha256(','.join(hashlist)).hexdigest() != 'e2093eaf89f0a8691ade68fd596f878eed6b389278d3b482382284432115c8e3':
                print ('Wrong hash for files in wireshark dir')
                MessageBox(None, 'Wrong hash for files in wireshark dir', 'Error', 0)                                                                       
                exit(1)            
            os.remove(os.path.join(datadir, "firstrun"))
            print ('plink and python integrity checked...',end='\r\n')            
            
            
    
    #a temporary hack to determine whether dansmith or waxwing was the one who issued a private key
    #by convention, dansmith's privkey ends with "==", otherwise it Is waxwing's
    if not os.path.isfile(alphatest_key): 
        if OS== 'win': MessageBox(None, 'Please make sure alphatest.txt is in your installation directory', 0)
        else: print ('Please make sure alphatest.txt is in your installation directory')
        exit(1)
    with open(alphatest_key, 'r') as keyfile: keytext = keyfile.read()
    lines = keytext.split('\n')
    lines.reverse()
    for index,line in enumerate(lines):
        if line.count('-----END RSA PRIVATE KEY-----') > 0: break
    if lines[index+1].endswith('=='):
        preferred_escrow = 'dansmith'
    else: preferred_escrow = 'waxwing'
        
    
    
    if OS=='win':
        if os.path.isfile(os.path.join(os.getenv('programfiles'), "Mozilla Firefox",  "firefox.exe" )): 
            firefox_exepath = os.path.join(os.getenv('programfiles'), "Mozilla Firefox",  "firefox.exe" )
        elif  os.path.isfile(os.path.join(os.getenv('programfiles(x86)'), "Mozilla Firefox",  "firefox.exe" )): 
            firefox_exepath = os.path.join(os.getenv('programfiles(x86)'), "Mozilla Firefox",  "firefox.exe" )
        else:
            print ('Please make sure firefox is installed and in your PATH', end='\r\n')
            MessageBox(None, 'Please make sure Firefox is installed. If it is already installed, make sure it is in your Program Files folder', 'Error', 0)
            exit(1)
    
    #make sure tshark's default profile exists
    #This profile contains factory defaults. We need it so that if user has his own wireshark installed
    #his settings would not interfere with ours
    paysty_profile = None
    if OS=='win':   paysty_profile = os.path.join(os.getenv('appdata'), 'wireshark', 'profiles', 'paysty')
    if OS=='linux': paysty_profile = os.path.join(os.getenv('HOME'), '.wireshark', 'profiles', 'paysty')
    
    if not os.path.isdir(paysty_profile):
        print ('Creating tshark\'s default profile...',end='\r\n')             
        try:
            os.makedirs(paysty_profile)
            paysty_pref = os.path.join (paysty_profile, 'preferences')
            open(paysty_pref, 'w').close()
            subprocess.call([tshark_exepath, '-G', 'defaultprefs'], stdout=open(paysty_pref, 'w'))
        except:
            print ('Error creating tshark\'s default profile', end='\r\n')
            MessageBox(None, 'Error creating tshark\'s default profile', 'Error', 0)
            exit(1)            
        
         
    FF_to_backend_port = random.randint(1025,65535)
    FF_proxy_port = random.randint(1025,65535)

    thread = ThreadWithRetval(target= buyer_start_minihttp_thread)
    thread.daemon = True
    thread.start()
  
    ff_retval = start_firefox()
    if ff_retval[0] != 'success':
        print ('Error while starting Firefox: '+ ff_retval[0], end='\r\n')
        if OS=='win':  MessageBox(None, 'Error while starting Firefox: '+ff_retval[0], 'Error', 0)
        exit(1)
    ff_proc = ff_retval[1]    
    
    while True:
        time.sleep(1)
        if ff_proc.poll() != None:
            #FF window was closed, shut down all subsystems and exit gracefully
            request = urllib2.Request("http://127.0.0.1:" +str(FF_to_backend_port)+ "/terminate")
            request.get_method = lambda : 'HEAD'            
            urllib2.urlopen(request)
            break
        
