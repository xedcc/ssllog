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
escrow_host = 'localhost' #e.g. '1.2.3.4'  NB! '127.0.0.1' may not work, use localhost instead
#the port is an arbtrary port on the escrow's server. Unless there is a port conflict, no need to change it.
escrow_port = 12345
#an existing username and password used to connect to sshd on escrow's server. For testing you can give your username if sshd ir run locally
escrow_ssh_user = 'default' #e.g. 'ssllog_user' 
escrow_ssh_pass = 'VqQ7ccyKcZCRq'

#ssllog_installdir is the dir from which main.py is run
currfile = inspect.getfile(inspect.currentframe())
installdir = os.path.dirname(os.path.realpath(__file__))

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

#where buyer's dumpcap puts its traffic capture file
buyer_dumpcap_capture_file= os.path.join(installdir, 'capture', 'buyer_dumpcap.pcap')
#where seller's dumpcap puts its traffic capture file
seller_dumpcap_capture_file= os.path.join(installdir, 'capture', 'seller_dumpcap.pcap')
#where Firefox saves html files when user marks them
htmldir = os.path.join(installdir,'htmldir')
sslkeylogfile = os.path.join(installdir, 'capture', 'sslkeylog')

#bitcond user/pass are already in bitcon.conf that comes with this installation
#these bitcond handlers can be initialized even before bitcoind starts
buyer_bitcoin_rpc = authproxy.AuthServiceProxy("http://ssllog_user:ssllog_pswd@127.0.0.1:8338")
seller_bitcoin_rpc = authproxy.AuthServiceProxy("http://ssllog_user:ssllog_pswd@127.0.0.1:8339")

#--------------End of customizable variables------------------------------------------------

#handle only paths we are interested and let python handle the response headers
#class "object" in needed to access super()
class buyer_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"
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
            self.send_header("value", os.path.join(installdir, 'capture', 'dummy'))
            super(buyer_HandlerClass, self).do_HEAD()
        elif self.path == '/finished':
            self.send_response(200)
            self.send_header("response", "finished")
            self.send_header("value", "ok")
            super(buyer_HandlerClass, self).do_HEAD()
            self.server.stop = True
    #logging messes up the terminal, disabling
    def log_message(self, format, *args):
        return
    
            
#handle only paths we are interested and let python handle the response headers
#class "object" in needed to access super()
class seller_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"
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
        if self.path.startswith('/sslkeylogfile='):
            print ("Received SSL keys from the buyer",end='\r\n')
            base64_sslkeylog_str = self.path[len('/sslkeylogfile='):]
            sslkeylog_str = base64.b64decode(base64_sslkeylog_str)
            with open (os.join.path(installdir,'escrow','sslkeylogfile'), "w") as file:
                file.write(sslkeylog_str)
            self.send_response(200)
            self.send_header("response", "sslkeylogfile")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
        if self.path.startswith('/hashes='):
            print ("Received hashes of SSL segments from the buyer",end='\r\n')
            self.server.retval = self.path[len('/hashes='):]
            self.send_response(200)
            self.send_header("response", "hashes")
            self.send_header("value", "ok")
            super(seller_HandlerClass, self).do_HEAD()
            #receiving "hashes=" message is a signal to stop this server and continue in the main thread with parsing the hashes
            self.server.stop = True
    #logging messes up the terminal, disabling
    def log_message(self, format, *args):
        return
                
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
 
            
#send all the hashes in an HTTP HEAD request    
def buyer_send_sslhashes(sslhashes):
    print ("Sending hashes of SSL segments to the seller",end='\r\n')
    hashes_string = ''
    for hash in sslhashes:
        hashes_string += ';'+hash
    message = requests.head("http://127.0.0.1:4445/hashes="+hashes_string, proxies={"http":"http://127.0.0.1:3128"})
    if message.status_code != 200:
       print ("Unable to send SSL hashes to seller",end='\r\n')
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
    #message = requests.head("http://127.0.0.1:4444/sslkeylogfile="+base64_keylogfile_ascii, proxies={"http":"http://127.0.0.1:8080"})
    #if message.status_code != 200:
       #print  "Unable to send SSL keylogfile to escrow"
       #cleanup_and_exit()
    
    #For local testing - just copy it into the escrow folder
    shutil.copy(os.path.join(installdir, 'capture', 'sslkeylog'), os.path.join(installdir,'escrow','sslkeylog'))    
    
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
        response = requests.get("http://example.org", proxies={"http":"http://127.0.0.1:3128"})
        if response.status_code != 200:
            print ("Unable to make a test connection through seller's proxy",end='\r\n')
            cleanup_and_exit()
    #stunnel changes PID after launch, use pidfile
    pidfile = open('/tmp/stunnel.pid', 'r')
    pid = int(pidfile.read().strip())
    pids['stunnel'] = pid

def send_logs_to_escrow(ssl_hashes):
    print ("Findind SSL segments in captured traffic",end='\r\n')
    if len(ssl_hashes) < 1:
        print ('zero hashes provided',end='\r\n')
        cleanup_and_exit()
    frames_wanted = []
    #we're only concerned with SSL frames which don't contain handshakes but application data
    try:
        frames_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'frame.number'])
    except Exception,e:
        print ('Exception in tshark',e,end='\r\n')
        cleanup_and_exit()
    frames_str = frames_str.rstrip()
    ssl_frames = frames_str.split('\n')
    print ('need to process SSL frames:', len(ssl_frames),end='\r\n')
    
    try:
        app_data_str = subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'ssl.app_data', '-T', 'fields', '-e', 'ssl.app_data'])
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
        print ('Processing frame ' + str(index+1) + ' out of total ' + str(len(ssl_frames)))        
        #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
        segments = appdata.split(',')
        
        for one_segment in segments:
            one_segment = one_segment.replace(':',' ')
            ssl_md5 = hashlib.md5(bytearray.fromhex(one_segment)).hexdigest()
            if ssl_md5 in ssl_hashes:
                print ("found hash", ssl_md5)
                frames_wanted.append(ssl_frames[index])
                if len(frames_wanted) == len(ssl_hashes):
                    break_out = True
                    break
                
        if break_out == True:
            break
            
    if len (frames_wanted) < 1:
        print ("Couldn't find all SSL frames with given hashes. Frames found:"+str(len(frames_wanted))+" out of:"+str(len(ssl_hashes)),end='\r\n')
        cleanup_and_exit()
    else:
        
        #sanity check: the whole scheme hinges on the assumption that all the found SSL segments belong to the same TCP stream
        tshark_arg = 'frame.number=='+frames_wanted[0]
        for frame in frames_wanted[1:]:
            tshark_arg += ' or frame.number=='+frame
        try:
            tcpstreams_str =  subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', tshark_arg, '-T', 'fields', '-e', 'tcp.stream'])
        except Exception,e:
            print ('Error starting tshark',e)
            cleanup_and_exit()
        tcpstreams_str = tcpstreams_str.rstrip()
        tcpstreams = tcpstreams_str.split('\n')
        #the amount of elements with the value of element [0] should be equal to the size of list
        if tcpstreams.count(tcpstreams[0]) != len(tcpstreams):
            print ("A very serious issue encountered. Not all SSL segments belong to the same TCP stream. Please contact the developers",end='\r\n')
            cleanup_and_exit()
        
        
        print ("All SSL segments found, removing all confidential information from the captured traffic",end='\r\n')
        
        #-------------------------------------------------------------------------------------------------
        #Obsolete code left here just in case
        ##prepare the cap file to be sent from gateway user to escrow. Leave only frames wanted, purge the rest.
        #frames_to_purge = ssl_frames
        #[frames_to_purge.remove(item) for item in frames_wanted if item in frames_to_purge]
        #End of obsolete code
        #----------------------------------------------------------------------------------------------
        
        #Leave only the TCP stream of the SSL segments we need to keep
        try:
            frames_to_keep_str =  subprocess.check_output([tshark_exepath, '-r', seller_dumpcap_capture_file, '-Y', 'tcp.stream=='+tcpstreams[0], '-T', 'fields', '-e', 'frame.number'])
        except Exception,e:
            print ('Error starting tshark',e,end='\r\n')
            cleanup_and_exit()
        frames_to_keep_str = frames_to_keep_str.rstrip()
        frames_to_keep = frames_to_keep_str.split('\n')
        
        if len(frames_to_keep) > 500:
            #editcap can't handle editing more than 512 frames in one invocation, hence the workaround
            prev_last_frame = '0'
            #max amount of ssl frames in one chunk that gets processed by editcap
            frames_in_chunk = 500
            for iteration in range(len(frames_to_keep)/frames_in_chunk + 1):
                frame_chunk = frames_to_keep[frames_in_chunk*iteration:frames_in_chunk*(iteration+1)]
                last_frame = frame_chunk[-1]
                partname = 'part' + str(iteration+1)
                subprocess.call([editcap_exepath, seller_dumpcap_capture_file, seller_dumpcap_capture_file+'2', '-r', '0-'+last_frame])
                editcap_args = [editcap_exepath, seller_dumpcap_capture_file+'2', seller_dumpcap_capture_file+partname, '-r']
                for frame in frame_chunk:
                    editcap_args.append(frame)
                try:
                    subprocess.call(editcap_args)
                except Exception,e:
                    print ('Exception in editcap',e,end='\r\n')
                    cleanup_and_exit()
                prev_last_frame = last_frame

                ##Obsolete code: chop-off up to the previous_last_frame
                #subprocess.call([editcap_exepath, seller_dumpcap_capture_file+'3', seller_dumpcap_capture_file+partname,  '0-'+prev_last_frame])
                
            mergecap_args = [mergecap_exepath, '-a', '-w', seller_dumpcap_capture_file+'final']
            for iteration in range(len(frames_to_keep)/frames_in_chunk + 1):
                mergecap_args.append(seller_dumpcap_capture_file+'part'+ str(iteration+1))
                subprocess.call(mergecap_args)
                
        else:
            editcap_args = [editcap_exepath, seller_dumpcap_capture_file, seller_dumpcap_capture_file+'final', '-r']
            for frame in frames_to_keep:
                editcap_args.append(frame)
            try:
                subprocess.call(editcap_args)
            except Exception,e:
                print ('Exception in editcap', e,end='\r\n')
                cleanup_and_exit()        
                     
        #at this point, send the capture to escrow. For testing, save it locally.
        #don't forget to base64 encodeit if sending via http head
        shutil.copy(seller_dumpcap_capture_file+'final', os.path.join(installdir,'escrow','escrow.pcap'))
        

#the return value will be placed into HTTP header and sent to buyer. Python has a 64K limit on header size
def seller_get_certificate_verify_message():
    print ("Preparing and sending the certificate together with a signature to the buyer",end='\r\n')
    with open (os.path.join(installdir, "stunnel", "seller.pem"), "r") as certfile:
        certdata = certfile.read()
    certificate = certdata.__str__()
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
        signature = seller_bitcoin_rpc.signmessage(seller_btc_address, certificate)
    except Exception, e:
        print ("Error while invoking signmessage. Did you indicate a valid BTC address?", e,end='\r\n')
        cleanup_and_exit()
    return signature + ';' + certificate + ':' + seller_btc_address    

def seller_start_bitcoind_stunnel_sshpass_dumpcap_squid(skip_capture):
    global pids
    
    if skip_capture == False:
        print ("Starting bitcoind in offline mode. No part of blockchain will be downloaded",end='\r\n')
        if os.path.isdir(os.path.join(installdir, 'bitcoind')) == False:
            os.makedirs(os.path.join(installdir, 'bitcoind'))
        if os.path.isdir(os.path.join(installdir, 'bitcoind', 'datadir_seller')) == False:
            os.makedirs(os.path.join(installdir, 'bitcoind', 'datadir_seller'))
           
        try:
           #start bitcoind in offline mode
           bitcoind_proc = subprocess.Popen([bitcoind_exepath, '-datadir=' + os.path.join(installdir, 'bitcoind', "datadir_seller"), '-maxconnections=0', '-server', '-listen=0', '-rpcuser=ssllog_user', '-rpcpassword=ssllog_pswd', '-rpcport=8339'], stdout=open(os.path.join(installdir, 'bitcoind', "bitcoind_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'bitcoind', "bitcoind_seller.stderr"),'w'))
        except:
            print ('Exception starting bitcoind',end='\r\n')
            cleanup_and_exit()
        pids['bitcoind']  = bitcoind_proc.pid
        
        print ("Starting ssh connection to escrow's server",end='\r\n')
        try:
            sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_host, '-R', str(escrow_port)+':localhost:33310'], stdout=open(os.path.join(installdir, 'ssh', "ssh_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'ssh', "ssh_seller.stderr"),'w'))
        except:
            print ('Exception connecting to sshd',end='\r\n')
            cleanup_and_exit()
        pids['sshpass']  = sshpass_proc.pid
    
    print ("Starting stunnel",end='\r\n')
    #stunnel finds paths in .conf relative to working dir
    os.chdir(os.path.join(installdir,'stunnel'))
    try:
        stunnel_proc = subprocess.Popen([stunnel_exepath, os.path.join(installdir, 'stunnel', 'seller.conf')], cwd=os.path.join(installdir, 'stunnel'), stdout=open(os.path.join(installdir, 'stunnel', 'stunnel_seller.stdout'),'w'), stderr=open(os.path.join(installdir, 'stunnel', 'stunnel_seller.stderr'),'w'))
    except:
        print ('Exception starting stunnel',end='\r\n')
        cleanup_and_exit()
    #stunnel changes PID after launch, use pidfile
    #give it a second to create the pid file
    time.sleep(1)
    pidfile = open('/tmp/stunnel2.pid', 'r')
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
            dumpcap_proc = subprocess.Popen([dumpcap_exepath, '-i', 'lo', '-f', 'tcp port 3128', '-w', seller_dumpcap_capture_file ], stdout=open(os.path.join(installdir, 'dumpcap', "dumpcap_seller.stdout"),'w'), stderr=open(os.path.join(installdir, 'dumpcap', "dumpcap_seller.stderr"),'w'))
        except Exception,e:
            print ('Exception dumpcap',e,end='\r\n')
            cleanup_and_exit()
        pids['dumpcap'] = dumpcap_proc.pid    
    
def buyer_get_and_verify_seller_cert():
    #receive signature and plain_cert as ";" delimited string
    print ('Requesting the certificate from the seller',end='\r\n')
    response = requests.head("http://127.0.0.1:4445/certificate", proxies={"http":"http://127.0.0.1:3128"})
    if response.status_code != 200:
        print ("Unable to get seller's certificate",end='\r\n')
        cleanup_and_exit()
    base64_message = response.headers['value']
    message = base64.b64decode(base64_message)
    signature = message[:message.find(";")]
    certificate = message[message.find(";")+1:message.find(":")]
    seller_btc_address = message[message.find(":")+1:]
    
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
        if buyer_bitcoin_rpc.verifymessage(seller_btc_address, signature, certificate) != True :
            print ("Failed to verify seller's certificate",end='\r\n')
            cleanup_and_exit()
    except Exception,e:
        print ('Exception while calling verifymessage',e,end='\r\n')
        cleanup_and_exit()
    
    print ('Successfully verified sellers certificate, writing it to disk',end='\r\n')
    with open (os.path.join(installdir, "stunnel","verifiedcert.pem"), "w") as certfile:
        certfile.write(certificate)
        
    

#start processes and return their PIDs for later SIGTERMing
def buyer_start_bitcoind_stunnel_sshpass_dumpcap(skip_capture):
    global pids
    global ppid
    
    if skip_capture == False:
        print ('Starting bitcoind',end='\r\n')
        if os.path.isdir(os.path.join(installdir, 'bitcoind')) == False:
           os.makedirs(os.path.join(installdir, 'bitcoind'))
        if os.path.isdir(os.path.join(installdir, 'bitcoind', 'datadir_buyer')) == False:
           os.makedirs(os.path.join(installdir, 'bitcoind', 'datadir_buyer'))
      
        try:
            #start bitcoind in offline mode
            bitcoind_proc = subprocess.Popen([bitcoind_exepath, '-datadir=' + os.path.join(installdir, 'bitcoind', "datadir_buyer"), '-maxconnections=0', '-server', '-listen=0', '-rpcuser=ssllog_user', '-rpcpassword=ssllog_pswd', '-rpcport=8338'], stdout=open(os.path.join(installdir, 'bitcoind', "bitcoind_buyer.stdout"),'w'), stderr=open(os.path.join(installdir, 'bitcoind', "bitcoind_buyer.stderr"),'w'))
        except:
            print ('Exception starting bitcoind',end='\r\n')
            cleanup_and_exit()
        pids['bitcoind'] = bitcoind_proc.pid
    
    print ('Starting ssh connection',end='\r\n')
    try:
        sshpass_proc = subprocess.Popen([sshpass_exepath, '-p', escrow_ssh_pass, ssh_exepath, escrow_ssh_user+'@'+escrow_host, '-L', '33309:localhost:'+str(escrow_port)], stdout=open(os.devnull,'w'))
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
        #give it a second to create the pid file
        time.sleep(1)
        pidfile = open('/tmp/stunnel.pid', 'r')
        pid = int(pidfile.read().strip())
        pids['stunnel'] = pid
            
        print ('Making a test connection to example.org through the tunnel',end='\r\n')
        #make a test request to see if stunnel setup is working. Two attempts with a 3 sec interval (in case seller hasn't yet caught up with his initialization)
        for i in range(2):
            try:
                response = requests.get("http://example.org", proxies={"http":"http://127.0.0.1:3128"}, timeout=10)
            except Exception,e:
                if i == 0:
                    print ("Can't connect. Sleeping 3 secs and retrying",end='\r\n')
                    time.sleep(3)
                    continue
                else:        
                    print ("Error while making a test connection",e,end='\r\n')
                    cleanup_and_exit()
        if response.status_code != 200:
            print ("Seller returned an invalid response",end='\r\n')
            print (response.text,end='\r\n')
            cleanup_and_exit()
         
        print ('Starting dumpcap in capture mode',end='\r\n')
        try:
            #todo: don't assume that 'lo' is the loopback, query it
            #listen in-between Firefox and stunnel, filter out all the rest of loopback traffic
            dumpcap_proc = subprocess.Popen([dumpcap_exepath, '-i', 'lo', '-f', 'tcp port 3128', '-w', buyer_dumpcap_capture_file ], stdout=open(os.path.join(installdir, 'dumpcap', "dumpcap_buyer.stdout"),'w'), stderr=open(os.path.join(installdir, 'dumpcap', "dumpcap_buyer.stderr"),'w'))
        except Exception,e:
            print ('Exception starting dumpcap',e,end='\r\n')
            cleanup_and_exit()
        pids['dumpcap'] = dumpcap_proc.pid

#use miniHTTP server to receive commands from Firefox addon and respond to them
def buyer_start_minihttp_thread():
    print ('Starting mini http server to communicate with Firefox plugin',end='\r\n')
    try:
        httpd = StoppableHttpServer(('127.0.0.1', 2222), buyer_HandlerClass)
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
        httpd = StoppableHttpServer(('127.0.0.1', 4445), seller_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        cleanup_and_exit()
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    sslhashes = httpd.serve_forever()
    print ('Returning from HTTP server, sslhashes:',sslhashes,end='\r\n')
    #pass retval down to the thread instance
    retval.append(sslhashes)
    
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
    dummy = open (os.path.join(installdir, "capture", 'dummy'), "w+")
    dummy.close()

    #SSLKEYLOGFILE
    sslkeylogfile_path = os.path.join(installdir, 'capture', 'sslkeylog')
    os.putenv("SSLKEYLOGFILE", sslkeylogfile_path)
    #TMP is where the html files are going to be saved
    os.putenv("TMP", os.path.join(installdir, 'htmldir'))
    print ("Starting a new instance of Firefox with a new profile",end='\r\n')
    try:
        subprocess.Popen([firefox_exepath,'-new-instance', '-P', 'ssllog'], stdout=open(os.path.join(installdir, 'firefox', "firefox.stdout"),'w'), stderr=open(os.path.join(installdir, 'firefox', "firefox.stderr")))
    except Exception,e:
        print ("Error starting Firefox", e,end='\r\n')
        cleanup_and_exit()
    

#the tempdir contains html files as well as folders with js,png,css. Ignore the folders
def buyer_get_htmlhashes():
    print ("Hashing the saved html file",end='\r\n')
    onlyfiles = [f for f in os.listdir(htmldir) if os.path.isfile(os.path.join(htmldir,f))]
    if len(onlyfiles) == 0:
        print ('No HTML files have been found in htmldir',end='\r\n')
        cleanup_and_exit()
    htmlhashes = []
    for file in onlyfiles:
        htmlhashes.append(hashlib.md5(open(os.path.join(htmldir, file), 'r').read()).hexdigest())
    return htmlhashes

#Find the frame which contains the html hash and return the frame's SSL part hash
def buyer_get_sslhashes(capturefile, htmlhashes):
    sslhashes = []
    for htmlhash in htmlhashes:
        if htmlhash == '':
            print ('empty hash provided. Please investigate',end='\r\n')
            cleanup_and_exit()
        #get frame numbers of all http responses that came from the bank
        try:
            frames_str = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'ssl and http.content_type contains html', '-T', 'fields', '-e', 'frame.number', '-o', 'ssl.keylog_file: '+sslkeylogfile])
        except Exception,e:
            print ('Error starting tshark', e,end='\r\n')
            cleanup_and_exit()
        frames_str = frames_str.rstrip()
        frames = frames_str.split('\n')
        if frames == ['']:
            print ('No HTML pages found in the capture file',end='\r\n')
            cleanup_and_exit()
        print ("Finding SSL segments corresponding to the saved html files",end='\r\n')
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
            md5hash = get_htmlhash_from_asciidump(ascii_dump)
            if md5hash == 0:
                print ("Expected to find HTML, but non found in frame " + str(frame) + " Please investigate",end='\r\n')
                continue
            if htmlhash == md5hash:
                found_frame = frame
                print ("found matching SSL segment in frame No " + frame,end='\r\n')
                break
        if not found_frame:            
            print ("Couldn't find an SSL segment containing html hash provided",end='\r\n')
            return 0
            
        #collect other possible SSL segments which are part of HTML page. 
        segments = [found_frame]
        try:
            segments_str =  subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'frame.number==' + found_frame, '-T', 'fields', '-e', 'ssl.segment', '-o', 'ssl.keylog_file: '+sslkeylogfile])
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
                
                                         
        # For good measure tell the seller to remove any packets containing HTTP POST requests
        # This way we guarantee that no login credentials will ever get accidentally submitted to escrow
                       
        try:
            post_requests_str = subprocess.check_output([tshark_exepath, '-r', capturefile, '-Y', 'ssl and tcp.stream=='+tcpstreams[0]+' and http.request.method==POST', '-T', 'fields', '-e', 'frame.number'])
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
                frames_ssl_hex = frame_ssl_hex.rstrip()
                frames_ssl_hex = frames_ssl_hex.split('\n')
                for frame_hex in frames_ssl_hex:
                    #get rid of commas and colons
                    #(ssl.app_data comma-delimits multiple SSL segments within the same frame)
                    frame_hex = frame_hex.replace(',',' ')
                    frame_hex = frame_hex.replace(':',' ')
                    if frame_hex == ' ':
                        print ('empty frame hex. Please investigate',end='\r\n')
                        cleanup_and_exit()
                    sslhashes.append(hashlib.md5(bytearray.fromhex(frame_hex)).hexdigest())
    
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

    #We are interested in "Uncompressed entity body" in case of compressed HTML. If not present, then
    #the very last entry of "De-chunked entity body" in case on uncompressed chunked HTML. If not present, then
    #the very last entry of "Reassembled SSL" in case of uncompressed unchunked segmented HTML (very rare)
    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                m_array = bytearray.fromhex(line[6:54])
                binary_html += m_array
            else:
                break          
    else:
        dechunked_pos = ascii_dump.rfind('De-chunked entity body')
        if dechunked_pos != -1:     
            for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
                #convert ascii representation of hex into binary
                #only deal with lines where first 4 chars are hexdigits
                if all(c in hexdigits for c in line [:4]):
                    m_array = bytearray.fromhex(line[6:54])
                    binary_html += m_array
                else:
                    break
        else:
            reassembled_pos = ascii_dump.rfind('Reassembled SSL')
            if reassembled_pos != -1:     
                #skip the HTTP header and find where the HTTP body starts
                body_start = reassembled_pos + ascii_dump[reassembled_pos:].find('0d 0a 0d 0a')
                if body_start == -1:
                    print ('Could not find HTTP body',end='\r\n')
                    cleanup_and_exit()
                    return
                lines = ascii_dump[body_start+len('0d 0a 0d 0a'):].split('\n')
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
            else:
                #example.org's response going through squid ends up as ungzipped, unchunked HTML
                page_end = ascii_dump.rfind('.\n\n')
                if page_end == -1:
                    print ("Could not find page's end",end='\r\n')
                    return 0
                page_start = ascii_dump.rfind('0d 0a 0d 0a')
                if page_start == -1:
                    print ("Could not find page's start",end='\r\n')
                    return 0
                if page_end < page_start:
                    print ("Could not find HTML page",end='\r\n')
                    return 0
                lines = ascii_dump[page_start+len('0d 0a 0d 0a'):page_end+len('.\n\n')].split('\n')
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
    return hashlib.md5(binary_html3).hexdigest()
   
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
    capturedir = os.path.join(installdir, 'capture')
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
        print ('Please provide one of the arguments: "buyer" or "seller" and optional "skip"',end='\r\n')
        exit()
    role = sys.argv[1]
    if role != 'buyer' and role != 'seller':
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
            #wait for minihttp server shutdown. Means that user has finished the SSL session
            while thread.isAlive():
               time.sleep(2)
            print ("User has finished the SSL session",end='\r\n')
            #todo: inform the seller at this stage that we are finished with the SSL session
            print ("Terminating dumpcap",end='\r\n')
            os.kill(pids['dumpcap'], signal.SIGTERM)
            pids.pop('dumpcap')
            
        htmlhashes = buyer_get_htmlhashes()
        sslhashes = buyer_get_sslhashes(buyer_dumpcap_capture_file, htmlhashes)
        if sslhashes == 0:
            #Rearrange out-of-order frames
            rearranged_buyer_dumpcap_capture_file = rearrange_outoforder_frames(buyer_dumpcap_capture_file)
            sslhashes = buyer_get_sslhashes(rearranged_buyer_dumpcap_capture_file, htmlhashes)
            if sslhashes == 0:
                print ("Still couldn't find HTML hash after rearranging the frames",end='\r\n')
                cleanup_and_exit()
            else:
                #make sure the escrow knows that the capture was rearranged
                sslhashes.insert(0,'rearranged')
        buyer_send_sslhashes(sslhashes)
        buyer_send_sslkeylogfile()
        
        if skip_capture == False:
            print ("Terminating sshpass and stunnel",end='\r\n')
            os.kill(pids['sshpass'], signal.SIGTERM)
            os.kill(pids['stunnel'], signal.SIGTERM)
            pids.pop('sshpass')
            pids.pop('stunnel')
        
    elif role == 'seller':
        #global pids
        seller_start_bitcoind_stunnel_sshpass_dumpcap_squid(skip_capture)
        
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
        print ('Thread returned:', retval,end='\r\n')
            
        hashes = [hash for hash in retval[0].split(';') if len(hash)>0]
        send_logs_to_escrow(hashes)
        