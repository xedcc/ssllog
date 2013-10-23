from __future__ import print_function

import base64
import BaseHTTPServer
import hashlib
import os
import random
import re
import select
import shutil
import signal
import SimpleHTTPServer
import subprocess
import sys
import tarfile
import threading
import time
from Tkinter import *
import urllib2
from xml.dom import minidom

TESTING = True
#ALPHA_TESTING means the users have to enter accno and sum themselves via FF addon
ALPHA_TESTING = True


installdir = os.path.dirname(os.path.realpath(__file__))
logdir = os.path.join(installdir, 'stcppipelogs')
sslkeylog = os.path.join(installdir, 'sslkeylog')
sslkey = os.path.join(installdir, 'sslkey')
stcppipe_exepath = os.path.join(installdir, 'oracle','stcppipe')
firefox_exepath = '/home/default2/Desktop/firefox-nightly/firefox'
ssh_exepath = 'ssh'
ssh_logfile = os.path.join(installdir, 'ssh.log')
#ssh_exepath = os.path.join(installdir, 'putty')
random_ssh_port = 0
#random TCP port on which firefox extension communicates with python backend
FF_to_backend_port = 0
#random port which FF uses as proxy port. Stcppipe listens on this port
FF_proxy_port = 0
oracle_snapID ='snap-f2596bf0'

accno = None
sum_ = None
stcppipe_proc = ssh_proc = None
html_hash = None
assigned_port = None
#username = "ubuntu"
username = "ubuntu"
is_ff_started = False
is_tk_destroyed = False

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
    
#handle only paths we are interested and let python handle the response headers
#class "object" is needed to access super()
class buyer_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"      
    
    #Firefox addon speaks with HEAD
    def do_HEAD(self):
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        # example HEAD string "/page_marked?accno=12435678&sum=1234.56"        
        if self.path.startswith('/page_marked'):
            if ALPHA_TESTING:
                params = []
                for param_str in self.path.split('?')[1].split('&'):
                    paralist = param_str.split('=')
                    params.append({paralist[0]:paralist[1]})
                global accno
                global sum_
                accno = params[0]['accno']
                sum_ = params[1]['sum']           
            result = find_page(accno, sum_)
            if result[0] != 'success':
                print ('sending failure. Reason: '+result[0] ,end='\r\n')
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "failure")
                self.end_headers()
                self.server.retval = 'failure'
                self.server.stop = True
                return
            #else
            filename, frames_no = result[1:3]
            if is_clear_cache_needed(filename, frames_no):    
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "clear_ssl_cache")
                print ('sending clear_ssl_cache',end='\r\n')
                self.end_headers()
                return
            #else
            retval = extract_ssl_key(filename)
            if retval != 'success':
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "failure")
                self.end_headers()
                self.server.retval = 'failure'
                self.server.stop = True
                return
            if retval == 'success':
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "success")
                self.end_headers()
                self.server.retval = 'success'
                self.server.stop = True
                return            

        if self.path.startswith('/check_oracle'):
            base64str = self.path.split('?')[1]
            arg_str = base64.b64decode(base64str)
            args = arg_str.split()
            if not TESTING:
                retval = check_oracle_urls(*args)
            else:
                retval = "success"
            self.send_response(200)
            self.send_header("response", "check_oracle")
            self.send_header("value", retval)
            self.end_headers()
            return
            
        if self.path.startswith('/start_tunnel'):
            arg_str = self.path.split('?')[1]
            args = arg_str.split(";")
            if ALPHA_TESTING:
                key_name = "alphatest.key"
            global assigned_port
            assigned_port = args[1]
            retval = start_tunnel(key_name, args[0])
            if retval == 'reconnect':
                print ('Reconnecting to sshd', end='\r\n')
                retval = start_tunnel(key_name, args[0])
            if retval != 'success':
                print ('Error while setting up a tunnel: '+retval, end='\r\n')
            self.send_response(200)
            self.send_header("response", "start_tunnel")
            self.send_header("value", retval)
            self.end_headers()
            return
        
            #ALPHA only, request the tarball from oracle; check whether escrow would also decrypt HTML            
        if self.path.startswith('/check_escrowtrace'):  
            result = decrypt_escrowtrace()
            if result == "success":    
                self.send_response(200)
                self.send_header("response", "check_escrowtrace")
                self.send_header("value", "success")
                print ('sending success',end='\r\n')
                self.end_headers()
                self.server.retval = 'success'
                self.server.stop = True
                return
            else:
                self.send_response(200)
                self.send_header("response", "check_escrowtrace")
                self.send_header("value", "failure")
                print ('sending failure',end='\r\n')
                self.end_headers()
                self.server.retval = 'failure'
                self.server.stop = True
                return     
        
        if self.path.startswith('/terminate'):
            global ssh_proc
            ssh_proc.stdin.write('exit\n')
            self.send_response(200)
            self.send_header("response", "terminate")
            self.send_header("value", "success")
            self.end_headers()
            return      
            
        if self.path.startswith('/started'):
            global is_ff_started
            is_ff_started = True
            self.send_response(200)
            self.send_header("response", "started")
            self.send_header("value", "success")
            self.end_headers()
            return                
    
#ALPHA only - fetch the tarball; make sure HTML decrypts
def decrypt_escrowtrace():
    global ssh_proc
    global random_ssh_port
    global assigned_port
    global html_hash
    escrowtracedir = os.path.join(installdir, "escrowtrace")
    ssh_proc.stdin.write('sslkey \n')
    #give oracle some time to launch an httpd
    time.sleep(5)
    #send request to ssh's local forwarding port
    try:
        oracle_url = urllib2.urlopen("http://127.0.0.1:"+str(random_ssh_port)+"/the/name/doesnt/matter/because/the/oracle/will/serve/the/correct/file/anyway", timeout=30)
    except:
        ssh_proc.stdin.write('exit failure\n')    
        return "Failed to fetch tarball from oracle"
    data = oracle_url.read()
    tarball = open(os.path.join(installdir, "escrowtrace.tar"), 'w')
    tarball.write(data)
    tarball.close()
    if os.path.isdir(escrowtracedir): shutil.rmtree(escrowtracedir)
    os.mkdir(escrowtracedir)
    tar_object = tarfile.open(os.path.join(installdir, "escrowtrace.tar"))
    tar_object.extractall(escrowtracedir)
    tar_object.close()
    
    filelist = os.listdir(escrowtracedir)
    mergecap_args = ['mergecap', '-w', 'merged'] + filelist
    #it was observed that mergecap may return before the output file was written entirely. We must give the OS some time to flush everything to disk:
    time.sleep(1)
    subprocess.call(mergecap_args, cwd=escrowtracedir)
    output = subprocess.check_output(['tshark', '-r', os.path.join(escrowtracedir, 'merged'), '-Y', 'ssl and http.content_type contains html', '-o', 'ssl.keylog_file:'+ sslkey, '-o',  'http.ssl.port:3128', '-x'])
    if output == '': 
        ssh_proc.stdin.write('exit failure\n')    
        return "Failed to find HTML in escrowtrace"
    html = get_html_from_asciidump(output)
    if html == -1:
        ssh_proc.stdin.write('exit failure\n')            
        return "Failed to find HTML in ascii dump"
    if html_hash != hashlib.md5(html).hexdigest() :
        ssh_proc.stdin.write('exit failure\n')            
        return "Escrowtrace's HTML doesn't match ours"
    
    ssh_proc.stdin.write('exit success\n')    
    return "success"
    
    
    
    
    

#look at tshark's ascii dump to better understand the parsing taking place
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
                m_array = bytearray.fromhex(line[6:54])
                binary_html += m_array
            else:
                break
        return binary_html
    
    #else      
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
        return binary_html
            
    #else
    reassembled_pos = ascii_dump.rfind('Reassembled SSL')
    if reassembled_pos != -1:
        for line in ascii_dump[reassembled_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary
            #only deal with lines where first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                m_array = bytearray.fromhex(line[6:54])
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
            #convert ascii representation of hex into binary
            #only deal with lines where first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                m_array = bytearray.fromhex(line[6:54])
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]
   
    

def find_page(accno, amount):
    global random_ssh_port
    global html_hash
    filelist = os.listdir(logdir)
    timestamps = []
    for f in filelist:
        timestamps.append([f, os.path.getmtime(os.path.join(logdir, f))])
    timestamps.sort(key=lambda x: x[1], reverse=True)
    
    print ('Total number of files to process:'+str(len(timestamps)), end='\r\n')
    for index, timestamp in enumerate(timestamps):
        print ('Processing file No:'+str(index), end='\r\n')
        filename = timestamp[0]
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.content_type contains html', '-o', 'ssl.keylog_file:'+ sslkeylog, '-o', 'http.ssl.port:'+str(random_ssh_port), '-x'])
        if output == '': continue
        #multiple frames are dumped ascendingly. Process from the latest to the earlier.
        frames = output.split('\n\nFrame (')
        #the first element contains an empty string after splitting
        if len(frames) > 2: frames.pop(0)
        frames.reverse()
        for frame in frames:
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
            html_hash = hashlib.md5(html).hexdigest()
            return ['success', filename, len(frames)]
    return ['Data not found in HTML']


#make sure there is no unwanted data (other HTML or POSTs) in that file/TCP stream
def is_clear_cache_needed(filename, frames_no):
    if frames_no > 1:
        print ('Extra HTML file found in the TCP stream', end='\r\n')
        return True
    output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.request.method==POST', '-o', 'ssl.keylog_file:'+ sslkeylog, '-o', 'http.ssl.port:'+str(random_ssh_port)])
    if output != '':
        print ('POST request found in the TCP stream', end='\r\n')
        return True
    return False


def extract_ssl_key(filename):
    #find the key which decrypts out tcp stream
    sslkey_fd = open(sslkeylog, 'r')
    keys_data = sslkey_fd.read()
    sslkey_fd.close()
    keys = keys_data.rstrip().split('\n')
    keys.reverse()
    print ('SSL keys needed to be processed:' + str(len(keys)), end='\r\n')
    for index,key in enumerate(keys):
        print ('Processing key number:' + str(index), end='\r\n')
        if not key.startswith('CLIENT_RANDOM'): continue
        tmpkey_fd = open(sslkey, 'w')
        tmpkey_fd.write(key+'\n')
        tmpkey_fd.flush()
        tmpkey_fd.close()
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.content_type contains html', '-o', 'ssl.keylog_file:'+ sslkey, '-o', 'http.ssl.port:'+str(random_ssh_port)])
        if output == '': continue        
        #else key found
        
        #For the user's peace of mind make sure no other streams can be decrypted with this key. We already know it can't be :)
        #merge all files sans our file and check against the key
        filelist = os.listdir(logdir)
        filelist.remove(filename)
        mergecap_args = ['mergecap', '-w', 'merged'] + filelist
        subprocess.call(mergecap_args, cwd=logdir)
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, 'merged'), '-Y', 'ssl and http', '-o', 'ssl.keylog_file:'+ sslkey, '-o',  'http.ssl.port:'+str(random_ssh_port)])
        if output != '':
            print ('The unthinkable happened. Our ssl key can decrypt another tcp stream', end='\r\n')
            exit(4)
            
        print ('SUCCESS unique ssl key found', end='\r\n')
        return 'success'
        
    print ('FAILURE could not find ssl key', end='\r\n')
    return 'FAILURE could not find ssl key'
    
    
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
    #after the server was stopped
    parentthread.retval = retval


def start_firefox():
    global FF_to_backend_port    
    #we could ask user to run Firefox with -ProfileManager and create a new profile themselves
    #but to be as user-friendly as possible, we add a new Firefox profile behind the scenes
    
    homedir = os.path.expanduser("~")
    if homedir == "~":
        print ("Couldn't find user's home directory",end='\r\n')
        return "Couldn't find user's home directory"
    #todo allow user to specify firefox profile dir manually 
    ff_user_dir = os.path.join(homedir, ".mozilla", "firefox")   
    # skip this step if "ssllog" profile already exists
    if (not os.path.isdir(os.path.join(ff_user_dir, "ssllog_profile"))):
        print ("Copying plugin files into Firefox's plugin directory",end='\r\n')
       
        try:
            inifile = open(os.path.join(ff_user_dir, "profiles.ini"), "r+")
        except Exception,e: 
            print ('Could not open profiles.ini. Make sure it exists and you have sufficient read/write permissions',e,end='\r\n')
            return 'Could not open profiles.ini'
        text = inifile.read()
   
        #get the last profile number and increase it by 1 for our profile
        our_profile_number = int(text[text.rfind("[Profile")+len("[Profile"):].split("]")[0]) +1
    
        try:
            inifile.seek(0, os.SEEK_END)
            inifile.write('[Profile' +str(our_profile_number) + ']\nName=ssllog\nIsRelative=1\nPath=ssllog_profile\n\n')
        except Exception,e:
            print ('Could not write to profiles.ini. Make sure you have sufficient write permissions',e,end='\r\n')
            return 'Could not write to profiles.ini'
        inifile.close()
    
        #create an extension dir and copy the extension files
        #we are not distributing our extension as xpi, but rather as a directory with files
        os.mkdir(os.path.join(ff_user_dir, 'ssllog_profile'))
        ff_extensions_dir = os.path.join(ff_user_dir, "ssllog_profile", "extensions")
        os.mkdir(ff_extensions_dir)
        #todo handle mkdir exception
        
        try:
            mfile = open (os.path.join(ff_extensions_dir, "lspnr@lspnr.net"), "w+")
        except Exception,e:
            print ('File open error', e,end='\r\n')
            return 'File open error'
        
        #write the path into the file
        try:
            mfile.write(os.path.join(installdir,"FF-addon"))
        except Exception,e:
            print ('File write error', e,end='\r\n')
            return 'File write error'
        mfile.close()
        
        #prevent FF from prompting the user to install extenxion
        try:
            mfile = open (os.path.join(ff_user_dir, 'ssllog_profile', 'extensions.ini'), "w+")
        except Exception,e:
            print ('File open error', e,end='\r\n')
            return 'File open error' 
        mfile.write("[ExtensionDirs]\nExtension0=" + os.path.join(installdir,"FF-addon") + "\n")
        mfile.close()
        
        #force displaying of add-on toolbar
        try:
            mfile = open (os.path.join(ff_user_dir, 'ssllog_profile', 'localstore.rdf'), "w+")
        except Exception,e:
            print ('File open error', e,end='\r\n')
            return 'File open error' 
        mfile.write(r'<?xml version="1.0"?><RDF:RDF xmlns:NC="http://home.netscape.com/NC-rdf#" xmlns:RDF="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><RDF:Description RDF:about="chrome://browser/content/browser.xul"><NC:persist RDF:resource="chrome://browser/content/browser.xul#addon-bar" collapsed="false"/></RDF:Description></RDF:RDF>')
        mfile.close()        
        

    #SSLKEYLOGFILE
    os.putenv("SSLKEYLOGFILE", sslkeylog)
    os.putenv("FF_to_backend_port", str(FF_to_backend_port))
    os.putenv("FF_proxy_port", str(FF_proxy_port))
    
    print ("Starting a new instance of Firefox with a new profile",end='\r\n')
    try:
        subprocess.Popen([firefox_exepath,'-new-instance', '-P', 'ssllog'], stdout=open(os.path.join(installdir, 'firefox', "firefox.stdout"),'w'), stderr=open(os.path.join(installdir, 'firefox', "firefox.stderr"), 'w'))
    except Exception,e:
        print ("Error starting Firefox", e,end='\r\n')
        return "Error starting Firefox"
    
    return 'success'


#using AWS query API make sure oracle meets the criteria
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
            if one_dns_name.firstChild.data != oracle_dns:
                continue
            is_dns_found = True
            break
        if not is_dns_found:
            return 'bad oracle'
        instance = one_dns_name.parentNode
    
        if instance.getElementsByTagName('imageId')[0].firstChild.data != 'ami-d0f89fb9' or\
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
    
        if volume.getElementsByTagName('snapshotId')[0].firstChild.data != oracle_snapID or\
        volume.getElementsByTagName('status')[0].firstChild.data != 'in-use' or\
        volume.getElementsByTagName('volumeType')[0].firstChild.data != 'standard':
            return 'bad oracle'
        createTime = volume.getElementsByTagName('createTime')[0].firstChild.data
        
        attached_volume = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item')[0]
        if attached_volume.getElementsByTagName('volumeId')[0].firstChild.data != instance_volumeId or\
        attached_volume.getElementsByTagName('instanceId')[0].firstChild.data != instanceId or\
        attached_volume.getElementsByTagName('device')[0].firstChild.data != '/dev/sda2' or\
        attached_volume.getElementsByTagName('status')[0].firstChild.data != 'attached' or\
        attached_volume.getElementsByTagName('attachTime')[0].firstChild.data != attachTime or\
        attached_volume.getElementsByTagName('attachTime')[0].firstChild.data != createTime:
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
                    print ('Too many volumes or instances detected')
                    #return 'bad oracle'
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

#privkey_file should correspond to RSA public key registered on oracle
#assigned_port should be provided by the escrow
def start_tunnel(privkey_file, oracle_address):
    global assigned_port
    global stcppipe_proc
    global ssh_proc
    global username
    global FF_proxy_port
    
    if os.path.isdir(logdir) : shutil.rmtree(logdir)
    os.mkdir(logdir)
    
    global random_ssh_port
    random_ssh_port = random.randint(1025,65535)
    stcppipe_proc = subprocess.Popen([stcppipe_exepath, '-d', logdir, '-b', '127.0.0.1', str(random_ssh_port), str(FF_proxy_port)])
    time.sleep(1)
    if stcppipe_proc.poll() != None:
        return 'stcppipe error'
    ssh_proc = subprocess.Popen([ssh_exepath, '-i', os.path.join(installdir, 'alphatest.key'), '-o', 'StrictHostKeyChecking=no', username+'@'+oracle_address, '-L', str(random_ssh_port)+':localhost:'+assigned_port], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    
    #give sshd 20 secs to respond with 'Tunnel ready'
    waiting_started = time.time()
    sshlog_fd = open(ssh_logfile, 'w')
    while 1:
        rlist = []
        rlist = select.select([ssh_proc.stderr],[],[], 1)[0]
        if len(rlist) > 0 and ssh_proc.stderr not in rlist:
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            sshlog_fd.close()            
            return 'select() error'           
        if time.time() - waiting_started > 20:
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            sshlog_fd.close()
            return 'sshd was taking too long to respond'        
        if ssh_proc.poll() != None:
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            sshlog_fd.close()                
            return 'ssh exited abruptly'
        if len(rlist) == 0:
            continue
        cmd = ssh_proc.stderr.readline()
        if not cmd: continue        
        sshlog_fd.write(cmd+'\n')
        sshlog_fd.flush()
        if cmd.startswith('Session finished. Please reconnect and use port '):
            newport = cmd[len('Session finished. Please reconnect and use port '):].split()[0]
            if len(newport) < 4 or len(newport)>5:
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                sshlog_fd.close()                
                return 'newport length error'
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            sshlog_fd.close()
            assigned_port = newport
            return 'reconnect'
        if cmd.startswith('Session finished.'): 
            os.kill(stcppipe_proc.pid, signal.SIGTERM)            
            sshlog_fd.close()            
            return 'session finished'
        if cmd.startswith('Tunnel ready'): 
            sshlog_fd.close()
            return 'success'
    
    



if __name__ == "__main__":
    #if len(sys.argv) != 11:
        #print("\n")
        #print ("10 arguments expected separated by a space in this sequence:")
        #print ("GetUserURL, ListMetricsURL, DescribeInstancesURL, DescribeVolumesURL, GetConsoleOutputURL")
        #print ("oracle DNS, private key file, assigned port, account number, sum")
        #print("\n")
        #exit(1)
    #GetUserURL = sys.argv[1]
    #ListMetricsURL = sys.argv[2]
    #DescribeInstancesURL= sys.argv[3]
    #DescribeVolumesURL= sys.argv[4]
    #GetConsoleOutputURL= sys.argv[5]
    #oracle_address= sys.argv[6]
    #privkey= sys.argv[7]
    #assigned_port= sys.argv[8]
   
    #accno= sys.argv[9]
    #sum_= sys.argv[10]
    
    #check_result = check_oracle_urls(GetUserURL, ListMetricsURL, DescribeInstancesURL, DescribeVolumesURL, GetConsoleOutputURL, oracle_dns)
    #if check_result != 'success':
        #print ('Error checking oracle: '+check_result)
        #exit(1)
    
    #show small dialog. It will go away as soon as addon sends "started" signal to backend
    tkwindow = Tk()    
    w = Label(tkwindow, text="Paysty is initializing...")
    w.pack()
    tkwindow.after(100, tkwindow.quit)    
    tkwindow.mainloop() 
    
    FF_to_backend_port = random.randint(1025,65535)
    FF_proxy_port = random.randint(1025,65535)

    thread = ThreadWithRetval(target= buyer_start_minihttp_thread)
    thread.daemon = True
    thread.start()
  
    ff_retval = start_firefox()
    if ff_retval != 'success':
        os.kill(stcppipe_proc.pid, signal.SIGTERM)
        ssh_proc.stdin.write('exit\n')
        print ('Error while starting Firefox: '+ff_retval, end='\r\n')
        exit(1)
    
    while True:
        if (is_ff_started and not is_tk_destroyed):
            tkwindow.destroy()
            is_tk_destroyed = True
        thread.join(1)
        if not thread.isAlive():
            break

    #we get here when thread terminates    
    
    #commented out for ALPHA
    #if thread.retval == 'failure':
        #print ("Could not decrypt HTML locally", end='\r\n')
        #ssh_proc.stdin.write('exit\n')
        #exit(1)  
        
    #elif thread.retval != 'success':
        #print ("Internal error. Thread returned unknown value", end='\r\n')
        #ssh_proc.stdin.write('exit\n')
        #exit(1)
    
    #sslkey_fd = open(sslkey, 'r')
    #key_data = sslkey_fd.read()
    #sslkey_fd.close()
    #ssh_proc.stdin.write('sslkey '+key_data+'\n')
    #exit(0)
    

    