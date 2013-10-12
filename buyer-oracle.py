from __future__ import print_function

import os
import subprocess
import sys
import BaseHTTPServer, SimpleHTTPServer
import threading
import urllib
from xml.dom import minidom
import base64

logdir = '/home/default2/Desktop/sslxchange/oracle/logs'
sslkeylog = '/home/default2/Desktop/sslkeylog'
buyer_http_port = 2222
oracle_snapID ='snap-1a8f0718'

ALPHA_TESTING = True
accno = None
sum_ = None

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
#class "object" in needed to access super()
class buyer_HandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler, object):
    protocol_version = "HTTP/1.1"      
    
    #Firefox addon speaks with HEAD
    def do_HEAD(self):
        print ('minihttp received ' + self.path + ' request',end='\r\n')
        if self.path.startswith('/page_marked'):
            if ALPHA_TESTING:
                # example HEAD string "/page_marked?accno=12435678&sum=1234.56"
                params = []
                for param_str in self.path.split('?')[1].split('&'):
                    paralist = param_str.split('=')
                    params.append({paralist[0]:paralist[1]})
                global accno
                global sum_
                accno = params[0]['accno']
                sum_ = params[1]['sum']
            
            result = find_page(accno, sum_)
            if result == False:
                print ('sending failure',end='\r\n')
                self.send_response(200)
                self.send_header("response", "page_marked")
                self.send_header("value", "failure")
                super(buyer_HandlerClass, self).do_HEAD()
            else:
                filename, frames_no = result
                if is_clear_cache_needed(filename, frames_no):    
                    self.send_response(200)
                    self.send_header("response", "page_marked")
                    self.send_header("value", "clear_ssl_cache")
                    print ('sending clear_ssl_cache',end='\r\n')
                    super(buyer_HandlerClass, self).do_HEAD()
                else:
                    self.send_response(200)
                    self.send_header("response", "page_marked")
                    self.send_header("value", "success")
                    print ('sending success',end='\r\n')
                    super(buyer_HandlerClass, self).do_HEAD()
                    extract_ssl_key(filename)
             
        elif self.path == '/tempdir':
            self.send_response(200)
            self.send_header("response", "tempdir")
            self.send_header("value", os.path.join(installdir, 'firefox', 'dummy'))
            super(buyer_HandlerClass, self).do_HEAD()
            
            

#look at tshark's ascii dump to better understand the parsing taking place
def get_html_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        return 1

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
   
    

def find_page(accno=None, amount=None):
    filelist = os.listdir(logdir)
    timestamps = []
    for f in filelist:
        timestamps.append([f, os.path.getmtime(os.path.join(logdir, f))])
    timestamps.sort(key=lambda x: x[1], reverse=True)
    
    print ('Total number of files to process:'+str(len(timestamps)), end='\r\n')
    for index, timestamp in enumerate(timestamps):
        print ('Processing file No:'+str(index), end='\r\n')
        filename = timestamp[0]
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.content_type contains html', '-o', 'ssl.keylog_file:'+ sslkeylog, '-x'])
        if output == '': continue
        #multiple frames are dumped ascendingly. Process from the latest to the earlier.
        frames = output.split('\n\nFrame (')
        #the first element contains an empty string after splitting
        if len(frames) > 2: frames.pop(0)
        frames.reverse()
        for frame in frames:
            html = get_html_from_asciidump(frame)
            if html == -1:
                print ('Error processing ascii dump if file:'+filename, end='\r\n')
                return False
            if html.find(accno) == -1:
                print ('Accno not found in HTML', end='\r\n')
                continue
            if html.find(amount) == -1:
                print ('Amount not found in HTML', end='\r\n')
                continue
            return filename, len(frames)
    return False

#make sure there is no unwanted data (other HTML or POSTs) in that file/TCP stream
def is_clear_cache_needed(filename, frames_no):
    if frames_no > 1:
        print ('Extra HTML file found in the TCP stream', end='\r\n')
        return True
    output = output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.request.method==POST', '-o', 'ssl.keylog_file:'+ sslkeylog])
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
    tmpkey_path = os.path.join(logdir, 'tmpkey')
    print ('SSL keys needed to be processed:' + str(len(keys)), end='\r\n')
    for index,key in enumerate(keys):
        print ('Processing key number:' + str(index), end='\r\n')
        if not key.startswith('CLIENT_RANDOM'): continue
        tmpkey_fd = open(tmpkey_path, 'w')
        tmpkey_fd.write(key+'\n')
        tmpkey_fd.flush()
        tmpkey_fd.close()
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, filename), '-Y', 'ssl and http.content_type contains html', '-o', 'ssl.keylog_file:'+ tmpkey_path])
        if output == '': continue        
        #else key found
        
        #For the user's peace of mind make sure no other streams can be decrypted with this key. We already know it can't be :)
        #merge all files sans our file and check against the key
        filelist = os.listdir(logdir)
        filelist.remove(filename)
        filelist.remove('tmpkey')
        mergecap_args = ['mergecap', '-w', 'merged'] + filelist
        subprocess.call(mergecap_args, cwd=logdir)
        output = subprocess.check_output(['tshark', '-r', os.path.join(logdir, 'merged'), '-Y', 'ssl and http', '-o', 'ssl.keylog_file:'+ tmpkey_path])
        if output != '':
            print ('The unthinkable happened. Our ssl key can decrypt another tcp stream', end='\r\n')
            exit(4)
            
        print ('SUCCESS unique ssl key found', end='\r\n')
        return True
        
    print ('FAILURE could not find ssl key ', end='\r\n')
    return False
    
    
#use miniHTTP server to receive commands from Firefox addon and respond to them
def buyer_start_minihttp_thread():
    print ('Starting mini http server to communicate with Firefox plugin',end='\r\n')
    try:
        httpd = StoppableHttpServer(('127.0.0.1', buyer_http_port), buyer_HandlerClass)
    except Exception, e:
        print ('Error starting mini http server', e,end='\r\n')
        #cleanup_and_exit()
    sa = httpd.socket.getsockname()
    print ("Serving HTTP on", sa[0], "port", sa[1], "...",end='\r\n')
    httpd.serve_forever()

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

#using AWS query API make sure oracle meets the criteria
def check_oracle_urls (DescribeInstancesURL, DescribeVolumesURL, GetConsoleOutputURL, oracle_dns):
    try:
        di_url = urllib.urlopen(DescribeInstancesURL)
        di_xml = di_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return -2
    try:
        di_dom = minidom.parseString(di_xml)
    except Exception,e:
        print(e, end='\r\n')
        return -3
    
    is_dns_found = False
    dns_names = di_dom.getElementsByTagName('dnsName')
    for one_dns_name in dns_names:
        if one_dns_name.firstChild.data != oracle_dns:
            continue
        is_dns_found = True
        break
    if not is_dns_found:
        return -1
    instance = one_dns_name.parentNode
    
    if instance.getElementsByTagName('imageId')[0].firstChild.data != 'ami-d0f89fb9' or
    instance.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].firstChild.data != 'running' or
    instance.getElementsByTagName('rootDeviceName')[0].firstChild.data != '/dev/sda1':
        return -1
    launchTime = instance.getElementsByTagName('launchTime')[0].firstChild.data
    instanceId = instance.getElementsByTagName('instanceId')[0].firstChild.data
    
    volumes = instance.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item')
    if len(volumes) > 1: return -1
    if volumes[0].getElementsByTagName('deviceName')[0].firstChild.data != '/dev/sda2': return -1
    if volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].firstChild.data != 'attached': return -1
    instance_volumeId = volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].firstChild.data
    attachTime = volumes[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].firstChild.data
    
    try:
        dv_url = urllib.urlopen(DescribeVolumesURL)
        dv_xml = dv_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return -2
    try:
        dv_dom = minidom.parseString(dv_xml)
    except Exception,e:
        print(e, end='\r\n')
        return -3
    
    is_volumeID_found = False
    volume_IDs = dv_dom.getElementsByTagName('volumeId')
    for one_volume_ID in volume_IDs:
        if one_volume_ID.firstChild.data != instance_volumeId:
            continue
        is_volumeID_found = True
        break
    if not is_volumeID_found:
        return -1
    volume = one_volume_ID.parentNode
    
    if volume.getElementsByTagName('snapshotId')[0].firstChild.data != oracle_snapID or
    volume.getElementsByTagName('status')[0].firstChild.data != 'in-use' or
    volume.getElementsByTagName('volumeType')[0].firstChild.data != 'standard':
        return -1
    createTime = volume.getElementsByTagName('createTime')[0].firstChild.data
    
    attached_volume = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item')[0]
    if attached_volume.getElementsByTagName('volumeId')[0].firstChild.data != instance_volumeId or
    attached_volume.getElementsByTagName('instanceId')[0].firstChild.data != instanceId or
    attached_volume.getElementsByTagName('device')[0].firstChild.data != '/dev/sda2' or
    attached_volume.getElementsByTagName('status')[0].firstChild.data != 'attached' or
    attached_volume.getElementsByTagName('attachTime')[0].firstChild.data != attachTime or
    attached_volume.getElementsByTagName('attachTime')[0].firstChild.data != createTime:
        return -1
    
    try:
        gco_url = urllib.urlopen(GetConsoleOutputURL)
        gco_xml = gco_url.read()
    except Exception,e:
        print(e, end='\r\n')
        return -2
    try:
        gco_dom = minidom.parseString(gco_xml)
        base64output = gco_dom.getElementsByTagName('output')[0].firstChild.data
        logdata = base64.b64decode(base64output)
    except Exception,e:
        print(e, end='\r\n')
        return -3
    
    #Only xvda2 is allowed to be in the log and no other string matchin the regex xvd*
    if re.search('xvd[^a] | xvda[^2]', logdata) != None:
        return -1
    
    return 1


if __name__ == "__main__":
    check_result = check_oracle_urls(DescribeInstanceURL, DescribeVolumesURL, GetConsoleOutputURL, oracle_address)
    if check_result != 1:
        if check_result == -1:
            print ('A fraudulent oracle detected')
            exit(1)
        elif check_result == -2:
            print ('Could not f the oracle URLs. Try again later')
            exit(1)
        elif check_result == -3:
            print ('Amazon supplied unparsable data. Try again later')
            exit(1)
            
    start_firefox()
    thread = threading.Thread(target= buyer_start_minihttp_thread)
    thread.start()
    
    