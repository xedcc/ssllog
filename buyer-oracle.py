from __future__ import print_function

import os
import subprocess
import sys
import BaseHTTPServer, SimpleHTTPServer
import threading

logdir = '/home/default2/Desktop/sslxchange/oracle/logs'
sslkeylog = '/home/default2/Desktop/sslkeylog'
buyer_http_port = 2222

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


if __name__ == "__main__":
    thread = threading.Thread(target= buyer_start_minihttp_thread)
    thread.start()
    
    