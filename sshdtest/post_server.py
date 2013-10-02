import BaseHTTPServer, SimpleHTTPServer
import os
import subprocess

class MyHandler( BaseHTTPServer.BaseHTTPRequestHandler):
    logdir = '/home/default2/Desktop/sslxchange/sshdtest'

    def do_POST( self ):
        try:
            filename = self.headers.getheader('escrow-filename')
            sha_hash = self.headers.getheader('escrow-hash')
            tarfile = os.path.join(self.logdir,filename)
            tarfile_fd = open(tarfile, 'w')
            
            length = int(self.headers.getheader('content-length'))
            data = self.rfile.read(length)
            ctype = self.headers.getheader('content-type')
            #the boundary is a line of two hyphens plus whatever's in content-type header
            boundary = '\r\n--'+ctype[ctype.find('boundary=')+len('boundary='):]
            filebody = data[data.find('\r\n\r\n')+len('\r\n\r\n'):]
            boundary_index = filebody.find(boundary)
            tarfile_fd.write(filebody[:boundary_index])
            tarfile_fd.flush()
            tarfile_fd.close()
            check_hash = subprocess.check_output(['sha256sum', tarfile]).split()[0]
            if check_hash == sha_hash:
                print 'Success: hashes match'
                self.send_response( 200 )
                self.end_headers()
            else:
                print "Failure: hashes don't match"
                self.send_response( 500 )
                self.end_headers()                
        except:
            print "Error"


def httpd(handler_class=MyHandler, server_address = ('127.0.0.1', 8045)):
    try:
        print "Server started"
        srvr = BaseHTTPServer.HTTPServer(server_address, handler_class)
        srvr.serve_forever() # serve_forever
    except KeyboardInterrupt:
        server.socket.close()


if __name__ == "__main__":
    httpd( )