import socket
import os
import signal
import time
import fcntl
import sys
import select
import wingdbstub

access_log_dir = '/home/default2/Desktop/sslxchange/sshdtest/accesslog'
oracle_socket = '/tmp/oracle-socket'
sshd_ppid = os.getppid()
sys.stderr.write('Welcome\n')

if len(sys.argv) != 2:
    sys.stderr.write('Internal error. The amount of arguments in not 2\n')
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
txid = sys.argv[1]
sys.stderr.write('Your txid is: '+txid+'\n')
if len(txid) != 9:
    sys.stderr.write('Internal error. Txid length is not 9\n')
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
    
#anti DOS check
#sshd has no internal way to limit the amount of connections that a successfully authenticated user can make, hence this check
#an attacker could flood sshd with successfull connections and exhaust server resources
#access file keeps timestamps of when user logged in
#if a user tries to login more than 5 times within 10 minutes, that's a sure sign that a malicious DOS is taking place
#because the user is not supposed to login manually but only through the provided software which has a built-in limit of no
#more than 1 connection per 10 minutes
#After the user performed his banking session, the only reason why he would have to login again is to check the oracle's audit logs

access_file_path = os.path.join(access_log_dir, txid)

if not os.path.isfile(access_file_path):
    try:
        open(access_file_path, 'w').close()
    except:
        sys.stderr.write('Try again later\n')
        time.sleep(1)
        os.kill(sshd_ppid, signal.SIGTERM)
        exit()
    
access_file = open(access_file_path, 'a+')
try:
    fcntl.flock(access_file, fcntl.LOCK_EX|fcntl.LOCK_NB)
except IOError:
    #accessfile is already locked by another connection of this user
    #That's a sign of multiple within-one-second connections
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(oracle_socket)
    s.send('ban '+txid)
    s.close()
    sys.stderr.write('User has been banned\n')
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
access_file.write(str(int(time.time()))+'\n' )
access_file.flush()
access_file.seek(0, os.SEEK_SET)
file_data = access_file.read()
lines = file_data.split()

current_timestamp = int(lines[-1])
lines.reverse()
for index,timestamp in enumerate(lines):
    if current_timestamp - int(timestamp) < 600:
        if index > 5:
            #more than 5 connections attempts in 10 minutes
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(oracle_socket)
            s.send('ban '+txid)
            s.close()
            sys.stderr.write('User has been banned\n')
            time.sleep(1)
            os.kill(sshd_ppid, signal.SIGTERM)
            exit()
    else:
        break
    
fcntl.flock(access_file, fcntl.LOCK_UN)
access_file.close()
#finished anti DOS check

  
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(oracle_socket)          
s.send(txid+' '+str(sshd_ppid))

while 1:
    time.sleep(1)
    rlist, wlist, xlist = select.select([sys.stdin,s],[],[])
    if sys.stdin in rlist:
        cmd = sys.stdin.readline()
        #Only proceed if there was actual data
        if cmd:
            cmd = cmd.strip()
            s.send(txid+'-cmd ' +cmd)
    if s in rlist:
        data_in = s.recv(4096)
        sys.stderr.write(data_in+'\n')
        sys.stderr.flush()
        if data_in.startswith('finished'):
            sys.stderr.write('Received finished signal\n')
            sys.stderr.flush()
            time.sleep(1)
            break
        

s.close()
os.kill(sshd_ppid, signal.SIGTERM)