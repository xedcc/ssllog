import socket
import os
import signal
import time
import fcntl
import sys
import select

access_log_dir = '/home/default2/Desktop/sshdtest/accesslog'
oracle_socket = '/tmp/oracle-socket2'

if len(sys.argv) != 2:
    print 'Internal error. The amount of arguments in not 2'
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
txid = sys.argv[1]
sshd_ppid = os.getppid()
if len(txid) != 9:
    print 'Internal error. Txid length is not 9'
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
        print ('Try again later')
        return
    
access_file = open(access_file_path, 'r+')
try:
    fcntl.flock(access_file, fcntl.LOCK_EX|fcntl.LOCK_NB)
except IOError:
    #accessfile is already locked by another connection of this user
    #That's a sign of multiple within-one-second connections
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(oracle_socket)
    s.send('ban '+txid)
    s.close()
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
access_file.write(str(int(time.time()))+'\n' )
access_file.flush()
file_data = access_file.read()
lines = file_data.split('\n')
first_item = lines[0]
lines = lines[1:]
#contains (time, index)
lower_threshold = (int(first_item),0)
for index,time in enumerate(lines):
    if int(time) - lower_threshold[0] < 600:
        if index - lower_threshold[1] > 5:
            #more than 5 connections attempts in 10 minutes
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(oracle_socket)
            s.send('ban '+txid)
            s.close()
            os.kill(sshd_ppid, signal.SIGTERM)
            exit()
        else:
            continue
    else:
        #find a new lower threshold
        for newindex,newtime in enumerate(lines[lower_threshold[1]+1:index+1]):
            if int(time) - int(newtime) < 600:
                lower_threshold[0] = int(newtime)
                lower_threshold[1] = lower_threshold[1]+1+newindex

fcntl.flock(access_file, fcntl.LOCK_UN)
access_file.close()
#finished anti DOS check
  
  
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(oracle_socket)          
s.send(txid)

while 1:
    sleep(1)
    rlist, wlist, xlist = select.select([sys.stdin,s],[],[])
    if sys.stdin in rlist:
        cmd = sys.stdin.read()
        s.send(txid+'-cmd ' +cmd)
    if s in rlist:
        data_in = s.recv(1024)
        print data_in
        if data.startswith('finished'):
            break
        

s.close()
os.kill(sshd_ppid, signal.SIGTERM)