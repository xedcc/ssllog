import os
import fcntl
import time
import sys
#we want stub.py to be as lean as possible until it performs the Anti-DOS check
#During DOS, stub.py has to be able to start fast and terminate fast, hence the few imports
#import wingdbstub

TESTING=False

installdir = os.path.dirname(os.path.realpath(__file__))
access_log_dir = os.path.join(installdir, 'accesslog')
oracle_socket = '/tmp/oracle-socket'

sshd_ppid = os.getppid()
if len(sys.argv) != 2:
    import signal
    sys.stderr.write('Internal error. The amount of arguments in not 2\n')
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
txid = sys.argv[1]
sys.stderr.write('Your txid is: '+txid+'\n')
if len(txid) != 9:
    import signal
    sys.stderr.write('Internal error. Txid length is not 9\n')
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
    
#anti DOS check
#sshd has no internal way to limit the amount of connections that a user with the correct pubkey can make, hence this check
#an attacker could flood sshd with successfull connections and exhaust server resources
#access file keeps timestamps of when user logged in
#if a user tries to login more than 5 times within 10 minutes, that's a sure sign that a malicious DOS is taking place
#because the user is not supposed to login manually but only through the provided software which has a built-in limit of no
#more than 1 connection per 10 minutes
#After the user performed his banking session, the only reason why he would have to login again is to check the oracle's audit logs

if not TESTING:
    if not os.path.isdir(access_log_dir): os.mkdir(access_log_dir)
    access_file_path = os.path.join(access_log_dir, txid)
    
    if not os.path.isfile(access_file_path):
        try:
            open(access_file_path, 'w').close()
        except:
            import signal
            sys.stderr.write('Try again later\n')
            time.sleep(1)
            os.kill(sshd_ppid, signal.SIGTERM)
            exit()
        
    access_file = open(access_file_path, 'a+')
    fcntl.flock(access_file, fcntl.LOCK_EX)
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
                import signal
                import socket
                import subprocess

                #more than 5 connections attempts in 10 minutes
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(oracle_socket)
                s.send('ban '+txid)
                s.close()
                sys.stderr.write('Too frequent connections. User has been banned. Contact escrow for details\n')
                #wait for changes to propagate to authkeysfile
                time.sleep(10)
                #get inode of lockfile and kill processes waiting on the lock of that inode
                inode = subprocess.check_output(['ls', '-i', access_file_path]).split()[0]
                proc_locks_fd = open('/proc/locks', 'r')
                proc_locks_data = proc_locks_fd.read()
                proc_locks_fd.close()
                lines = proc_locks_data.split('\n')
                #A line for a process waiting on a lock ("->") looks like:
                #2: -> FLOCK  ADVISORY  WRITE 20530 00:1f:1978949 0 EOF
                procs_to_kill = []
                for line in lines:
                    splitline = line.split()
                    if not len(splitline)==9:
                        continue
                    if splitline[1] == "->":
                        procs_to_kill.append(splitline[5])
                for proc in procs_to_kill:
                    os.kill(int(proc), signal.SIGTERM)
                sys.stderr.write('Killed ' +str(len(procs_to_kill)) + ' processes \n')
                os.kill(sshd_ppid, signal.SIGTERM)
                exit()
        else:
            break
        
    fcntl.flock(access_file, fcntl.LOCK_UN)
    access_file.close()
    #finished anti DOS check

import socket
import select
import subprocess
import signal

sys.stderr.write('Welcome\n')
  
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