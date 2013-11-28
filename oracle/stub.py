import os
import fcntl
import time
import sys
#we want stub.py to start up quickly and perform the Anti-DOS check, hence the few imports

TESTING=False
is_auditor = False

installdir = os.path.dirname(os.path.realpath(__file__))
access_log_dir = os.path.join(installdir, 'accesslog')
oracle_socket = os.path.join(installdir, 'oracle-socket')

#stub.py is invoked by sshd via the "command" option in authorizedkeys file when a pubkey logs in
#when stub.py finishes, sending SIGTERM to parent sshd is a sure way to end the ssh connection
sshd_ppid = os.getppid()
#argv[1] is tx-id, argv[2] is optional and can be "auditor" (for OT use)
if len(sys.argv) < 2 or len(sys.argv) > 3:
    import signal
    sys.stderr.write('Internal error. The amount of arguments in not betweeb 2 and 3\n')
    sys.stderr.flush()
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
txid = sys.argv[1]

if len (sys.argv) == 3:
    if sys.argv[2] != 'auditor':
        import signal
        sys.stderr.write('Internal error. The third argument is not "auditor"\n')
        sys.stderr.flush()
        time.sleep(1)
        os.kill(sshd_ppid, signal.SIGTERM)
        exit()
    else:
        is_auditor = True
sys.stderr.write('Your txid (or the txid you are auditing) is: '+txid+'\n')
sys.stderr.flush()
if len(txid) != 9:
    import signal
    sys.stderr.write('Internal error. Txid length is not 9\n')
    sys.stderr.flush()
    time.sleep(1)
    os.kill(sshd_ppid, signal.SIGTERM)
    exit()
    
#anti DOS check
#sshd has no internal way to limit the amount of connections that a user with the authenticated pubkey can make, hence this check
#an attacker could flood sshd with successfull connections and exhaust server resources
#access file keeps timestamps of when user logged in
#the user can only exceed the limit of login attempts if he is not using the provided software (which honors the limit)
#After the user performed his banking session, the only reason why he would have to login again is to check the oracle's audit logs

#we don't have to protect from a DOS by an OpenTransactions auditor/judge, because the judge is a trusted party
if not TESTING or not is_auditor:
    if not os.path.isdir(access_log_dir): os.mkdir(access_log_dir)
    access_file_path = os.path.join(access_log_dir, txid)
    
    if not os.path.isfile(access_file_path):
        try:
            open(access_file_path, 'w').close()
        except:
            import signal
            sys.stderr.write('Try again later\n')
            sys.stderr.flush()
            time.sleep(1)
            os.kill(sshd_ppid, signal.SIGTERM)
            exit()
    
    #append the current timestamp 
    access_file = open(access_file_path, 'a+')
    fcntl.flock(access_file, fcntl.LOCK_EX)
    current_timestamp = str(int(time.time()))
    sys.stderr.write(current_timestamp + ' Connection attempt\n')
    sys.stderr.flush()
    access_file.write(current_timestamp +'\n' )
    access_file.flush()
    
    #analyze the timestamps
    access_file.seek(0, os.SEEK_SET)
    file_data = access_file.read()
    lines = file_data.split()    
    lines.reverse()
    limit = 200 if txid == 'escrow-id' else 100
    for index,timestamp in enumerate(lines):
        if int(current_timestamp) - int(timestamp) < 3600:
            if index > limit:
                import signal
                import socket
                import subprocess

                #exceeded hourly connection amount limit
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(oracle_socket)
                s.send('ban '+txid)
                s.close()
                sys.stderr.write('Too frequent connections. User has been banned. Contact escrow for details\n')
                sys.stderr.flush()
                #wait for changes to propagate to authkeysfile
                #while the attacker is beng removed from authkeysfile, he may establish more connections and spawn stub.py threads
                #all those threads will be blocked waiting on access_file lock
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
                sys.stderr.flush()
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
sys.stderr.flush()
  
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(oracle_socket)          
s.send(txid+' '+str(sshd_ppid)+(' auditor'if is_auditor else ''))

data_in = None
while 1:
    time.sleep(1)
    #either a user command on stdin or an oracle.py response on s
    rlist, wlist, xlist = select.select([sys.stdin,s],[],[])
    if sys.stdin in rlist:
        cmd = sys.stdin.readline()
        #Only proceed if there was actual data
        #It was observed that sometimes select() triggers on empty stdin 
        if cmd:
            cmd = cmd.strip()
            s.send(txid+'-cmd ' +cmd+(' auditor'if is_auditor else ''))
    if s in rlist:
        data_in = s.recv(4096)
        sys.stderr.write(data_in+'\n')
        sys.stderr.flush()
        if data_in.startswith('Session finished.'):
            sys.stderr.write('Received finished signal\n')
            sys.stderr.flush()
            time.sleep(1)
            break
        
s.close()
os.kill(sshd_ppid, signal.SIGTERM)