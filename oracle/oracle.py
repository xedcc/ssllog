import socket,select
import os
import threading
import time
import subprocess
import signal
import shutil
import StringIO
import fcntl
import sys
import random

TESTING = False
if sys.argv[1] == 'testing' if len(sys.argv)>1 else False: TESTING = True

database = []
#database fields

#'txid':   unique 9-digit id assigned by the escrow for a particular BTC transaction.
#'pubkey': RSA public key which the user generates, gives to the escrow, and the escrow adds it to the oracle's authorized keys file. Allows to ssh into the oracle.
#'port':   a random port on the oracle server used for ssh port forwarding. If at the time of banking session this port happens to be occupied, a new random port will be generated, authkeysfile will be updated to use that port and the user will be asked to login again.
#'added':  time when the escrow added this pubkey to the oracle.
#'is_logged_in_now': whether the user is having an active ssh session. Used to prevent multiple ssh sessions by the same user.
#'last_login_time':  last time the user established an ssh session or 0 otherwise.
#'finished_banking'  time when the banking session ended or 0 otherwise. -1 if the user has been banned.
#'hash':   sha256 hash of the tarball of the folder containing logs generated by stcppipe. Hash is taken only after banking session is over.
#'escrow_fetched_tarball': time when the escrow successfully fetched the tarball and confirmed that the tarball's hash matched or 0 otherwise.
#'sshd_ppid': PID of the fork()ed sshd which started stub.py. Used to detect stale sessions after the user disconnects abruptly.

installdir = os.path.dirname(os.path.realpath(__file__))
stcppipe_logdir = os.path.join(installdir, 'stcppipelog')
authorized_keys = os.path.join(installdir, '.ssh', 'authorized_keys')

#host and port to which the oracle will POST the tarball
escrow_host = None
escrow_port = None
is_escrow_registered = False
is_escrow_logged_in = False
escrow_last_sshd_ppid = 0

db_lock_path = os.path.join(installdir, 'db.lock')
db_lock_fd = open(db_lock_path, 'w')

def __LOCK_DB():
    global db_lock_fd
    fcntl.flock(db_lock_fd, fcntl.LOCK_EX)
    
def __UNLOCK_DB():
    global db_lock_fd
    fcntl.flock(db_lock_fd, fcntl.LOCK_UN)

#get txid index in the database and optionally ban it
#Optionally allows not to lock the database if the calling process is already holding the lock
def get_txid_index_in_db(txid, lock=True, ban=False):
    if lock: __LOCK_DB()
    found_index = -1
    for index,item in enumerate(database):
        if item['txid'] == txid:
            found_index = index
            break
    if ban==True and found_index != -1:
        database[index]['finished_banking'] = -1
    if lock: __UNLOCK_DB()
    return found_index

 
def get_database_as_a_string():
    iostr = StringIO.StringIO()
    __LOCK_DB()
    iostr.write(database)
    __UNLOCK_DB()
    return iostr.getvalue()

def escrow_add_pubkey(txid, pubkey, port):
    #make sure the txid is not in the db already
    __LOCK_DB()
    index = get_txid_index_in_db(txid, lock=False)
    if index >= 0:
        __UNLOCK_DB()
        return (-1, 'txid already added')
    database.append({'txid':txid, 'pubkey':pubkey, 'port':int(port), 'added': int(time.time()), 'is_logged_in_now':False, 'last_login_time':0, 'finished_banking':0, 'hash': '', 'escrow_fetched_tarball':0, 'sshd_ppid':0})
    __UNLOCK_DB()
    
    akeys_file = open(authorized_keys, 'a')
    fcntl.flock(akeys_file, fcntl.LOCK_EX)
    akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,permitopen="localhost:'+port+'",command="/usr/bin/python '+os.path.join(installdir, 'stub.py')+' '+txid+'"'+' ssh-rsa '+pubkey+'\n')
    fcntl.flock(akeys_file, fcntl.LOCK_UN)
    akeys_file.close()
      
    return(0,'')
                            
    
def escrow_get_tarball(txid):
    __LOCK_DB()
    index = get_txid_index_in_db(txid, lock=False)
    if index < 0:
        __UNLOCK_DB()
        return (-1, 'txid does not exist')
    has_finishes_session = database[index]['finished_banking']
    is_sent_to_escrow = database[index]['escrow_fetched_tarball']
    tarball_hash = database[index]['hash']
    __UNLOCK_DB()
    
    if not has_finishes_session:
        return (-1, 'user has not yet finished their banking session')
    if is_sent_to_escrow == True:
        return (-1, 'tarball already sent to escrow')
    else:
        try:
            #POST the tarball to escrow with custom headers, so that escow could check the hash and respond with 500 if hash mismatched
            http_code = subprocess.check_output(['curl', '--write-out', '%{http_code}', '--silent', '-F', 'localfile=@'+os.path.join(stcppipe_logdir, txid+'.tar'), escrow_host+':'+str(escrow_port), '-H', 'escrow-filename:'+txid+'.tar', '-H', 'escrow-hash:'+tarball_hash ])
        except:
            return (-1, "Error POSTing the tarball to escrow's server")
    if http_code == 500:
        return (-1, 'Escrow reported hash mismatch')        
      
    __LOCK_DB()  
    index = get_txid_index_in_db(txid, lock=False)
    if index < 0:
        __UNLOCK_DB()
        return (-1, 'txid does not exist even though it existed just a second ago')
    
    database[index]['escrow_fetched_tarball'] = int(time.time())
    __UNLOCK_DB()
    #Now that escrow confirmed safe receipt of the tarball, remove the logdir and the tarball
    shutil.rmtree(os.path.join(stcppipe_logdir, txid))
    os.remove(os.path.join(stcppipe_logdir, txid+'.tar'))
    return (0,'')


def cleanup_and_exit(conn, txid=0,  msg=''):
    if txid !=0:
        index = get_txid_index_in_db(txid)
        if index < 0:
            print('finished Transaction ID not found in database')
            conn.send('finished Transaction ID not found in database')
            time.sleep(1)
            conn.close()
            return
        __LOCK_DB()
        is_logged_in = database[index]['is_logged_in_now']
        database[index]['is_logged_in_now'] = False
        __UNLOCK_DB()
        if is_logged_in == False:
            print('finished Internal error. User was already logged out')
            conn.send('finished Internal error. User was already logged out')
            time.sleep(1)
            conn.close()
            return
    print('finished ' + msg)
    conn.send('finished ' + msg)
    time.sleep(1)
    conn.close()
      
               
def thread_handle_txid(conn, txid, sshd_ppid):
    __LOCK_DB
    index = get_txid_index_in_db(txid, lock=False)
    if index < 0:
        __UNLOCK_DB()
        cleanup_and_exit(conn, msg='Transaction ID not found in database')
        return
           
    port = None
    is_logged_in = None
    
    is_logged_in = database[index]['is_logged_in_now']
    prev_sshd_ppid = database[index]['sshd_ppid']

    if is_logged_in:
        #check for a stale session from prevous login
        try:
            os.kill(prev_sshd_ppid, 0)
            #we get here if there was no exception
            __UNLOCK_DB()
            cleanup_and_exit(conn, msg='This user is already logged in', txid=txid)
            return
        except OSError:
            #The PID is no longer running, i.e. we have a stale session, leave is_logged_in in True and move on
            pass
    
    finished_banking = database[index]['finished_banking']          
    database[index]['is_logged_in_now'] = True
    database[index]['sshd_ppid'] = int(sshd_ppid)
    database[index]['last_login_time'] = int(time.time())
    #Copy the vars which we'll need later, so we don't have to lock db again later
    port = database[index]['port']
    __UNLOCK_DB()
 
    if finished_banking:
        #if the user has finished the banking session, it is assumed that he logs in to audit the database
        db_str = get_database_as_a_string()
        print 'Database sent to user'
        conn.send('database ' + db_str)
        #allow stub to process socket data before sending the "finished" message
        time.sleep(3)
        cleanup_and_exit(conn, msg='Sent database to user', txid=txid)
        return
    
    #setup to perform banking audit  
    if not os.path.isdir(stcppipe_logdir): os.mkdir(stcppipe_logdir)
    logdir = os.path.join(stcppipe_logdir, txid)
    if os.path.isdir(logdir): shutil.rmtree(logdir)
    os.mkdir(logdir)
    start_time = int(time.time())
    stcppipe_proc = subprocess.Popen([os.path.join(installdir, 'stcppipe'), '-d', logdir, '-b', '127.0.0.1', '3128', str(port)])
    #if stcppipe returns with returncode 1 , it means that the port is in use. Very unlikely but possible
    time.sleep(1)
    if stcppipe_proc.poll() == 1:
        #modfy authkeys file and ask user to reconnect on a different random port
        newport = random.randint(1025,65535)
        #we use 2 file descriptors to open the file for reading and writing. The lock is held on the reading file descriptor
        fd_read = open(authorized_keys, 'r')
        fcntl.flock(fd_read, fcntl.LOCK_EX)
        filedata = fd_read.read()
        lines = filedata.split('\n')
        is_found_in_authkeys = False
        for index,line in enumerate(lines):
            if line.count(txid) != 0:
                line = line.replace(str(port),str(newport))
                lines.pop(index)
                lines.insert(index, line)
                is_found_in_authkeys = True
                break
        if not is_found_in_authkeys:
            cleanup_and_exit(conn, msg='Internal error. The txid was not found in authorized keys file', txid=txid)
            fcntl.flock(fd_read, fcntl.LOCK_UN)
            fd_read.close()
            return
        fd_write = open(authorized_keys, 'w')
        for line in lines:
            fd_write.write(line+'\n')  
        fd_write.close()
        fcntl.flock(fd_read, fcntl.LOCK_UN)
        fd_read.close()
        
        __LOCK_DB
        index = get_txid_index_in_db(txid, lock=False)
        if index < 0:
            __UNLOCK_DB()
            cleanup_and_exit(conn, msg='Transaction ID not found in database')
            return
        database[index]['port'] = newport
        __UNLOCK_DB
    
        cleanup_and_exit(conn, msg='Please reconnect and use port '+str(newport)+' for forwardng', txid=txid)
        return
    
    conn.send('Tunnel ready')
        
    
    #wait for sslkey from the user
    last_dos_check = start_time
    conn.settimeout(1 if TESTING else 10)
    msg_in = None
    while 1:
        try:
            msg_in = conn.recv(1024)
        except:
            #timeout reached
            pass
        current_time = int(time.time())
        if current_time-start_time > 1200:
            #there was no finished signal for 20 minutes, wrapping up
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)
            shutil.rmtree(logdir)
            cleanup_and_exit(conn, msg='Time limit expired. Connection closed', txid=txid)
            return
        
        #Anti DOS measure. Every minute make sure the user is not overwhelming the logdir with data or new files(generated on every new connection). Limits: 1000 files or 50MB of data
        if current_time-last_dos_check > 60:
            last_dos_check = current_time
            filelist = os.listdir(logdir)
            if len(filelist) > 1000 or sum([os.path.getsize(os.path.join(logdir,f)) for f in filelist]) > 50000000:
                ban_user(txid)
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                time.sleep(3)
                shutil.rmtree(logdir)
                cleanup_and_exit(conn, msg='You have been banned. Contact escrow for details')
                return
        
        if msg_in: 
            if msg_in.startswith(txid+'-cmd sslkey '):
                sslkey = msg_in[len(txid+'-cmd sslkey '):]
                if len(sslkey) > 180:
                    os.kill(stcppipe_proc.pid, signal.SIGTERM)
                    time.sleep(3)
                    shutil.rmtree(logdir)
                    cleanup_and_exit(conn, msg='Wrong sslkey length', txid=txid)
                    return
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                time.sleep(3)            
                finish_time = int(time.time())
                
                sslkey_fd = open(os.path.join(logdir,'sslkey'), 'w')
                sslkey_fd.write(sslkey+'\n')
                sslkey_fd.close()
                tar_path = os.path.join(stcppipe_logdir, txid+'.tar')
                subprocess.call(['tar', 'cf', tar_path, logdir])
                output = subprocess.check_output(['sha256sum', tar_path])
                sha_hash = output.split()[0]
                
                __LOCK_DB()
                index = get_txid_index_in_db(txid, lock=False)
                if index < 0:
                    __UNLOCK_DB()
                    cleanup_and_exit(conn, msg='Transaction ID not found in database')
                    return
                
                database[index]['finished_banking'] = finish_time
                database[index]['hash'] = sha_hash
                __UNLOCK_DB()
                cleanup_and_exit(conn, msg='Session ended successfully ', txid=txid)
                return
            
            else:
                os.kill(stcppipe_proc.pid, signal.SIGTERM)
                time.sleep(3)
                shutil.rmtree(logdir)
                cleanup_and_exit(conn, msg='Unknown command received. Expected "sslkey"', txid=txid)
                return
    

def escrow_thread(conn, sshd_ppid):
    global is_escrow_registered
    global is_escrow_logged_in
    global escrow_host
    global escrow_port
    global escrow_last_sshd_ppid
    
    if is_escrow_logged_in:
        #check for a stale session from the previous login
        try:
            os.kill(escrow_last_sshd_ppid, 0)
            #if we get here, there was no exception, meaning that the user is indeed still logged in
            print('finished Escrow is already logged in')
            conn.send('finished Escrow is already logged in')
            time.sleep(1)
            conn.close()
            return
        except OSError:
            #the PID was not found, i.e. a stale session detected. Leave the logged_in flag and move on
            pass     
    
    is_escrow_logged_in = True
    escrow_last_sshd_ppid = int(sshd_ppid)
    conn.settimeout(1)
    
    while 1:
        #escrow isn't allowed to make more than one request per minute. Anti DOS measure.
        if TESTING: time.sleep(1)
        else: time.sleep(60)
        try:
            args = conn.recv(1024)
        except:
            #timeout triggered
            continue
        arglist = args.split()
        if len(arglist) < 2:
            print('finished Too few arguments')
            conn.send('finished Too few arguments')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return
        magic, cmd, paralist = arglist[0], arglist[1], arglist[2:]
        if not magic == 'escrow-id-cmd':
            print('finished Internal error. Wrong magic string')
            conn.send('finished Internal error. Wrong magic string')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return
        if not is_escrow_registered and not cmd == 'register_escrow':
            print('finished You must register escrow first ')
            conn.send('finished You must register escrow first ')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return
        if cmd == 'register_escrow':
            #This is the very first command that escrow must send after installing this oracle
            #format: register_escrow pubkey escrow_host escrow_port
            if len(paralist) != 3:
                print('finished Invalid amount of parameters')
                conn.send('finished Invalid amount of parameters')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            if is_escrow_registered:
                print('finished Escrow already registered')
                conn.send ('finished Escrow already registered')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            pubkey, host_ip, port = paralist
            
            input_error = False
            if (len(pubkey) > 1000) or (len(port)>5) or not port.isdigit() or (len(host_ip) > 15):
                input_error = True
            if not input_error:
                try:
                    port_int = int(port)
                    if port_int > 65536: input_error=True
                except:
                    input_error = True
            
            if input_error:
                print('finished Faulty data for registering escrow')
                conn.send('finished Faulty data for registering escrow')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            
            akeys_file = open(authorized_keys, 'w')
            fcntl.flock(akeys_file, fcntl.LOCK_EX)            
            akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding,command="/usr/bin/python '+os.path.join(installdir, 'stub.py') + ' escrow-id" ssh-rsa '+pubkey+'\n')
            fcntl.flock(akeys_file, fcntl.LOCK_UN)
            akeys_file.close()
            
            escrow_host = host_ip
            escrow_port = port
            is_escrow_registered = True
            print('Escrow successfully registered')
            conn.send('Escrow successfully registered')
            continue    
        
        if cmd == 'add_pubkey':
            #format: add_pubkey tx-id pubkey forwarding_port
            if len(paralist) != 3:
                print('finished Invalid amount of parameters')
                conn.send('finished Invalid amount of parameters')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            txid, pubkey, port = paralist
            input_error = False
            if (len(txid) != 9) or (len(pubkey) > 1000) or not port.isdigit():
                input_error = True
            if not input_error:
                try:
                    port_int = int(port)
                    if port_int > 65536: input_error=True
                except:
                    input_error = True
                    
            if input_error:
                print('finished Faulty data for adding a pubkey')
                conn.send('finished Faulty data for adding a pubkey')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            retval = escrow_add_pubkey(txid, pubkey, port)
            if retval[0] == -1:
                conn.send('finished '+retval[1])
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            else:
                print('Public key successfully added to database')
                conn.send('Public key successfully added to database')
                continue
                       
        if cmd == 'get_tarball':
            #format: get_tarball txid
            if len(paralist) != 1:
                print('finished Invalid amount of parameters')
                conn.send('finished Invalid amount of parameters')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            txid = paralist[0]
            retval = escrow_get_tarball(txid)
            if retval[0] == -1:
                print('finished '+retval[1])
                conn.send('finished '+retval[1])
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            else:
                print('Tarball successfully sent to escrow host')
                conn.send('Tarball successfully sent to escrow host')
                continue
        
        if cmd == 'get_database':
            if len(paralist) != 0:
                print('finished Invalid amount of parameters')
                conn.send('finished Invalid amount of parameters')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            db_str = get_database_as_a_string()
            print 'Database sent to escrow' + db_str
            conn.send('database ' + db_str)
            continue
        
        if cmd == 'exit':
            is_escrow_logged_in = False
            print('finished Escrow initiated disconnect')
            conn.send('finished Escrow initiated disconnect')
            time.sleep(1)
            conn.close()
            return
                   
        else:
            print('finished Unrecognized command')
            conn.send('finished Unrecognized command')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return

#remove txid record from authorizedkeys file
#Leave it in the database as proof that the user was once registered and later was banned
def ban_user(txid):
    if not txid:
        print 'internal error. Empty txid'
        return
    fd_read = open(authorized_keys, 'r')
    fcntl.flock(fd_read, fcntl.LOCK_EX)
    filedata = fd_read.read()
    lines = filedata.split('\n')
    is_found_in_authkeys = False
    for index,line in enumerate(lines):
        if line.count(txid) != 0:
            lines.pop(index)
            is_found_in_authkeys = True
            break
    if not is_found_in_authkeys:
        print ('Internal error. The txid to be banned was not found in authorized keys file')
        fcntl.flock(fd_read, fcntl.LOCK_UN)
        fd_read.close()
        return
    fd_write = open(authorized_keys, 'w')
    for line in lines:
        fd_write.write(line+'\n')
    fd_write.close()
    fcntl.flock(fd_read, fcntl.LOCK_UN)
    fd_read.close()
    
    #NB escrow is never in the database
    if txid != 'escrow-id':
        if get_txid_index_in_db(txid, ban=True) == -1:
            print 'Internal error. Could not find txid in database'
            return
    

                

if __name__ == "__main__":
    
    oracle_socket = os.path.join(installdir, 'oracle-socket')
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(oracle_socket): os.unlink(oracle_socket)
    s.bind(oracle_socket)
    #/proc/sys/net/core/somaxconn is 128 on Linux, We need to able to process this many new connection in case of DOS
    s.listen(128)
    #timeout is needed because if the socket is blocking, we won't be able to pause this script under debugger
    s.settimeout(1)
    
    while 1:
        try:
            #timeout triggered, sleep so that (when debugging) the Ctrl+C could stop the script
            time.sleep(0.2)
        except:
            exit(0)
        try:
            conn, addr = s.accept()
        except:
            continue
        args = conn.recv(1024)
        arglist = args.split()
        if len(arglist) != 2:
            print('finished Internal error. Did not receive two arguments as expected')
            conn.send('finished Internal error. Did not receive two arguments as expected')
            time.sleep(1)
            conn.close()
            continue
        arg1, arg2 = arglist
        if arg1 == 'escrow-id':
            thread = threading.Thread(target= escrow_thread, args=(conn, arg2))
            thread.daemon = True
            thread.start()
        elif arg1 == 'ban':
            ban_user(arg2)
        else:
            thread = threading.Thread(target= thread_handle_txid, args=(conn, arg1, arg2))
            thread.daemon = True
            thread.start()

            