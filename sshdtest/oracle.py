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

TESTING = True
#if sys.argv[1] == 'testing' if len(sys.argv)>1 else False: TESTING = True

database = []
stcppipe_logdir = '/home/default2/Desktop/sslxchange/sshdtest/stcppipelog'
authorized_keys = '/home/default2/Desktop/sslxchange/sshdtest/authorizedkeys'

escrow_host = None
escrow_port = None
is_escrow_registered = False
is_escrow_logged_in = False
escrow_last_sshd_ppid = 0

db_lock_path = '/home/default2/Desktop/sslxchange/sshdtest/db.lock'
db_lock_fd = open(db_lock_path, 'w')

def __LOCK_DB():
    global db_lock_fd
    try:
        fcntl.flock(db_lock_fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError:
        print 'An already existing lock detected. Blocking now'
        fcntl.flock(db_lock_fd, fcntl.LOCK_EX)
    
def __UNLOCK_DB():
    global db_lock_fd
    fcntl.flock(db_lock_fd, fcntl.LOCK_UN)

#get txid index in the database and optionally remove it
#Optionally don't lock the database if the calling process is already holding the lock
def get_txid_index_in_db(txid, remove=False, lock=True):
    if lock: __LOCK_DB()
    found_index = -1
    for index,item in enumerate(database):
        if item['txid'] == txid:
            found_index = index
            break
    if remove==True and found_index != -1:
        database.pop[index]
    if lock: __UNLOCK_DB()
    return found_index

def open_socket_to_stub(txid):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("/tmp/"+txid+"_stub")
    return s
  

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
    database.append({'txid':txid, 'pubkey':pubkey, 'port':int(port), 'time_added_to_db': int(time.time()), 'is_logged_in_now':False, 'last_login_time':0, 'has_finished_banking_session':False, 'time_fin_ban_sess':0, 'tarballsha256hash': '', 'has_escrow_copied_the_data':False, 'time_esc_cop_data':0, 'sshd_ppid':0})
    __UNLOCK_DB()
    
    akeys_file = open(authorized_keys, 'a')
    fcntl.flock(akeys_file, fcntl.LOCK_EX)
    akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,permitopen="localhost:'+port+'",command="/usr/bin/python /home/default2/Desktop/sslxchange/sshdtest/stub.py '+txid+'"'+' ssh-rsa '+pubkey+'\n')
    fcntl.flock(akeys_file, fcntl.LOCK_UN)
    akeys_file.close()
      
    return(0,'')
                            
    

def escrow_get_tarball(txid):
    __LOCK_DB()
    index = get_txid_index_in_db(txid, lock=False)
    if index < 0:
        __UNLOCK_DB()
        return (-1, 'txid does not exist')
    
    is_sent_to_escrow = database[index]['has_escrow_copied_the_data']
    tarball_hash = database[index]['tarballsha256hash']
    has_finishes_session = database[index]['has_finished_banking_session']
    __UNLOCK_DB()
    
    if not has_finishes_session:
        return (-1, 'user has not yet finished their banking session')
    if is_sent_to_escrow == True:
        return (-1, 'tarball already sent to escrow')
    else:
        try:
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
    
    database[index]['has_escrow_copied_the_data'] = True
    database[index]['time_esc_cop_data'] = int(time.time())
    __UNLOCK_DB()
    return (0,'')


def cleanup_and_exit(conn, txid=0,  msg=''):
    if txid !=0:
        index = get_txid_index_in_db(txid)
        if index < 0:
            print('finished Transaction ID not found in database')
            conn.send('finished Transaction ID not found in database')
            conn.close()
            return
        __LOCK_DB()
        is_logged_in = database[index]['is_logged_in_now']
        database[index]['is_logged_in_now'] = False
        __UNLOCK_DB()
        if is_logged_in == False:
            print('finished Internal error. User was already logged out')
            conn.send('finished Internal error. User was already logged out')
            conn.close()
            return
    print('finished ' + msg)
    conn.send('finished ' + msg)
    conn.close()
      
               
def thread_handle_txid(conn, txid, sshd_ppid):
    __LOCK_DB
    index = get_txid_index_in_db(txid, lock=False)
    if index < 0:
        __UNLOCK_DB()
        cleanup_and_exit(conn, msg='Transaction ID not found in database')
        return
           
    has_finished = None
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
               
    database[index]['is_logged_in_now'] = True
    database[index]['sshd_ppid'] = int(sshd_ppid)
    database[index]['last_login_time'] = int(time.time())
    #Copy the vars which we'll need later, so we don't have to lock db again later
    has_finished = database[index]['has_finished_banking_session']
    port = database[index]['port']
    __UNLOCK_DB()
 
    if has_finished:
        #if the user has finished the banking session, it is assumed that he logs in to audit the database
        db_str = get_database_as_a_string()
        print 'Database sent to user'
        conn.send('database ' + db_str)
        #allow stub to process socket data before sending the "finished" message
        time.sleep(3)
        cleanup_and_exit(conn, msg='Sent database to user', txid=txid)
        return
    
    #setup to perform banking audit            
    logdir = os.path.join(stcppipe_logdir, txid)
    if os.path.isdir(logdir):
        shutil.rmtree(logdir)
    os.mkdir(logdir)
    start_time = int(time.time())
    stcppipe_proc = subprocess.Popen(['/home/default2/Desktop/sslxchange/stcppipe/stcppipe', '-d', logdir, '-b', '127.0.0.1', '3128', str(port)])
    #if stcppipe returns with returncode 1 , it means that the port is in use. Very unlikely but possible
    time.sleep(1)
    if stcppipe_proc.poll() == 1:
        #modfy authkeys file and ask user to reconnect on a different random port
        newport = random.randint(1025,65535)
        fd = open(authorized_keys, 'w+')
        fcntl.flock(fd, fcntl.LOCK_EX)
        filedata = fd.read()
        lines = filedata.split()
        is_found_in_authkeys = False
        for index,line in enumerate(lines):
            if line.count(txid) != 0:
                line = line.replace(str(port),str(newport))
                is_found_in_authkeys = True
                break
        if not is_found_in_authkeys:
            cleanup_and_exit(conn, msg='Internal error. The txid was not found in authorized keys file', txid=txid)
            return
        for line in lines:
            fd.write(line+'\n')        
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()
        cleanup_and_exit(conn, msg='Please reconnect and use port '+str(newport)+' for forwardng', txid=txid)
        return
    
    conn.send('Tunnel ready')
        
    

    
    #wait for the "finished" signal from the user
    while 1:
        conn.settimeout(1)
        try:
            msg_in = conn.recv(1024)
        except:
            #timeout reached
            continue
        if int(time.time())-start_time > 3600:
            #there was no finished signal for an hour. wrapping up
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)
            shutil.rmtree(logdir)
            cleanup_and_exit(conn, msg='An hour expired. Connection closed', txid=txid)
            return
            
        if msg_in == txid+'-cmd finished':
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)            
            finish_time = int(time.time())
            
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
            
            database[index]['has_finished_banking_session'] = True
            database[index]['time_fin_ban_sess'] = finish_time
            database[index]['tarballsha256hash'] = sha_hash
            __UNLOCK_DB()
            cleanup_and_exit(conn, msg='Session ended successfully ', txid=txid)
            return
        
        else:
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)
            shutil.rmtree(logdir)
            cleanup_and_exit(conn, msg='Unknown command received. Expected "finished"', txid=txid)
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
            if (len(pubkey) > 1000) or (int(port) > 65536 if port.isdigit() else True) or (len(host_ip) > 15):
                print('finished Faulty data for registering escrow')
                conn.send('finished Faulty data for registering escrow')
                time.sleep(1)
                conn.close()
                is_escrow_logged_in = False
                return
            
            akeys_file = open(authorized_keys, 'w')
            fcntl.flock(akeys_file, fcntl.LOCK_EX)            
            akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding,command="/usr/bin/python /home/default2/Desktop/sslxchange/sshdtest/stub.py escrow-id" ssh-rsa '+pubkey+'\n')
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
            if (len(txid) != 9) or (len(pubkey) > 1000) or (int(port) > 65536 if port.isdigit() else True):
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
        
        if cmd == 'finish_session':
            print('finished Escrow initiated disconnect')
            conn.send('finished Escrow initiated disconnect')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return
            
        
        else:
            print('finished Unrecognized command')
            conn.send('finished Unrecognized command')
            time.sleep(1)
            conn.close()
            is_escrow_logged_in = False
            return

#remove txid record from authorizedkeys file as well as from database 
def ban_user(txid):
    if not txid:
        print 'internal error. Empty txid'
        return
    if txid == 'escrow-id':
        #we don't want to actually ban escrow for good. He still has to wait another 10 minutes before logging in, though
        return
    fd = open(authorized_keys, 'w+')
    fcntl.flock(fd, fcntl.LOCK_EX)
    filedata = fd.read()
    lines = filedata.split()
    is_found_in_authkeys = False
    for index,line in enumerate(lines):
        if line.count(txid) != 0:
            lines.pop[index]
            is_found_in_authkeys = True
            break
    if not is_found_in_authkeys:
        print ('Internal error. The txid to be banned was not found in authorized keys file')
        return
    for line in lines:
        fd.write(line+'\n')        
    fcntl.flock(fd, fcntl.LOCK_UN)
    fd.close()
    
    if get_txid_index_in_db(txid, remove==True) == -1:
        print 'nternal error. Could not find txid in database'
        return
    

                

if __name__ == "__main__":
    
    auth_fd = open(authorized_keys, 'w')
    auth_fd.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding,command="/usr/bin/python /home/default2/Desktop/sslxchange/sshdtest/stub.py escrow-id" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClBsy9E5wPNvuc0ACLDdY1RLrzAeTcyvOAQ/W+2y7KV4cu96LuiNDFLk44WSVKAK/+StGN/PjOaBxLybRugBbCEH7wGRkYb3D1EdOA2ybgTj2Qqpc+9x+RiEZwj3wZywj6qc/35JZHdWy+rsbrNOiz4/aLTyBdKW9D3ZPDUikLekMmcw+mbGV7oVPZOIbpKOmvPI6MmiM3SradS0B4nbemm3TXKe5CPX9JDz9fX2yjGFKoSXC1WiZnbfHmo5R6KRXsJ17mEENgalv85T4rZmq1Kup/dDncGozFUone0MY7ocxUskQWy3MxMOxwPqOZMmNLPzux7sWZmGHKlgcrKO8P\n')
    auth_fd.close()
    
    oracle_socket = '/tmp/oracle-socket'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #reuse address for multiple runs during testing
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        os.remove(oracle_socket)
    except OSError:
        pass
    s.bind(oracle_socket)
    #/proc/sys/net/core/somaxconn is 128 on Linux, doesn't hurt to set higher just in case it can get higher
    s.listen(150)
    #timeout is needed because if the socket is blocking, we won't be able to pause this script under debugger
    s.settimeout(1)
    
    while 1:
        try:
            #timeout triggered, sleep so that (when debugging) the console could interrupt
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

            