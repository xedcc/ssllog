import socket,select
import os
import threading
import time
import subprocess
import signal
import shutil
import StringIO
import pprint
import fcntl

database = []
stcppipe_logdir = '/home/default2/Desktop/sshdtest/stcppipelog'
authorized_keys = '/home/default2/Desktop/sshdtest/authorizedkeys'

escrow_host = None
escrow_port = None
is_escrow_registered = False
is_escrow_logged_in = False

db_lock_path = '/home/default2/Desktop/sshdtest/db.lock'
db_lock = open(db_lock_path, 'w')


def __LOCK_DB():
    global db_lock
    try:
        fcntl.flock(db_lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError:
        print 'An already existing lock detected. Blocking now'
        fcntl.flock(db_lock, fcntl.LOCK_EX)
    
def __UNLOCK_DB():
    global db_lock
    fcntl.flock(db_lock, fcntl.LOCK_UN)

def get_txid_index_in_db(txid):
    __LOCK_DB()
    found_index = -1
    for index,item in enumerate(database):
        if item['txid'] == txid:
            found_index = index
            break
    __UNLOCK_DB()
    return found_index

def open_socket_to_stub(txid):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("/tmp/"+txid+"_stub")
    return s
  

def get_database_as_a_string():
    iostr = StringIO.StringIO()
    __LOCK_DB()
    pprint.pprint(database, iostr)
    __UNLOCK_DB()
    return iostr

def escrow_add_pubkey(txid, pubkey, port):
    #make sure the txid is not in the db already
    index = get_txid_index_in_db(txid)
    if index >= 0:
        return (-1, 'txid already added')
    
    #Read the authorized keys file and append it
    akeys_file = open(authorized_keys, 'a')
    akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,permitopen="localhost:'+port+'",command="/usr/bin/python /home/default2/Desktop/sshdtest/stub.py '+txid+'"'+' ssh-rsa '+pubkey+'\n')
    akeys_file.close()
    
    __LOCK_DB()
    database.append({'txid':txid, 'pubkey':pubkey, 'port':int(port), 'time_added_to_db': int(time.time()), 'is_logged_in_now':False, 'last_login_time':0, 'has_finished_banking_session':False, 'time_fin_ban_sess':0, 'tarballsha256hash': '', 'has_escrow_copied_the_data':False, 'time_esc_cop_data':0})
    __UNLOCK_DB()
    return(0,'')
                            
    

def escrow_get_tarball(txid):
    index = get_txid_index_in_db(txid)
    if index < 0:
        return (-1, 'txid does not exist')
    
    __LOCK_DB()
    is_sent_to_escrow = database[index]['has_escrow_copied_the_data']
    tarball_hash = database[index]['tarballsha256hash']
    __UNLOCK_DB()
    
    if is_sent_to_escrow == True:
        return (-1, 'tarball already sent to escrow')
    else:
        try:
            subprocess.call(['curl', '-F', 'localfile=@'+os.path.join(stcppipe_logdir, txid), escrow_host+':'+str(escrow_port), '-H', '"escrow-filename":"'+txid+'"', '-H', '"escrow-hash":"'+tarball_hash+'"' ])
        except:
            return (-1, "Error POSTing the tarball to escrow's server")
                
    index = get_txid_index_in_db(txid)
    if index < 0:
        return (-1, 'txid does not exist even though it existed just a second ago')
    
    __LOCK_DB()
    database[_index]['has_escrow_copied_the_data'] = True
    database[_index]['time_esc_cop_data'] = int(time.time())
    __UNLOCK_DB()
    return (0,'')


def cleanup_and_exit(conn, txid=0,  msg=''):
    if txid !=0:
        index = get_txid_index_in_db(txid)
        if index < 0:
            conn.send('finished Transaction ID not found in database')
            conn.close()
            return
        __LOCK_DB()
        is_logged_in = database[index][is_logged_in_now]
        database[index][is_logged_in_now] = False
        __UNLOCK_DB()
        if is_logged_in == False:
            conn.send('finished Internal error. User was already logged out')
            conn.close()
            return       
    conn.send('finished ' + msg)
    conn.close()
      
         
       
def thread_handle_txid(thisthread, conn, txid):
    index = get_txid_index_in_db(msg_in)
    if index < 0:
        cleanup_and_exit(conn, msg='Transaction ID not found in database')
        return
           
    has_finished = None
    port = None
    is_logged_in = None
    
    __LOCK_DB()
    is_logged_in = database[index]['is_logged_in_now']
    if not is_logged_in:
        database[index]['is_logged_in_now'] = True
        database[index]['last_login_time'] = int(time.time())
        #Copy now the vars which we'll need later, so we could unlock db
        has_finished = database[index]['has_finished_banking_session']
        port = database[index]['port']
    __UNLOCK_DB()

    
    if is_logged_in:
        cleanup_and_exit(conn, msg='This user is already logged in', txid=txid)
        return
    if has_finished:
        #if the user has finished the banking session, it is assumed that he logs in to audit the database
        db_str = get_database_as_a_string()
        conn.send('database ' + db_str)
        #give the stub some time to process data in socket before sending more data
        time.sleep(3)
        cleanup_and_exit(conn, msg='Sent database to user', txid=txid)
        return
    
    #setup to perform banking audit            
    logdir = os.path.join(stcppipe_logdir, txid)
    os.mkdir(logdir)
    start_time = int(time.time())
    stcppipe_proc = subprocess.Popen(['stcppipe', '-d', logdir, '-b', '127.0.0.1', 3128, port])
    
    #wait for a finished signal from the user
    while 1:
        conn.settimeout(10)
        msg_in = None
        try:
            msg_in = conn.recv(1024)
        except:
            #timeout reached
            pass
        if (msg_in == None) and (int(time.time())-start_time > 3600):
            #there was no finished signal for an hour. wrapping up
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)
            shutil.rmtree(logdir)
            cleanup_and_exit(conn, msg='An hour expired. Connection closed', txid=txid)
            return
            
        if msg_in != txid+'-cmd finished':
            #there was no finished signal for an hour. wrapping up
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)
            shutil.rmtree(logdir)
            cleanup_and_exit(conn, msg='Invalid command received. Expected "finished"', txid=txid)
            return
        
        if msg_in == txid+'-cmd finished':
            os.kill(stcppipe_proc.pid, signal.SIGTERM)
            time.sleep(3)            
            finish_time = int(time.time())
            
            tar_path = os.path.join(stcppipe_logdir, txid+'.tar')
            subprocess.call(['tar', 'cf', tar_path, logdir])
            output = subprocess.check_output(['sha256sum', tar_path])
            sha_hash = output.split()[0]
            
            index = get_txid_index_in_db(txid)
            if index < 0:
                cleanup_and_exit(conn, msg='Transaction ID not found in database')
                return
            
            __LOCK_DB()
            database[index]['has_finished_banking_session'] = True
            database[index]['time_fin_ban_sess'] = finish_time
            database[index]['tarballsha256hash'] = sha_hash
            database[index]['is_logged_in_now'] = False           
            __UNLOCK_DB()
            cleanup_and_exit(conn, msg='Session ended successfully ', txid=txid)
            return
    

def escrow_thread(parentthread, conn):
    global is_escrow_registered
    global is_escrow_logged_in
    global escrow_host
    global escrow_port
    
    if is_escrow_logged_in:
        conn.send('finished Already logged in')
        conn.close()
        return
    else:
        is_escrow_logged_in = True
    
    while 1:
        #escrow isn't allowed to make more than one request per minute. Anti DOS measure.
        sleep(60)
        data = conn.recv()
        if not data.startswith('escrow-cmd '):
            conn.send('finished Bogus data received from escrow')
            conn.close()
            return
               
        datalist = data.split()
        if len(datalist) < 2:
            conn.send('finished No command specified')
            conn.close()
            return
        cmd = datalist[1]
        
        if cmd.startswith('add_pubkey '):
            #format: add_pubkey tx-id pubkey forwarding_port
            dummy, txid, pubkey, port = data.split()
            if (len(txid) != 9) or (len(pubkey) > 1000) or (int(port) < 65536 if port.isdigit() else False):
                conn.send('finished Faulty data for adding a pubkey')
                conn.close()
                return
            retval = escrow_add_pubkey(txid, pubkey, port)
            if retval[0] == -1:
                conn.send('finished '+retval[1])
                conn.close()
                return
                       
        if cmd.startswith('get_tarball '):
            #format: get_tarball txid
            dummy, txid = data.split()
            retval = escrow_get_tarball(txid)
            if retval[0] == -1:
                conn.send('finished '+retval[1])
                conn.close()
                return
        
        if cmd.startswith('get_database '):
            db_str = get_database_as_a_string()
            conn.send('database ' + db_str)
            
        if cmd.startswith('register_escrow '):
            #This is assumed to be the very first command that escrow sends after installing this oracle
            #format: register_escrow pubkey escrow_host escrow_port
            if is_escrow_registered:
                conn.send ('finished Escrow already registered')
                conn.close()
                return
            dummy, pubkey, host_ip, port = data.split()
            if (len(pubkey) > 1000) or (int(port) < 65536 if port.isdigit() else False) or (len(host_ip) > 15):
                conn.send('finished Faulty data for registering escrow')
                conn.close()
                return
            akeys_file = open(authorized_keys, 'w')
            akeys_file.write('no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding,command="/usr/bin/python /home/default2/Desktop/sshdtest/stub.py escrow" ssh-rsa '+pubkey+'\n')
            akeys_file.close()
            escrow_host = host
            escrow_port = port
            is_escrow_registered = True
            
                

if __name__ == "__main__":
    
    oracle_socket = '/tmp/oracle-socket4'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #reuse address for multiple runs during testing
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        os.remove(oracle_socket)
    except OSError:
        pass
    open(oracle_socket,'w').close()
    s.bind(oracle_socket)
    #/proc/sys/net/core/somaxconn is 128 on Linux, doesn't hurt to set higher just in case
    s.listen(150)

    while 1: 
        conn, addr = s.accept()
        txid = conn.recv(1024)           
        if data != 'escrow':
            thread = threading.Thread(target= thread_handle_txid, args=(thread, conn, txid))
            thread.start()
        else:
            thread = threading.Thread(target= escrow_thread, args=(thread, conn))
            thread.start()

            