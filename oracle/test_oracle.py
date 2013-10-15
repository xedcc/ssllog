#This script perform the following tests on oracle.py:

#Register escrow and check authkeysfile
#Add pubkey and check authkeysfile and database
#User1 ssh, visit sites, finish session and check database (specifically tarball hash)
#Add another pubkey and check authkeysfile
#User1 ssh again and check database
#Get tarball make sure hashes match and database changed
#Escrow logs out, logs back in and adds pubkey with a port that is busy
#user2 logs in and just waits, user3 with a busy port logs in
#Escrow check database (user3 port should change)

#Make sure that "oracle.py testing " and "post_server.py" are running
#Make sure that this test is run from the same directory where stub.py resides


import subprocess
import select
import sys
import fcntl
import time
import re
import os

pubkey_escrow = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQClBsy9E5wPNvuc0ACLDdY1RLrzAeTcyvOAQ/W+2y7KV4cu96LuiNDFLk44WSVKAK/+StGN/PjOaBxLybRugBbCEH7wGRkYb3D1EdOA2ybgTj2Qqpc+9x+RiEZwj3wZywj6qc/35JZHdWy+rsbrNOiz4/aLTyBdKW9D3ZPDUikLekMmcw+mbGV7oVPZOIbpKOmvPI6MmiM3SradS0B4nbemm3TXKe5CPX9JDz9fX2yjGFKoSXC1WiZnbfHmo5R6KRXsJ17mEENgalv85T4rZmq1Kup/dDncGozFUone0MY7ocxUskQWy3MxMOxwPqOZMmNLPzux7sWZmGHKlgcrKO8P'

pubkey_user1 = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDGyGDPY3PYQ3OHctbWEzpMDrQa29sXouiydQEERLU8zUH8UEByglZs/B9lRTiN9UxjdC21kJu5aWtn0iXB3ehxsvUSkOxYku7R7x/N0SZZzKpmkfZCpWmzZh4wGR7VjhSBYbvlARw6vcDLqg+ot4tvg9pGbXdYGOrX07RB3MxCzOa0r0bK6V1sAUoXs8JgxNDy31syTcPrIkegJp8yHM4s5s4DFQ5yteSnXW15gvIt8+/dqog7l0UbRc6vbbyKK4Ms2dMCBDIID6VXkDRQtllUdaqKVoTDX+i1dkuMcm+It3+4wAhPwfreYdTwygdNWS7EQinKq4pGYofKJ3yYp5RX'

pubkey_user2 = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQCqrY7EJIjAd3Iy/4BzVmmwm7PSTI2mtATOUW3OSMj5RVIzbZa0qDIoDYmKpI0VkPrhistGGhz/4K4h30Y3aCOlBRanfGiypLlmnLyJ/ryM/KOsbj0J+dj2ISZIZWXCZKMgpT9Fk0qHmwlK5zXO2q/MJFy0krj9Rh8/A1J8B8mGZK49OXrlD4dOfxYrCSO7r7fzckDELAi0RUBvsfQ83jwLb7RqT4LX/wsrgk1ojxMVVIfuZwhpZRKIdkqS8kXsIVanWC9QZYstwgTdeHW9vkKf27tRiVqP02ZvRBTTUxYe4pXaVBQaSJZyEXxf0pcR98cL0Y1FCzrrtA7HJwQlWuER'

pubkey_user3 = 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDtLCIqoZwIC6Pj3qBgn6i0sXGzb01lRZYZDqv1YXUqQbqWUJAbTR6OvvKDvlq1ssVs/vicsEdZPID3gosPK5ZlwsHNRAZ7ohyy2oVPefR4DDijlg6MEIAEcK/zTn5S2GLoIvSMD63ZAh0W7idsI2PZiZJ2QpCZxigQn5vT5XZMmaI8JTtKbl8V7/O7yB8gs0m6o2HXJqJXD1068TwUzXfgQC332cy4JeeEDfqTkk34rPdsRSNA1df9wYFgbT5m+4PpeZ9Uy85OfMcT9dxpeF6XSJ4/MypPx8QpcuWtByQ5QPdBUdyUzzZ5B5/u6IK3GOgXdAONLDsR+b16tvEDo10T'

installdir = os.path.dirname(os.path.realpath(__file__))
authorized_keys = os.path.join(installdir, '.ssh', 'authorized_keys')


ak_escrow_std = 'no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding,command="/usr/bin/python ' + os.path.join(installdir, 'stub.py') + ' escrow-id"'
ak_user_std1 = 'no-pty,no-agent-forwarding,no-user-rc,no-X11-forwarding,permitopen="localhost:'
ak_user_std2 = '",command="/usr/bin/python ' + os.path.join(installdir, 'stub.py')
ssh_port = 22

test_register_escrow = False
test_keyfile_after_escreg = False
test_add_first_pubkey = False
test_keyfile_after_first_pubkey = False
test_request_db = False
test_db = False
test_start_user_sshd = False
test_send_requests = False
test_send_finished_msg = False
test_get_db_to_check_hash = False
test_tarball_hash_in_db = False
test_add_second_pubkey = False
test_keyfile_after_second_pubkey = False
test_start_user_sshd_again = False
test_user_db_after_second_login = False
test_get_tarball = False
test_tarball_hash_match = False
test_get_db_after_getting_tarball = False
test_db_after_getting_tarball = False
test_escrow_logout = False
test_escrow_login = False
test_add_third_pubkey_with_busy_port = False
test_start_user2_sshd = False
test_start_user3_sshd = False
test_get_db_with_3_users = False
test_db_with_3_users = False
test_keyfile_with_3_users = False



#This will hold user's stderr after the escrow adds a new user and the user logs in. It temporary holds this script's stdin
user_stderr = user2_stderr = user3_stderr = 0
user_proc = user2_proc = user3_proc =  None
escrow_db = user_db = user2_db = user3_db = None

is_user_ssh_ready = False
is_escrow_db_ready = False
is_user_db_ready = False
is_user2_db_ready = False
is_user3_db_ready = False
is_escrow_registered = False
is_escrow_loggedout = False
is_pubkey_added = False
is_hash_matched = False
is_hash_mismatched = False
is_user_session_finished = False
is_user2_session_finished = False
is_user3_session_finished = False
is_user3_newport_received = False


escrow_proc = subprocess.Popen(['ssh', '-i', os.path.join(installdir, 'escrow_key'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)

while 1:
    rlist, wlist, xlist = select.select([escrow_proc.stderr, user_stderr, user2_stderr, user3_stderr],[],[], 0.5)
    was_data = False
    if len(rlist) > 0:
        for fd in rlist:  
            if fd == escrow_proc.stderr:
                data = escrow_proc.stderr.readline()
                if not data: continue
                was_data = True
                print ('escrow ssh>>> '+data)
                if data.startswith('database'):
                    is_escrow_db_ready = True
                    escrow_db = data
                elif data.startswith('Escrow successfully registered'):
                    is_escrow_registered = True
                elif data.startswith('Public key successfully'):
                    is_pubkey_added = True
                elif data.startswith('Tarball successfully sent'):
                    is_hash_matched = True
                elif data.startswith('Session finished. Escrow reported hash mismatch'):
                    is_hash_matched = True
                elif data.startswith('Session finished. Escrow initiated disconnect'):
                    is_escrow_loggedout = True
                continue
            if fd == user_stderr:
                data = user_stderr.readline()
                if not data: continue
                was_data = True
                print ('user ssh>>> '+data)
                if data.startswith('Tunnel ready'):
                    is_user_ssh_ready = True
                if data.startswith('database'):
                    is_user_db_ready = True
                    user_db = data
                if data.startswith('Session finished. Session ended successfully'):
                    is_user_session_finished = True
                continue
            if fd == user2_stderr:
                data = user2_stderr.readline()
                if not data: continue
                was_data = True
                print ('user2 ssh>>> '+data)
                if data.startswith('database'):
                    is_user2_db_ready = True
                    user2_db = data
                if data.startswith('Session finished. Session ended successfully'):
                    is_user2_session_finished = True
                continue
            if fd == user3_stderr:
                data = user3_stderr.readline()
                if not data: continue
                was_data = True
                print ('user3 ssh>>> '+data)
                if data.startswith('Session finished. Please reconnect and use port'):
                    is_user3_newport_received = True
                    user3_new_port = data[len('Session finished. Please reconnect and use port'):].split()[0]
                if data.startswith('database'):
                    is_user3_db_ready = True
                    user3_db = data
                if data.startswith('Session finished. Session ended successfully'):
                    is_user3_session_finished = True
                continue
    if was_data: continue
    
    if not test_register_escrow:
        escrow_proc.stdin.write('register_escrow '+pubkey_escrow+' 127.0.0.1 8045'+'\n')
        escrow_proc.stdin.flush()
        print 'Sent register_escrow'
        test_register_escrow = True
        continue
    
    if not test_keyfile_after_escreg:
        if not is_escrow_registered:
            continue
        akeys_file = open(authorized_keys, 'r')
        fcntl.flock(akeys_file, fcntl.LOCK_EX)
        file_data = akeys_file.read()
        fcntl.flock(akeys_file, fcntl.LOCK_UN)
        akeys_file.close()
        if file_data != ak_escrow_std+' ssh-rsa '+pubkey_escrow+'\n':
            print 'FAILED 1st Authorized keys file test'
            exit(0) 
        print 'PASSED register_escrow test'
        test_keyfile_after_escreg = True
        continue
    
    if not test_add_first_pubkey:
        is_pubkey_added = False
        escrow_proc.stdin.write('add_pubkey 2341-0978 '+pubkey_user1+' 2134'+'\n')
        escrow_proc.stdin.flush()
        print ('Sent add_pubkey')
        test_add_first_pubkey = True
        continue
    
    if not test_keyfile_after_first_pubkey:
        if not is_pubkey_added:
            continue
        akeys_file = open(authorized_keys, 'r')
        fcntl.flock(akeys_file, fcntl.LOCK_EX)
        file_data = akeys_file.read()
        fcntl.flock(akeys_file, fcntl.LOCK_UN)
        akeys_file.close()
        if file_data != ak_escrow_std+' ssh-rsa '+pubkey_escrow+'\n'+ak_user_std1+'2134'+ak_user_std2+' 2341-0978" ssh-rsa '+pubkey_user1+'\n':
            print 'FAILED 2nd Authorized keys file test'
            exit(0)          
        print 'PASSED add pubkey test'
        test_keyfile_after_first_pubkey = True
        continue
    
    if not test_request_db:
        is_escrow_db_ready = False
        escrow_proc.stdin.write('get_database'+'\n')
        escrow_proc.stdin.flush()
        print ('Requested the database')
        test_request_db = True
        continue
    
    if not test_db:
        if not is_escrow_db_ready:
            continue
        #we can't include time_added value, since it is not contant
        if not re.match("database "+
                        re.escape("[{") +
                        "'escrow_fetched_tarball': 0" +
                        ", 'added': " + "[0-9]{10,10}" +
                        ", 'hash': ''" +
                        ", 'last_login_time': 0" +
                        ", 'finished_banking': 0" +
                        ", 'is_logged_in_now': False" +
                        ", 'sshd_ppid': 0" +
                        ", 'pubkey': '" + re.escape(pubkey_user1)+ "'"+
                        ", 'port': 2134" +
                        ", 'txid': '2341-0978'" +
                        re.escape("}]\n"), escrow_db):
            print 'FAILED database compare'
            exit(0)
        print 'PASSED database compare'
        test_db = True
        continue
    
    if not test_start_user_sshd:
        print 'Starting user ssh'
        user_proc = subprocess.Popen(['ssh', '-o', 'IdentitiesOnly=yes', '-i', os.path.join(installdir, 'key1'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        user_stderr=user_proc.stderr
        test_start_user_sshd = True
        continue
    
    if not test_send_requests:
        if not is_user_ssh_ready:
            continue
        print('Sending various page requests')
        devnull = open('/dev/null', 'w')
        subprocess.call(['curl', '-x', 'https://127.0.0.1:2134', 'https://www.youtube.com'], stdout=devnull, stderr=devnull)
        subprocess.call(['curl', '-x', 'https://127.0.0.1:2134', 'https://www.wikipedia.org'], stdout=devnull, stderr=devnull)
        subprocess.call(['curl', '-x', 'https://127.0.0.1:2134', 'https://www.google.com'], stdout=devnull, stderr=devnull)
        subprocess.call(['curl', '-x', 'https://127.0.0.1:2134', 'https://www.twitter.com'], stdout=devnull, stderr=devnull)
        subprocess.call(['curl', '-x', 'https://127.0.0.1:2134', 'https://www.ebay.com'], stdout=devnull, stderr=devnull)
        devnull.close()
        test_send_requests = True
        continue
    
    if not test_send_finished_msg:
        print ('Sending sslkey message to user ssh')
        user_proc.stdin.write('sslkey CLIENT_RANDOM 5256b4caa2f7ac21baf61e56e266b258a046ec15c610a7145bacd49215310383 0fef805068b8a102a11a21a8b02f86cbbba91d0f15faa36ac69d52ec22ffae84f67147f18e7d92036624025deb751e94\n')
        test_send_finished_msg = True
        continue
    
    if not is_user_session_finished:
        #let the user kill stcppipe, create tarball and propagate changes to db
        continue
    
    if not test_get_db_to_check_hash:
        is_escrow_db_ready = False
        escrow_proc.stdin.write('get_database'+'\n')
        escrow_proc.stdin.flush()
        print ('Requested the database to check the tarball hash')
        test_get_db_to_check_hash = True
        #need some time for oracle to respond
        time.sleep(3)
        continue
    
    if not test_tarball_hash_in_db:
        if not is_escrow_db_ready:
            continue
        output = subprocess.check_output(['sha256sum', os.path.join(installdir, 'stcppipelog', '2341-0978.tar')])
        sha_hash = output.split()[0]
        if not re.match("database " +
                        re.escape("[{") +
                        "'escrow_fetched_tarball': 0"
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': '"+"[0-9,a-f]{64,64}"+"'"+
                        ", 'last_login_time': "+"[0-9]{10,10}"+
                        ", 'finished_banking': "+"[0-9]{10,10}"+
                        ", 'is_logged_in_now': False"+
                        ", 'sshd_ppid': "+"[0-9]{3,5}"+
                        ", 'pubkey': '"+re.escape(pubkey_user1)+"'" +
                        ", 'port': 2134"
                        ", 'txid': '2341-0978'" +
                        re.escape("}]\n"), escrow_db):
            print 'FAILED database compare'
            exit(0)
        print 'PASSED database compare'
        test_tarball_hash_in_db = True
        continue
    
    if not test_add_second_pubkey:
        is_pubkey_added = False
        escrow_proc.stdin.write('add_pubkey 6534-1120 '+pubkey_user2+' 7656'+'\n')
        escrow_proc.stdin.flush()
        print ('Sent add_pubkey')
        test_add_second_pubkey = True
        continue
    
    if not test_keyfile_after_second_pubkey:
        if not is_pubkey_added:
            continue
        akeys_file = open(authorized_keys, 'r')
        fcntl.flock(akeys_file, fcntl.LOCK_EX)
        file_data = akeys_file.read()
        fcntl.flock(akeys_file, fcntl.LOCK_UN)
        akeys_file.close()
        if file_data != ak_escrow_std+' ssh-rsa '+pubkey_escrow+'\n'+ak_user_std1+'2134'+ak_user_std2+' 2341-0978" ssh-rsa '+pubkey_user1+'\n'+ak_user_std1+'7656'+ak_user_std2+' 6534-1120" ssh-rsa '+pubkey_user2+'\n':
            print 'FAILED 3rd Authorized keys file test'
            exit(0)          
        print 'PASSED add pubkey test 3'
        test_keyfile_after_second_pubkey = True
        continue
    
    if not test_start_user_sshd_again:
        print 'Starting user ssh'
        is_user_db_ready = False
        user_proc = subprocess.Popen(['ssh', '-o', 'IdentitiesOnly=yes', '-i', os.path.join(installdir, 'key1'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        user_stderr=user_proc.stderr
        test_start_user_sshd_again = True
        continue
    
    if not test_user_db_after_second_login:
        if not is_user_db_ready:
            continue
        if not re.match("database " +
                       re.escape("[{")+
                       "'escrow_fetched_tarball': 0"+
                       ", 'added': " + "[0-9]{10,10}" +
                       ", 'hash': '" + "[0-9,a-f]{64,64}"+"'"+ 
                       ", 'last_login_time': " + "[0-9]{10,10}"+
                       ", 'finished_banking': " + "[0-9]{10,10}"+
                       ", 'is_logged_in_now': True" +
                       ", 'sshd_ppid': " + "[0-9]{3,5}"+
                       ", 'pubkey': '" +re.escape(pubkey_user1)+ "'"+
                       ", 'port': 2134"+
                       ", 'txid': '2341-0978'"+
                       re.escape("}, {")+
                       "'escrow_fetched_tarball': 0,"+
                       " 'added': " +"[0-9]{10,10}"+
                       ", 'hash': ''" +
                       ", 'last_login_time': 0" +
                       ", 'finished_banking': 0" + 
                       ", 'is_logged_in_now': False"+
                       ", 'sshd_ppid': 0"+
                       ", 'pubkey': '" +re.escape(pubkey_user2) +"'"+
                       ", 'port': 7656" +
                       ", 'txid': '6534-1120'" +
                       re.escape("}]\n"), user_db):
            print ('Failed database compare No.2')
            exit(0)
        print 'Success in database compare No2'
        test_user_db_after_second_login = True
        continue
    
    if not test_get_tarball:
        escrow_proc.stdin.write('get_tarball 2341-0978'+'\n')
        escrow_proc.stdin.flush()
        print ('Sent get_tarball')
        test_get_tarball = True
        continue
            
    if not test_tarball_hash_match:
        if is_hash_matched:
            print ('PASSED tarball hash matched')
            test_tarball_hash_match = True
            continue
        elif is_hash_mismatched:
            print ('FAILED tarball hash matched')
            exit(0)
        else:
            continue
        
    if not test_get_db_after_getting_tarball:
        is_escrow_db_ready = False
        escrow_proc.stdin.write('get_database'+'\n')
        escrow_proc.stdin.flush()
        print ('Requested the database to check the tarball hash')
        test_get_db_after_getting_tarball = True
        continue
    
    if not test_db_after_getting_tarball:
        if not is_escrow_db_ready:
            continue
        if not re.match("database " +
                        re.escape("[{") +
                        "'escrow_fetched_tarball': "+"[0-9]{10,10}"+
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': '"+"[0-9,a-f]{64,64}"+"'"+
                        ", 'last_login_time': "+"[0-9]{10,10}"+
                        ", 'finished_banking': "+"[0-9]{10,10}"+
                        ", 'is_logged_in_now': False"+
                        ", 'sshd_ppid': "+"[0-9]{3,5}"+
                        ", 'pubkey': '"+re.escape(pubkey_user1)+"'" +
                        ", 'port': 2134" +
                        ", 'txid': '2341-0978'" +
                        re.escape("}, {")+
                      
                        "'escrow_fetched_tarball': 0" +
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': ''"+
                        ", 'last_login_time': 0"+
                        ", 'finished_banking': 0" +
                        ", 'is_logged_in_now': False" +
                        ", 'sshd_ppid': 0" +
                        ", 'pubkey': '"+re.escape(pubkey_user2)+"'" +
                        ", 'port': 7656" +
                        ", 'txid': '6534-1120'" +
                        re.escape("}]\n"), escrow_db):
            print ('FAILED database compare No3')
            exit(0)
        print 'PASSED database compare No3'
        test_db_after_getting_tarball = True
        continue
    
    if not test_escrow_logout:
        is_escrow_loggedout = False
        escrow_proc.stdin.write('exit'+'\n')
        escrow_proc.stdin.flush()
        print ('Sent exit')
        test_escrow_logout = True
        continue
    
    if not test_escrow_login:
        if not is_escrow_loggedout:
            continue
        print ('Starting an escrow ssh session')
        escrow_proc = subprocess.Popen(['ssh', '-i', os.path.join(installdir, 'escrow_key'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        if escrow_proc.poll() != None:
            #the process returned an exit code
            print ('FAILED esrow login')
            exit(1)
        else:
            print ('PASSED escrow login')
            test_escrow_login = True
            continue
    
    if not test_add_third_pubkey_with_busy_port:
        is_pubkey_added = False
        #post server is listening on port 8045
        escrow_proc.stdin.write('add_pubkey 0000-1111 '+pubkey_user3+' 8045'+'\n')
        escrow_proc.stdin.flush()
        print ('Sent add_pubkey')
        test_add_third_pubkey_with_busy_port = True
        continue
    
    if not test_start_user2_sshd:
        print ('Starting a user2 ssh session')
        user2_proc = subprocess.Popen(['ssh', '-i', os.path.join(installdir, 'key2'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        user2_stderr = user2_proc.stderr
        time.sleep(6)
        if user2_proc.poll() != None:
            #the process returned an exit code
            print ('FAILED user2 login')
            exit(1)
        else:
            print ('PASSED user2 login')
            test_start_user2_sshd = True
            continue
    
    if not test_start_user3_sshd:
        print ('Starting a user3 ssh session')
        user3_proc = subprocess.Popen(['ssh', '-i', os.path.join(installdir, 'key3'), 'localhost', '-p', str(ssh_port)], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        user3_stderr = user3_proc.stderr
        time.sleep(6)
        if user3_proc.poll() == None:
            #the process did not returned an exit code as expected
            print ('FAILED user3 login')
            exit(1)
        else:
            print ('PASSED user3 login')
            test_start_user3_sshd = True
            continue
        
    if not test_get_db_with_3_users:
        if not is_user3_newport_received:
            continue
        is_escrow_db_ready = False
        escrow_proc.stdin.write('get_database'+'\n')
        escrow_proc.stdin.flush()
        print ('Requested db with 3 users')
        test_get_db_with_3_users = True
        continue
    
    if not test_db_with_3_users:
        if not is_escrow_db_ready:
            continue
        if not re.match("database " +
                        re.escape("[{") +
                        "'escrow_fetched_tarball': "+"[0-9]{10,10}" +
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': '"+"[0-9,a-f]{64,64}"+"'"+
                        ", 'last_login_time': "+"[0-9]{10,10}"+
                        ", 'finished_banking': "+"[0-9]{10,10}"+
                        ", 'is_logged_in_now': False"+
                        ", 'sshd_ppid': "+"[0-9]{3,5}"+
                        ", 'pubkey': '"+re.escape(pubkey_user1)+"'" +
                        ", 'port': 2134" +
                        ", 'txid': '2341-0978'" +
                        re.escape("}, {")+
                      
                        "'escrow_fetched_tarball': 0" +
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': ''" +
                        ", 'last_login_time': "+"[0-9]{10,10}"+
                        ", 'finished_banking': 0" +
                        ", 'is_logged_in_now': True"+
                        ", 'sshd_ppid': "+"[0-9]{3,5}"+
                        ", 'pubkey': '"+re.escape(pubkey_user2)+"'" +
                        ", 'port': 7656" +
                        ", 'txid': '6534-1120'" +
                        re.escape("}, {")+
            
                        "'escrow_fetched_tarball': 0" +
                        ", 'added': "+"[0-9]{10,10}"+
                        ", 'hash': ''" +
                        ", 'last_login_time': "+"[0-9]{10,10}"+
                        ", 'finished_banking': 0" +
                        ", 'is_logged_in_now': False" +
                        ", 'sshd_ppid': "+"[0-9]{3,5}" +
                        ", 'pubkey': '"+re.escape(pubkey_user3)+"'" +
                        ", 'port': "+str(user3_new_port) +
                        ", 'txid': '0000-1111'" +
                        re.escape("}]\n"),escrow_db):
           
            print ('FAILED database compare No4')
            exit(0)
        print 'PASSED database compare No4'
        test_db_with_3_users = True
        continue
    
    print "ALL TESTS FINISHED SUCCESSFULLY"
    exit(0)
        
    
        
        
            
        
    
        
        
            
        
        
        