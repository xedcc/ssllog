import os
import base64
import struct
import binascii
from hashlib import sha1
import hmac
import rsa
import platform
import multiprocessing

#taken and simplified from pycrypto package: Crypto.Util.number
def long_to_bytes(n):
    s = ''
    n = long(n)
    while n > 0:
        s = struct.pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000'[0]:
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    return s



with open('D:\key3', 'r') as f:
    privkey = rsa.PrivateKey.load_pkcs1(f.read())

pkps=[]
for a in [privkey.d,privkey.p,privkey.q,privkey.coef]:
    ab = long_to_bytes(a)
    if ord(ab[0]) & 0x80: ab=chr(0x00)+ab
    pkps.append(ab)
privkeystring = ''.join([struct.pack(">I",len(pkp))+pkp for pkp in pkps])
priv_repr = binascii.b2a_base64(privkeystring)[:-1]

#generate pubkey from privkey material, see https://bitbucket.org/sybren/python-rsa/src/509b1d657cb8eb942587be862aef10587b5ea2af/rsa/key.py?at=default#cl-592
pubkey = rsa.PublicKey(privkey.n, privkey.e)

eb = long_to_bytes(pubkey.e)
nb = long_to_bytes(pubkey.n)
if ord(eb[0]) & 0x80: eb=chr(0x00)+eb
if ord(nb[0]) & 0x80: nb=chr(0x00)+nb
keyparts = [ 'ssh-rsa', eb, nb ]
keystring = ''.join([ struct.pack(">I",len(kp))+kp for kp in keyparts]) 
public_repr = binascii.b2a_base64(keystring)[:-1]

macdata = ''
for s in ['ssh-rsa','none','imported-openssh-key',privkeystring]:
    macdata += (struct.pack(">I",len(s)) + s)

#construct a SHA1 hash of the given magic string; this will be used as
#key for hmac.
#no passphrase included here because no encryption used
HMAC_key = 'putty-private-key-file-mac-key'
HMAC_key2 = sha1(HMAC_key).digest()
HMAC2 = hmac.new(HMAC_key2,macdata,sha1)

with open('D:\key.ppk','wb') as f:
    f.write('PuTTY-User-Key-File-2: ssh-rsa\r\n')
    f.write('Encryption: none\r\n')
    f.write('Comment: imported-openssh-key\r\n')
    
    #public key section
    f.write('Public-Lines: '+str(int((len(public_repr)+63)/64))+'\r\n')
    for i in range(0,len(public_repr),64):
        f.write(public_repr[i:i+64])
        f.write('\r\n')
    
    #private key section
    f.write('Private-Lines: '+str(int((len(priv_repr)+63)/64))+'\r\n')
    for i in range(0,len(priv_repr),64):
        f.write(priv_repr[i:i+64])
        f.write('\r\n')
        
    #add private mac
    f.write('Private-MAC: ')
    f.write(HMAC2.hexdigest())
    f.write('\r\n')