from bitcoinrpc import authproxy
import pyelliptic
import sys
sys.path.append("/home/default/Desktop/sslxchange")
import arithmetic as a

#This private key should already have been imported into bitcoind.
#(bitcoind accepts only privkeys in compressed format, so convert this key into compressed format first
hex_privkey = "02e1e203734abc5f6764bc3ff8f96af308b9859a4c0735456023475ea112caed"
#address corresponding to the privkey
seller_addr_funded_multisig = "19CzQYZGiaENfypuNzMAf3Mg4vs5oE1hgV"

bitcoin_rpc = authproxy.AuthServiceProxy("http://Ulysseys:YourSuperGreatPasswordNumber_83756789458765434jnc@127.0.0.1:8332")

#send the pubkey both signed and plaintext
#the buyer will verifymessage()
def send_to_buyer(signed_msg, pubkey):
    #todo: send to buyer via the website or some other way
    pass

def seller_get_pubkey(hex_privkey):
    return a.privtopub(hex_privkey)

def seller_send_pubkey(pubkey):
    signed_msg = bitcoin_rpc.signmessage(btc_address, pubkey)
    send_to_buyer(signed_msg, pubkey)
    
def buyer_verify_signedmessage(signed_msg,pubkey):
    seller_btc_address = a.pubkey_to_address(pubkey)
    #make sure that this is the address which funded the multisig address
    if (seller_addr_funded_multisig != seller_btc_address):
        raise Exception ("Somebody is trying to spoof the seller's address")
    if bitcoin_rpc.verifymessage(seller_btc_address, signed_msg, pubkey) != True :
        raise Exception ("Failed to verify seller's message")
    #generate a pem for stunnel and send it to seller
    

#we want buyer's stunnel to verify that it is indeed the seller we are stunnel'ing SSL traffic to
#but stunnel only allows verification of certificates signed by a Certficate Authority (it doesn't allow self-signed certs for verification)
#instead of having user generate a CA cert (which may be error-prone), SSLlogs comes with a pre-generated CA certificate
#the user can use this CA cert to sign his own cert
#Ideally this should be done automatically during the installation phase
#Remember, all this is done to exonerate the escrow from accusations of logging buyer's banking credentials

def seller_generate_cert():
    import subprocess
    subprocess.check_output(['openssl', 'genrsa', '-out', 'seller.key', '4096'])
    