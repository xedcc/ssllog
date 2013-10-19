from bitcoinrpc import authproxy
import sys
sys.path.append("/home/default/Desktop/sslxchange") 
import addrgen
import pickle
import urllib2
import urllib
import json
import requests

#address = addrgen.get_addr(addrgen.gen_eckey(compressed=True))
#get_addr returns compressed priv key, whereas we need an uncompressed one. Use bitadress.org to convert
addresses = [('1P9kcHjJ2f7PwW2qb5FwMvaH2k7GMPCz8q', '5JnRh5si1TXfAfA5NJWsZeQXKJvSVHfY1A7gannRNw3iy3dkSoV'), ('1HQ1fcZ9hXZZeDySb1S8dsmuECcu7WKpq3', '5JJqKjbsypVb4ZgY7rYAoaJ95h89Y2k9ecKxqCgsX1TbQo3aKdc'), ('19CzQYZGiaENfypuNzMAf3Mg4vs5oE1hgV', '5HqZCywSNWo2bYfkL1Rqzt3N2bF3nfEccohGpq9nr92qRi5NVcD')]

#access = authproxy.AuthServiceProxy("http://9cbfc6df-1f0d-44d3-a893-c836c04d6ad9:pablo.lv555@rpc.blockchain.info:80")
my_address = "1KSuZeo4TuD9DjbQrrTUao5YSfUQ3fNNVn"
counterparty_address = "1KSuZeo4TuD9DjbQrrTUao5YSfUQ3fNNVn"
escrow_address  = "1NsUEnwDSWVz4t9UGzz4ERQb8wVdHbBvbX"

access_local = authproxy.AuthServiceProxy("http://Ulysseys:YourSuperGreatPasswordNumber_83756789458765434jnc@127.0.0.1:8332")

multisig = access_local.createmultisig(2 ,[my_address,counterparty_address,escrow_address])
#print multisig

#url = "https://blockchain.info/unspent?active=1KSuZeo4TuD9DjbQrrTUao5YSfUQ3fNNVn"
#fp = urllib2.urlopen(url)
#data = fp.read()
#print data

#with open("unspent", 'wb') as output:
        #pickle.dump(data, output, pickle.HIGHEST_PROTOCOL)



#Alice = {}
#Bob = {}
#Escrower ={}
#print access.importprivkey(addresses[0][1])
#print access.importprivkey(addresses[1][1])
#print access.importprivkey(addresses[2][1])

#Alice ['pubkey'] = access.validateaddress(addresses[0][0])['pubkey']
#Bob ['pubkey'] = access.validateaddress(addresses[1][0])['pubkey']
#Escrower['pubkey'] = access.validateaddress(addresses[2][0])['pubkey']

#print Alice ['pubkey']
#print Bob ['pubkey']
#print Escrower['pubkey']

sorted_json_data = []

#returns how many outputs (sorted descendingly) need to be spent, sum of those outputs)
def select_outputs(satoshis_needed):
        outputs_to_spend_total_value = 0
        for index, output in enumerate(sorted_json_data):
                if outputs_to_spend_total_value >= satoshis_needed:
                        break 
                outputs_to_spend_total_value += output['value']
        #sanity check: make sure there isn't insufficient funds
        if outputs_to_spend_total_value < satoshis_needed:
                raise Exception("insufficient funds for the address")
        return [index, outputs_to_spend_total_value]
    
#txs format:
#multiple inputs ABC... are allowed. Only two output: output Y - the BTC being sold + a bond as one output, and output Z - the change address which should be one of the inputs addresses ABC....The change address is mandatory because with only a multisig output, blockchain.info will only show the transaction after it is confirmed
def confirm_tx (txid, multisig_address, btc_for_multisig):
        r = requests.get("https://blockchain.info/rawtx/" + txid)
        if r.status_code != 200:
                return r.reason + " transaction has not yet been seen by the network"	
	
	inputs_sum, outputs_sum = 0
        #build a list of unique input addresses, a list of output addresses
        inputs = set()
        for input in r.json()['inputs']:
                inputs.add(input['prev_out']['addr'])
		inputs_sum += input['prev_out']['value']          
        outputs = []
        for output in r.json()['out']:
                outputs.append(output['addr'])
		outputs_sum += output['value']
		
	#make sure minimal fee has been included
	if inputs_sum - outputs_sum < 50000:
		return "Invalid tx: miner's fee is less than 0,0005 BTC"

	#only two output addresses allowed - one starts with "3" (multi-signature address) and another is one of the inputs addresses

        if len(outputs) != 2:
                return "Invalid tx: exactly two outputs are expected"
        if outputs[0][:1] == '3': 
		multisig_index = 0
		standard_index = 1
        else if outputs[1][:1] == '3':
		multisig_index=1
		standard_index = 0
        else:
                return "Invalid tx: can't find multisig output address starting with '3' "   
        if not (outputs[standard_index] in inputs):
                return "Invalid tx: change address is supposed to be one of the inputs' addresses"
	#make sure change address is a regular address starting with "1'
	if outputs[standard_index][:1] != '1':
		return "Invalid tx: change address is not a regular address"
        if btc_for_multisig*pow(10,8) != r.json()['out'][multisig_index]['value']:
                return "Invalid tx: multisig address value doesn't match the expected value"
        
        #blockchain.info has a bug which mangles the multisig addresses
        #to make sure that the mangled address is our multisig_address, we need to get our multisig_address's hash160
        #and compare it to the hash160 of the tx's output scripts
        r = requests.get("https://blockchain.info/rawaddr/" + multisig_address)
        if r.status_code != 200:
                return r.reason + " Can't find multisig address"
        multisig_hash160 = r.json()['hash160']
        
        #output scripts are only exposed on tx HTML page
	r2 = requests.get("http://blockchain.info/tx/" + txid + "?show_adv=true")	
	hashes = []
	offset=0
	#find all 40-char hashes after the string 'OP_HASH160'
	while True:
		offset = r2.text.find('OP_HASH160', offset)
		if offset == -1:
			break
		hashes.append(r2.text[offset+len('OP_HASH160')+1:offset+len('OP_HASH160')+1+40])
		offset = offset+len('OP_HASH160')+1+40
	if len(hashes) != 2:
		return "Invalid tx: only two output scripts are expected"
	if multisig_hash160 != hashes[multisig_index]:
		return "Invalid tx: couldn't find the multisig address among the outputs"
	
	return "Success"
                
def create_and_sign_multisig():
	sellers_inputs = sellers_txid, multisig_index
	my_inputs = mytx, my_multisig_inputs
	rawtx = access_local.createrawtransaction([{"txid":sellers_txid,"vout":}, {"txid":sellers_txid,"vout":}], addresses)
	signedrawtx = access_local.signrawtransaction(rawtx, outputs_signrawtx, ["5JA7hhEWF9nsFBXdwwkQK9JvLAG6c2fRUGki4KPUtqsjC3ESScF"])
	#give seller the signedrawtx
	
def sign_and_push_multisig(signedrawtx):
	raw_decoded = access_local.decoderawtransaction(signedrawtx)
	#make sure inputs and outputs match and miner fee in place
	r = requests.post("https://blockchain.info/pushtx", params={'tx':signedrawtx})
	

if __name__ == "__main__":
        btc_to_spend = 0.11
        miners_fee = 0.0001*pow(10,8)
        satoshis_to_spend = btc_to_spend*pow(10,8)
        
        with open('/home/default/Desktop/sslxchange/unspent', 'rb') as input:
                data = pickle.load(input)
        #json_data = json.JSONDecoder().decode(data)
        json_data = data
        global sorted_json_data
        sorted_json_data = sorted(json_data['unspent_outputs'],key=lambda x:x['value'], reverse=True)
	
	#blockchain.info has a bug on "unspent" pages - it shows "tx_hash" in incorrect byte order.
	#This bug should be fixed any moment. So, first check if it has been fixed by taking a tx_hash, check if it exists and if it doesn't exist (i.e. the bug is still there), reverse byte order.
	tx_hash = json_data['unspent_outputs'][0]['tx_hash']
	r = requests.get("https://blockchain.info/tx/" + tx_hash)
        if r.status_code != 200:
                for output in json_data['unspent_outputs']:
			txhash = output['tx_hash']
			for i in range(1,33):
				newtxhash += txhash[-i*2:64-(i-1)*2]
			output['tx_hash'] = newtxhash
		#last sanity check - make sure the transaction with reversed byte order exists
		r = requests.get("https://blockchain.info/tx/" + json_data['unspent_outputs'][0]['tx_hash'])
		if r.status_code != 200:
			raise Exception("Can't find outputs for the source address")


        
        [number_of_outputs_to_spend, sum_of_outputs] = select_outputs(satoshis_to_spend)
        
        outputs_createrawtx = []
        outputs_signrawtx = []
        for output in sorted_json_data[0:number_of_outputs_to_spend]:
                output_dict = {"txid":output['tx_hash'],"vout":output['tx_output_n']}
                outputs_createrawtx.append(output_dict)
                output_dict = {"txid":output['tx_hash'],"vout":output['tx_output_n'], "scriptPubKey":output['script']}
                outputs_signrawtx.append(output_dict)
                
        addresses = {multisig['address']:satoshis_to_spend/pow(10,8), my_address:((sum_of_outputs-satoshis_to_spend-miners_fee)/pow(10,8))}
       
        rawtx = access_local.createrawtransaction(outputs_createrawtx, addresses)
        mytxid = access_local.decoderawtransaction(rawtx)["txid"]
        signedrawtx = access_local.signrawtransaction(rawtx, outputs_signrawtx, ["5JA7hhEWF9nsFBXdwwkQK9JvLAG6c2fRUGki4KPUtqsjC3ESScF"])
        print signedrawtx
        
        r = requests.post("https://blockchain.info/pushtx", params={'tx':signedrawtx})
        #Transaction Submitted HTTP/1.1 200 OK
        
        print r