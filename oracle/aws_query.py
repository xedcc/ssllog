import sys
import hmac
import base64
import hashlib
import urllib 

if len(sys.argv) == 1:
    print ('Outputs an HTTP GET link to be used in a browser to check the oracle status')
    print ('Usage: DescribeInstances/DescribeVolumes/GetConsoleOutput InstanceId=<your instance id>/GetUser/ListMetrics AWS-ID AWS-secret')
    print ('Or alternatively: AWS-secret "string containing all components necessary for building a query separated with &"')

args = []
endpoint = default_endpoint = 'ec2.sa-east-1.amazonaws.com'
common_args = [('Expires=2015-01-01'), ('SignatureMethod=HmacSHA256'), ('SignatureVersion=2')]

if len(sys.argv) >= 4:
    if sys.argv[1] == "DescribeInstances" or sys.argv[1] == "DescribeVolumes" or sys.argv[1] == "GetConsoleOutput":
        args.append('Version=2013-10-15')
        endpoint = 'ec2.sa-east-1.amazonaws.com'
    if sys.argv[1] == "GetConsoleOutput":
        args.append(sys.argv[2])
    if sys.argv[1] == "GetUser":
        args.append('Version=2010-05-08')
        endpoint = 'iam.amazonaws.com'
    if sys.argv[1] == "ListMetrics":
        args.append('Version=2010-08-01')
        endpoint = 'monitoring.sa-east-1.amazonaws.com'
        
    args += common_args
    args.append('Action='+sys.argv[1])
    args.append('AWSAccessKeyId='+sys.argv[-2])
    secret = sys.argv[-1]
elif len(sys.argv) != 3:
    print 'Two arguments expected: secret and parameter string'
    exit(0)   
    
else:
    secret = sys.argv[1]
    arg = sys.argv[2].strip()
    args = arg.split('&')
    endpoint = default_endpoint

args.sort()
argstr = ''
for arg in args:
    argstr+= urllib.quote_plus(arg, '=')+'&'
argstr = argstr[:-1]

mhmac = hmac.new(secret, ('GET\n'+endpoint+'\n/\n'+argstr).encode('utf-8'),hashlib.sha256)
base64str = base64.b64encode(mhmac.digest()).strip().decode('utf-8')
urlenc_sig = urllib.quote_plus(base64str)

final_string='https://'+endpoint+'/?'+argstr+'&Signature='+urlenc_sig
print final_string
