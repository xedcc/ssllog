pref("extensions.lspnr.default_escrow", "dansmith");
pref("extensions.lspnr.escrow_list", "dansmith");
pref("extensions.lspnr.snapshot_id", "snap-81a54469");
pref("extensions.lspnr.msg_ipc", "");
pref("extensions.lspnr.msg_toolbar", "");
pref("extensions.lspnr.first_run", true);
pref("extensions.lspnr.uid", "2134");
pref("extensions.lspnr.start_new_session", false);

pref("extensions.lspnr.escrow_dansmith.dnsname", "ec2-54-207-26-20.sa-east-1.compute.amazonaws.com");
pref("extensions.lspnr.escrow_dansmith.getuserurl", "https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=GetUser&Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=i2jb7ztPm2wpNe6DAzzrpIae55H4wQ0QpP2dtlFp0lk%3D");
pref("extensions.lspnr.escrow_dansmith.listmetricsurl", "https://monitoring.sa-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=ListMetrics&Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-08-01&Signature=hf6Z44d7GDNqRnkSxl2gGJLNPW2%2F8N9NG6aBzL4wLIk%3D");
pref("extensions.lspnr.escrow_dansmith.describeinstancesurl", "https://ec2.sa-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=DescribeInstances&Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2013-10-15&Signature=wGzH6YE2JNhlEsbRi8r%2Bu%2FVb4W1s2W6oMETBWBxB5%2BA%3D");
pref("extensions.lspnr.escrow_dansmith.describevolumesurl", "https://ec2.sa-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=DescribeVolumes&Expires=2015-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2013-10-15&Signature=n9b%2BcKDlEWgy2LPSpg7N%2FPkA%2Bkn1n8pOJtLNOydGtRg%3D");
pref("extensions.lspnr.escrow_dansmith.getconsoleoutputurl", "https://ec2.sa-east-1.amazonaws.com/?AWSAccessKeyId=AKIAI3J2VY5V6W3XDV2Q&Action=GetConsoleOutput&Expires=2015-01-01&InstanceId=i-87e5ad98&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2013-10-15&Signature=%2BmBLaKFFNrRSLSxi5erIt4c2JpUxCUsaS3NP8LvX%2Fjw%3D");

pref("security.ssl3.dhe_dss_aes_128_sha", false);
pref("security.ssl3.dhe_dss_aes_256_sha",false);
pref("security.ssl3.dhe_dss_camellia_128_sha",false);
pref("security.ssl3.dhe_dss_camellia_256_sha",false);
pref("security.ssl3.dhe_dss_des_ede3_sha",false);
pref("security.ssl3.dhe_rsa_aes_128_sha",false);
pref("security.ssl3.dhe_rsa_aes_256_sha",false);
pref("security.ssl3.dhe_rsa_camellia_128_sha",false);
pref("security.ssl3.dhe_rsa_camellia_256_sha",false);
pref("security.ssl3.dhe_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_ecdsa_aes_128_sha",false);
pref("security.ssl3.ecdh_ecdsa_aes_256_sha",false);
pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",false);
pref("security.ssl3.ecdh_rsa_aes_128_sha",false);
pref("security.ssl3.ecdh_rsa_aes_256_sha",false);
pref("security.ssl3.ecdh_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdh_rsa_rc4_128_sha",false);
pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",false);
pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",false);
pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",false);
pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",false);
pref("security.ssl3.ecdhe_rsa_aes_128_sha",false);
pref("security.ssl3.ecdhe_rsa_aes_256_sha",false);
pref("security.ssl3.ecdhe_rsa_des_ede3_sha",false);
pref("security.ssl3.ecdhe_rsa_rc4_128_sha",false);

//Although a non-DH cipher, wireshark wouldn'r decrypt bitcointalk.org which uses a camellia cipher
pref("security.ssl3.rsa_camellia_128_sha",false);
pref("security.ssl3.rsa_camellia_256_sha",false);

pref("security.enable_tls_session_tickets",false);

//tshark can't dissect spdy
pref("network.http.spdy.enabled",false);
pref("network.http.spdy.enabled.v2",false);
pref("network.http.spdy.enabled.v3",false);

pref("network.websocket.enabled",false);
pref("browser.cache.disk.enable", false);
pref("browser.cache.memory.enable", false);
pref("browser.cache.disk_cache_ssl", false);
pref("network.http.use-cache", false);

pref("browser.shell.checkDefaultBrowser", false);
pref("startup.homepage_welcome_url", "");
pref("browser.rights.3.shown", true)
pref("extensions.checkCompatibility", false); 
// The last version of the browser to successfully load extensions. 
//Used to determine whether or not to disable extensions due to possible incompatibilities. 
pref("extensions.lastAppVersion", "100.0.0");
pref("extensions.update.autoUpdate", false); 
pref("extensions.update.enabled", false);
pref("datareporting.policy.dataSubmissionEnabled", false)
