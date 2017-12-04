import os
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256
import Crypto.Signature.PKCS1_v1_5 as Signer

def hack(location):
    key = RSA.importKey(open('id_rsa','r').read())
    hacked = key.hack(location)
    for x in hacked:
    	download_all