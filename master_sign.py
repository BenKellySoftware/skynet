import os
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256
import Crypto.Signature.PKCS1_v1_5 as Signer


def sign_file(file):
    # Load RSA Key
    key = RSA.importKey(open('id_rsa','r').read())
    signature = sign(file, key)
    #RSA Signature mode, Deprecated
    # The sign outputs a tuple that has no second value for some weird reason
    # signature = key.sign(file, "")[0]

    return signature + file

def sign(file, key):
    hash = SHA256.new(file)
    return Signer.new(key).sign(hash) 


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
