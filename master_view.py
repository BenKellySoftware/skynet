import os
import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_v1_5 as Cipher
import Crypto.Random as Random

def decrypt_valuables(ciphertext):
    key = RSA.importKey(open('id_rsa','r').read())
    # This is the one part I don't get, but it works
    # sentinel = Random.new().read(???)
    # Decrypt
    plaintext = Cipher.new(key).decrypt(ciphertext, b'')
    # Break into message and hash, digested hash is 32 bits
    message = plaintext[:-32]
    hash = plaintext[-32:]
    if validate(message, hash):
        print(message)
    else:
        print("Invalid")

def validate(message, hash):
    return SHA256.new(message).digest()==hash

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)