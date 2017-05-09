from Crypto.Hash import SHA256
from Crypto.Random import random

from lib.helpers import read_hex

# 1536 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime)
generator = 2

def create_dh_key():
    private = random.randint(0, int(2**32))
    public = pow(generator, private, prime)
    # print('Keys are: '+str(private)+', '+str(public))
    return (public, private)

def calculate_dh_secret(their_public, my_private):
    # Calculate the shared secret
    shared_secret = pow(their_public, my_private, prime)
    
    # Use digest to output as 32 byte ascii hash (that uses all 256 values instead of the 16 hexdigest gives)
    shared_hash = SHA256.new(bytes(str(shared_secret), "ascii")).digest()
    return shared_hash