import struct

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util import Counter

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.hmac = None
        self.ctr = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            # print("Shared hash: {}".format(shared_hash))
        
        #Create Hmac
        self.hmac = HMAC.new(shared_hash, digestmod=SHA256)
        
        # Uses first 4 bytes of shared hash
        self.ctr = Counter.new(128, initial_value=int.from_bytes(shared_hash[4:], byteorder='big'))
        
        # Using CTR AES to encrypt with incrimenting counter thats the same on both ends
        self.cipher = AES.new(shared_hash, AES.MODE_CTR, counter=self.ctr)

    def send(self, data):
        if self.cipher:
            encrypted_data = self.cipher.encrypt(data)
            mac = self.mac(encrypted_data)
            msg = encrypted_data + mac
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
                
        else:
            msg = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(msg))
        self.conn.sendall(pkt_len)
        self.conn.sendall(msg)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        
        msg = self.conn.recv(pkt_len)
        if self.cipher:
            # MAC is the last 32 bits, Encrypted Data is everything else 
            encrypted_data = msg[:-32]
            mac = msg[-32:]
            if self.verify_hmac(encrypted_data, mac):
                data = self.cipher.decrypt(encrypted_data)
            else:
                # print("Invalid HMAC, message might've been tampered with")
                data = bytes("Invalid HMAC, message might've been tampered with", "ascii")
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = msg

        return data

    # Confirms message wasn't tampered with by checking against HMAC
    def verify_hmac(self, encrypted_data, mac):
        return self.mac(encrypted_data) == mac

    # Updates hmac with new data and digests
    def mac(self, encrypted_data):
        self.hmac.update(encrypted_data)
        return self.hmac.digest()
    
    def close(self):
        self.conn.close()