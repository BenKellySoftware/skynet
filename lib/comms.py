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

        # This can be broken into code run just on the server or just on the client
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
        # Uses first 4 bytes of shared hash (the only common number both ends have I could think of)
        self.ctr = Counter.new(128, initial_value=int.from_bytes(shared_hash[:4], byteorder='big'))
        # Using CTR AES to encrypt with incrimenting IV thats the same on both ends
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
                data = "Invalid HMAC, message might've been tampered with"
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = msg

        return data

    def verify_hmac(self, encrypted_data, mac):
        return self.mac(encrypted_data) == mac

    def mac(self, encrypted_data):
        self.hmac.update(encrypted_data)
        return self.hmac.digest()
    # def pad(self, m, pad_length=16):
    #     # Work out how many bytes need to be added
    #     required_padding = pad_length - (len(m) % pad_length)
    #     # Use a bytearray so we can add to the end of m
    #     b = bytearray(m)
    #     # Then k-1 zero bytes, where k is the required padding
    #     b.extend(bytes("\x00" * (required_padding-1), "ascii"))
    #     # And finally adding the number of padding bytes added
    #     b.append(required_padding)
    #     return bytes(b)

    # def unpad(self, m, pad_length=16):
    #     # The last byte should represent the number of padding bytes added
    #     required_padding = m[-1]
    #     # Ensure that there are required_padding - 1 zero bytes
    #     if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
    #         return m[:-required_padding]
    #     else:
    #         # Raise an exception in the case of an invalid padding
    #         raise AssertionError("Padding was invalid")

    def close(self):
        self.conn.close()