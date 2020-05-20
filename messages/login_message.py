from messages.auth_message import AuthMessage

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from struct import unpack

class LoginMessage(AuthMessage):
    public_key = b''
    password = b''
    server_pub_key = b''

    def __init__(self, initiator,  raw_data = b'' ):
        super().__init__(b'LOG', initiator)
        if len(raw_data) > 0:
            self.raw_data = raw_data

    def parse(self,server_priv_key):
        self.client_pub_key = self.raw_data[:450] # rsa public key length in PEM format
        self.password = self.decrypt_data(self.raw_data[450:], server_priv_key)

    def decrypt_data(self, data,private_key):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(data)

    def get_data(self):
        cipher_rsa = PKCS1_OAEP.new(self.server_pub_key)
        return self.client_pub_key+cipher_rsa.encrypt(self.password)

    def get_status_code(self):
        return 0

    def get_signature(self):
        return b''

