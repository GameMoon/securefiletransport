from messages.auth_message import AuthMessage

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from struct import unpack


class ResponseMessage(AuthMessage):
    status_code = 0

    def __init__(self, initiator,  status_code, raw_data=b''):
        super().__init__(b'RES', initiator)
        self.status_code = status_code
        self.signature = b''
        self.sym_key = b''
        self.recv_pub_key = b''
        self.raw_data = b''

        if len(raw_data) > 0:
            self.raw_data = raw_data

    def parse(self, sender_pub_key, recv_priv_key = b''):
        self.signature = self.raw_data[-256:]
        if not self.check_signature(sender_pub_key): raise("Signature check fail")

        if self.status_code == 200:
            cipher_rsa = PKCS1_OAEP.new(recv_priv_key)
            self.sym_key = cipher_rsa.decrypt(self.raw_data[:256])

    def get_status_code(self):
        return self.status_code

    def get_data(self):
        if self.status_code != 200 : return b''

        if len(self.raw_data) > 0: 
            return self.raw_data[:256]
        if len(self.data) > 0: return self.data

        cipher_rsa = PKCS1_OAEP.new(self.recv_pub_key)
        self.data = cipher_rsa.encrypt(self.sym_key)
        return self.data


    
