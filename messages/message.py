from abc import ABCMeta, abstractmethod
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class Message:
    data = b''
    base_header_size = 22

    def __init__(self, protocol, msg_type, initiator):
        self.protocol = protocol
        self.message_type = msg_type
        self.initiator = initiator
        self.signature = b''
        self.sign_priv_key = None

    @abstractmethod
    def get_header(self):
        pass

    @abstractmethod
    def get_data(self):
        pass

    def get_bytes(self):
        result = self.get_header()
        result = result + self.get_data()
        result = result + self.get_signature()
        return result

    def get_message_hash(self, raw_data = b''):
        if len(raw_data) > 0: return SHA256.new(raw_data) 
        return SHA256.new(self.get_header()+self.get_data())

    def check_signature(self, key, raw_data=b''):
        try:
            pkcs1_15.new(key).verify(
                self.get_message_hash(raw_data), self.get_signature())
            return True
        except:
            return False

    def get_signature(self, raw_data=b''):
        if self.signature == b'':
            if not self.sign_priv_key:
                raise("Missing sign key")

            self.signature = pkcs1_15.new(self.sign_priv_key).sign(
                self.get_message_hash(raw_data))
        return self.signature
