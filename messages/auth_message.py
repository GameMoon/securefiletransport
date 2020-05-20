from abc import ABCMeta, abstractmethod
from messages.message import Message
from struct import pack

from Crypto.Signature import pkcs1_15

class AuthMessage(Message):
    protocol = 1
    header_size = 4  # 4 byte status code

    def __init__(self, message_type, initiator):
        super().__init__(self.protocol, message_type, initiator)  
    
    @abstractmethod
    def get_data(self):
        pass

    @abstractmethod
    def get_status_code(self):
        pass

    def get_header(self):
        data = self.get_data()
        if self.message_type == b'LOG': sign_len = 0
        else: sign_len = 256
        
        result = b''
        result = result + pack("s", bytes([self.protocol])) # 1 byte protocol version
        result = result + pack("3s", self.message_type) # 3 bytes message type
        result = result + pack("12s", (Message.base_header_size+AuthMessage.header_size+len(data)+sign_len).to_bytes(12,'big')) # 12 bytes message length
        result = result + pack("6s", self.initiator.encode()) # 6 bytes initator
        result = result + pack("4s", self.get_status_code().to_bytes(4, 'big') ) # 4 bytes status code
        return result
    

   
    
