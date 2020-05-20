from abc import ABCMeta, abstractmethod
from messages.message import Message
from struct import pack
import time


class DataMessage(Message):
    protocol = 2
    header_size = 10 # 10 byte timestamp

    def __init__(self, message_type, initiator):
        super().__init__(self.protocol, message_type, initiator)

    @abstractmethod
    def get_data(self):
        pass

    def get_timestamp(self):
        return int(time.time()*1000)
    
    def get_header(self):
        data = self.get_data()
        sign_len = 256
            
        result = b''
        result = result + pack("s", bytes([self.protocol])) # 1 byte protocol version
        result = result + pack("3s", self.message_type) # 3 bytes message type
        result = result + pack("12s", (32+len(data)+sign_len).to_bytes(12,'big')) # 12 bytes message length
        result = result + pack("6s", self.initiator.encode()) # 6 bytes initator
        result = result + pack("10s", self.get_timestamp().to_bytes(10,'big')) # 10 bytes timestamp
        return result