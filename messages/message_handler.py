from messages.auth_message import AuthMessage, Message
from messages.data_message import DataMessage

from messages.auth_message_handler import AuthMessageHandler
from messages.data_message_handler import DataMessageHandler

from struct import unpack

class MessageHandler:

    @staticmethod
    def parse(raw_data):
        raw_header = raw_data[:Message.base_header_size]
        protocol, msg_type, msg_length, initiator = unpack("1s3s12s6s", raw_header)
        data = raw_data[Message.base_header_size:]
        
        protocol = int.from_bytes(protocol, "big")
        msg_length = int.from_bytes(msg_length, "big")
        initiator = initiator.decode().rstrip("\x00")

        header = {"header": protocol, "msg_type": msg_type, "msg_length":msg_length, "initiator":initiator}

        if msg_length != len(raw_data):
            raise Exception("invalid_message_length")

        if protocol == AuthMessage.protocol:
            return AuthMessageHandler.parse(header,data)
        elif protocol == DataMessage.protocol:
            return DataMessageHandler.parse(header, raw_data)
        else: raise Exception("invalid_protocol")
