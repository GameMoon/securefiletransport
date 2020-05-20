from struct import unpack

from messages.data_message import DataMessage,Message
from messages.cmd_message import CmdMessage

class DataMessageHandler:

    @staticmethod
    def parse(header, raw_data):
        data_header = raw_data[Message.base_header_size:Message.base_header_size+DataMessage.header_size]
        time_stamp = unpack("10s", data_header)

        if header['msg_type'] == b'TXT':
            return CmdMessage(header['initiator'], raw_data)
        elif header['msg_type'] == b'BIN':
            pass
        else:
            raise Exception("invalid_message_type")
