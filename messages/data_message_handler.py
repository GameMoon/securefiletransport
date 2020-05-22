from struct import unpack

from messages.data_message import DataMessage,Message
from messages.cmd_message import CmdMessage
from messages.bin_message import BinMessage

class DataMessageHandler:

    @staticmethod
    def parse(header, raw_data):
        data_header = raw_data[Message.base_header_size:Message.base_header_size+DataMessage.header_size]
        (time_stamp, ) = unpack("10s", data_header)
        time_stamp = int.from_bytes(time_stamp,"big")
        delta = DataMessage.get_timestamp() - time_stamp
        if delta > 10: raise Exception("invalid_timestamp")

        if header['msg_type'] == b'TXT':
            return CmdMessage(header['initiator'], raw_data)
        elif header['msg_type'] == b'BIN':
            return BinMessage(header['initiator'], raw_data)
        else:
            raise Exception("invalid_message_type")
