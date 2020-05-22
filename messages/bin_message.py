from messages.data_message import DataMessage, Message
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import json


class BinMessage(DataMessage):
    data = b''
    content = b''
    sym_key = b''
    sign_pub_key = b''

    def __init__(self, initiator, raw_data=b''):
        super().__init__(b'BIN', initiator)
        if len(raw_data) > 0:
            self.raw_data = raw_data

    def parse(self, sym_key, sign_pub_key):
        self.sym_key = sym_key
        self.sign_pub_key = sign_pub_key
        self.data = self.raw_data[DataMessage.header_size +
                                  Message.base_header_size:-256]

        # Signature check
        self.signature = self.raw_data[-256:]
        if not self.check_signature(self.sign_pub_key, self.raw_data[:-256]):
            raise("Signature check fail")

        # Decode data
        json_input = self.data.decode()
        b64 = json.loads(json_input)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(self.sym_key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])

        self.content = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

    def get_data(self):
        if len(self.data) > 0:
            return self.data

        header = self.initiator.encode()
        cipher = AES.new(self.sym_key, AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(self.content)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        json_v = [b64encode(x).decode('utf-8')
                  for x in (cipher.nonce, header, ciphertext, tag)]
        self.data = json.dumps(dict(zip(json_k, json_v))).encode()
        return self.data

    @staticmethod
    def create(initiator, sym_key, sign_priv_key, data):
        cmd_message = BinMessage(initiator)
        cmd_message.sym_key = sym_key
        cmd_message.sign_priv_key = sign_priv_key
        cmd_message.content = data
        return cmd_message.get_bytes()


