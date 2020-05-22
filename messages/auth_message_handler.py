from struct import unpack

from messages.auth_message import AuthMessage, Message
from messages.login_message import LoginMessage
from messages.response_message import ResponseMessage

class AuthMessageHandler:

    @staticmethod
    def parse(header,raw_data):
        auth_header = raw_data[:AuthMessage.header_size]
        # status_code = unpack("4s", auth_header)
        status_code = int.from_bytes(auth_header, "big")

        if header['msg_type'] == b'LOG':
            return LoginMessage(header['initiator'], raw_data[AuthMessage.header_size:])
        elif header['msg_type'] == b'RES':
            return ResponseMessage(header['initiator'],status_code,raw_data[AuthMessage.header_size:])
        else:
            raise Exception("invalid_message_type")

    @staticmethod
    def create_login_msg(server_pub_key,client_pub_key,username,password):
        login_message = LoginMessage(username)
        login_message.server_pub_key = server_pub_key
        login_message.password = password.encode()
        login_message.client_pub_key = client_pub_key
        return login_message.get_bytes()
    
    @staticmethod
    def get_login_params(loginMessage, server_private_key):
        loginMessage.parse(server_private_key)
        return (loginMessage.initiator, loginMessage.client_pub_key, loginMessage.password)

    @staticmethod
    def create_resp_msg(username, status_code, server_private_key, sym_key=b'', client_pub_key=b''):
        response_msg = ResponseMessage(username,status_code)
        response_msg.sign_priv_key = server_private_key
        if status_code == 200:
            response_msg.sym_key = sym_key
            response_msg.recv_pub_key = client_pub_key
        return response_msg.get_bytes()
