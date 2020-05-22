from netsim.netinterface import network_interface

from messages.message_handler import MessageHandler
from messages.cmd_message import CmdMessage
from messages.bin_message import BinMessage

from messages.auth_message_handler import AuthMessageHandler
from server_src.db_controller import DBController
from server_src.key_controller import KeyController
from server_src.command_controller import CommandController
from server_src.client import Client

import time

class ClientController:
    
    def __init__(self,path,addr,key_controller,db_controller):
        self.addr = addr
        self.path = path
        self.key_controller = key_controller
        self.db = db_controller

        self.cmd_controller = CommandController(self.db)
        self.network = network_interface(self.path, self.addr)
        self.connection_state = 0
        self.client = Client()
        self.banned_clients = {}

    def listen(self):
        print("Server listening [Address: "+str(self.addr+"]"))

        while True:
            if self.connection_state > 0 and self.get_timestamp() - self.client.timeout  > 180:
                print("client timeout")
                self.connection_state = 0
                self.client.delete()

            try:
                self.handle_client()
            except KeyboardInterrupt:
                raise
            except:
                print("Message parse error")
                self.connection_state = 0
                self.client.delete()

        self.key_controller.delete_client_keys()
        self.connection_state = 0

    def get_timestamp(self):
        return int(time.time())

    def handle_client(self):
        status, data = self.network.receive_msg()
        # Check for new message
        if not status: return

        message = MessageHandler.parse(data)
        self.client.timeout = self.get_timestamp()

        if self.connection_state == 0:
            client_addr, raw_client_pub_key, password = AuthMessageHandler.get_login_params(message, self.key_controller.private_key)

            # Check if user is banned
            if client_addr in self.banned_clients.keys():
                if self.get_timestamp() - self.banned_clients[client_addr] < 5:
                    return
                else:
                    del self.banned_clients[client_addr]

            self.client.set(
                client_addr,
                self.key_controller.load_rsa_key(raw_client_pub_key),
                self.key_controller.generate_sym_key())

            # Password check
            status_code = 403
            if self.db.check_password(self.client.addr, password):
                print("[",self.client.addr,"] client authenticated")
                status_code = 200
                # set client basedir
                self.client.base_dir = self.db.get_base_folder(self.client.addr)
                self.client.current_dir = self.client.base_dir
                self.connection_state = 1
            else:
                self.banned_clients[self.client.addr] = self.get_timestamp()

            msg = AuthMessageHandler.create_resp_msg(
                self.addr,
                status_code,
                self.key_controller.private_key,
                self.client.sym_key,
                self.client.public_key)

            self.network.send_msg(self.client.addr,msg)
        

        elif self.connection_state == 1:
            # Response message parsing to CmdMessage
            message.parse(self.client.sym_key,self.client.public_key)
            response, response_type = self.cmd_controller.execute(
                message, self.client)

            msg_data = b''
            if response_type == b'TXT':
                msg_data = CmdMessage.create_response(
                    self.addr,
                    self.client.sym_key,
                    self.key_controller.private_key,
                    response)
            elif response_type == b'BIN':
                msg_data = BinMessage.create(
                    self.addr,
                    self.client.sym_key,
                    self.key_controller.private_key,
                    response)
            elif response_type == b'INC':
                self.connection_state = 2
                return
            
            self.network.send_msg(self.client.addr, msg_data)

            if response == "disconnect":
                self.connection_state = 0
                self.client.delete()
                return

        elif self.connection_state == 2:
            # Response message parsing to BinMessage
            message.parse(self.client.sym_key, self.client.public_key)
            response = self.cmd_controller.upload_file(self.client,message.content)
            msg_data = CmdMessage.create_response(
                self.addr,
                self.client.sym_key,
                self.key_controller.private_key,
                response)
            self.network.send_msg(self.client.addr, msg_data)
            self.connection_state = 1

        
            
