
from Crypto.PublicKey import RSA
from getpass import getpass
import socket
import os, sys

from client_src.file_controller import FileController
from messages.message_handler import MessageHandler
from messages.auth_message_handler import AuthMessageHandler
from messages.cmd_message import CmdMessage
from messages.bin_message import BinMessage

from netsim.netinterface import network_interface


class Client:
    path = "./network/"
    password = "testconn2"
    connection_state = 0

    def __init__(self,own_address,server_addr):
        self.server_addr = server_addr
        self.server_pub_key = self.load_server_public_key()
        self.conn_priv_key = self.generate_connection_keys()
        self.sym_key = b''
        self.own_address = own_address
        self.network_interface = network_interface(self.path,own_address)
        
        self.password = getpass("Enter your password:")
        # self.password = "test2"

        self.file_controller = FileController(self.own_address, self.password)
        
        self.inc_file = ""
        self.connect_server(server_addr)

    def load_server_public_key(self):
        with open("server_pub.pem", "rb") as f:
            return RSA.import_key(f.read())

    def generate_connection_keys(self):
        return RSA.generate(2048)

    def connect_server(self,server_addr):
            
        while True:
            self.handle_message()

    def handle_message(self):
        status, data = self.network_interface.receive_msg()
        # TODO timeout
      
        if status:
            message = MessageHandler.parse(data)
        
            if self.connection_state == 1:
                try:
                    message.parse(self.server_pub_key, self.conn_priv_key)
                    if message.status_code == 200:
                        self.sym_key = message.sym_key
                        print("connected to the server")
                        self.connection_state = 2
                    elif message.status_code == 403:
                        print("wrong password")
                        os._exit(1)
                except:
                    print("Message parse error")

            if self.connection_state == 3:
                try:
                    message.parse(self.sym_key,self.server_pub_key)
                    print(message.command.decode())
                    self.connection_state = 2
                except Exception(e):
                    print(str(e))
                    self.connection_state = 0

            if self.connection_state == 4:
                message.parse(self.sym_key, self.server_pub_key)
                print("writing file to ",self.inc_file)
                # TODO
                self.file_controller.decrypt_file(self.inc_file,message.content)
                self.connection_state = 2

        if self.connection_state == 0:
            self.network_interface.send_msg(self.server_addr,
                AuthMessageHandler.create_login_msg(
                    self.server_pub_key,
                    self.conn_priv_key.publickey().export_key(),
                    self.own_address,
                    self.password)
            )
            self.connection_state = 1

        if self.connection_state == 2:
            command = input("> ")
            try:
                msg = CmdMessage.create(
                    self.own_address, self.sym_key, self.conn_priv_key, command)
                self.network_interface.send_msg(self.server_addr,msg)

                cmd_params = command.split(" ")
                if cmd_params[0] == "upload": 
                    data = self.file_controller.encrypt_file(cmd_params[1])
                    msg = BinMessage.create(
                        self.own_address, self.sym_key, self.conn_priv_key, data)
                    self.network_interface.send_msg(self.server_addr, msg)
                   
                elif cmd_params[0] == "download":
                    if len(cmd_params) == 3:
                        self.inc_file = cmd_params[2]
                    else: self.inc_file = cmd_params[1]
                    self.connection_state = 4
                    return


                self.connection_state = 3
            except Exception as e:
                print(str(e))


if __name__ == "__main__":
    client = Client("B","A")
