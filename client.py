
from Crypto.PublicKey import RSA
from getpass import getpass
import socket
import os, sys

from client_src.file_encoder import FileEncoder
from client_src.command_handler import CommandHandler
from messages.message_handler import MessageHandler
from messages.auth_message_handler import AuthMessageHandler
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
        self.command_handler = CommandHandler(own_address)
        self.network_interface = network_interface(self.path,own_address)
        
        # self.password = getpass("Enter your password:")
        self.password = "test"

        #self.file_encoder = FileEncoder(self.password)

        self.connect_server(server_addr)

    def load_server_public_key(self):
        with open("server_pub.pem", "rb") as f:
            return RSA.import_key(f.read())

    def generate_connection_keys(self):
        return RSA.generate(2048)

    def connect_server(self,server_addr):
            
        while True:
            self.handle_message()
            # self.handle_commands()

    def handle_message(self):
        status, data = self.network_interface.receive_msg()
        if status:
            message = MessageHandler.parse(data)
        else: message = b''
        
        # TODO timeout
        if self.connection_state == 0:
                self.network_interface.send_msg(self.server_addr,
                    AuthMessageHandler.create_login_msg(
                        self.server_pub_key,
                        self.conn_priv_key.publickey().export_key(),
                        self.own_address,
                        self.password)
                )
                self.connection_state = 1

        if self.connection_state == 1 and message:
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

        if self.connection_state == 2:
            command = input("> ")
            # try:
            msg = self.command_handler.create_message(command,self.sym_key,self.conn_priv_key)
            self.network_interface.send_msg(self.server_addr,msg)
            self.connection_state = 3
            # except Exception as e:
                # print(str(e))

        if self.connection_state == 3 and message:
            pass

    def handle_commands(self):
        command = input()
        print(command)


if __name__ == "__main__":
    client = Client("B","A")
