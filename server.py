from server_src.command_controller import CommandController
from server_src.db_controller import DBController
from server_src.key_controller import KeyController
from server_src.client_controller import ClientController

import sys

class Server:
    path = "./network/"
    password = "9uKAEfMkbWrc9Psy"
    

    def __init__(self,addr):
        self.key_controller = KeyController(self.password)
        self.db = DBController(self.key_controller)
        self.client_controller = ClientController(self.path, addr,self.key_controller,self.db)

    def listen(self):
        self.client_controller.listen()
    
     
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(sys.argv[0], "server_addr")
    else:
        server = Server(sys.argv[1])
        server.listen()

