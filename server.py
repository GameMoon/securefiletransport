
from Crypto.PublicKey import RSA
from messages.message_handler import MessageHandler
from messages.auth_message_handler import AuthMessageHandler
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

from messages.cmd_message import CmdMessage

from netsim.netinterface import network_interface
import sqlite3

class Server:
    path = "./network/"
    serverid = "server"
    password = "9uKAEfMkbWrc9Psy"
    

    def __init__(self,addr):
        #self.generate_server_keys()
        self.conn = sqlite3.connect('server.db')
        # self.init_db()

        self.private_key = self.load_private_key(self.password) # Long term private key
        self.client_public_key = b'' # Short term client public key
        self.sym_key = b'' # Short term symmetric key
        self.connection_state = 0
        

        self.addr = addr
        self.network_interface = network_interface(self.path, self.addr)
        self.listening_clients()

    def listening_clients(self):
        print("Server listening [Address: "+str(self.addr+"]"))
        
        while True:
            self.handle_client()

        self.client_public_key = b''
        self.connection_state = 0

    def handle_client(self):
        status, data = self.network_interface.receive_msg()
        if status:
            message = MessageHandler.parse(data)

            if self.connection_state == 0:
                client_address, client_public_key, password = AuthMessageHandler.get_login_params(message,self.private_key)
                #TODO password check
                # Store short term client keys
                self.client_address = client_address
                self.client_public_key = RSA.import_key(client_public_key)
                # Generate symmetric key
                self.sym_key = self.generate_sym_key()
                # Send symmetric key back

                status_code = 403
                if self.check_password(self.client_address,password):
                    print("[",self.client_address,"] client authenticated")
                    status_code = 200
                self.network_interface.send_msg(self.client_address,
                                                AuthMessageHandler.create_resp_msg(
                                                    self.serverid,
                                                    status_code,
                                                    self.private_key,
                                                    self.sym_key,
                                                    self.client_public_key))
                self.connection_state = 1

            elif self.connection_state == 1:
                message.parse(self.sym_key,self.client_public_key)
                print(message.command)
                

    def load_private_key(self,password):
        with open("server_priv.pem", "rb") as f:
            return RSA.import_key(f.read(), password)

    def generate_sym_key(self):
        return get_random_bytes(16)

    def check_password(self,userid,password):
        c = self.conn.cursor()
        c.execute('SELECT password,salt FROM users WHERE userid=?', userid)
        password_hash, salt = c.fetchone()
        new_hash = PBKDF2( pad(password, 32), salt, 24, count=100000, hmac_hash_module=SHA512)

        if password_hash == new_hash: return True
        else: return False


    # These functions for init
    def generate_server_keys(self): # Long term keys which shared with the clients out of band
        private_key = RSA.generate(2048)
        with open("server_priv.pem", "wb") as f:
            f.write(private_key.export_key(format='PEM', pkcs=8, passphrase=self.password))
            f.close()

        with open("server_pub.pem", "wb") as f:
            f.write(private_key.publickey().export_key())
            f.close()

    def init_db(self):
        c = self.conn.cursor()
        password = "test".encode()
        salt = get_random_bytes(16)
        key = PBKDF2( pad(password, 32), salt, 24, count=100000, hmac_hash_module=SHA512)
       
        c.execute('''CREATE TABLE users (userid, password, salt)''')
        c.execute("INSERT INTO users VALUES (?,?,?)", ('B', key, salt))
        c.execute('''CREATE TABLE folders (id, userid, name)''')
        c.execute('''CREATE TABLE files (id, folderid, content)''')
        self.conn.commit()
       
if __name__ == "__main__":
    server = Server("A")

