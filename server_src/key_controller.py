from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA512
import os

class KeyController:
    pub_key_path = "server_pub.pem"
    priv_key_path = "server_priv.pem"
    
    def __init__(self,password):
        self.password = password
        
        self.private_key = self.load_private_key(password) # Long term private key

    # Long term keys which shared with the clients out of band
    def generate_server_keys(self):
        private_key = RSA.generate(2048)
        with open(self.priv_key_path, "wb") as f:
            f.write(private_key.export_key(
                format='PEM', pkcs=8, passphrase=self.password))
            f.close()

        with open(self.pub_key_path, "wb") as f:
            f.write(private_key.publickey().export_key())
            f.close()

    def load_private_key(self, password):
        if not os.path.isfile(self.priv_key_path):
            self.generate_server_keys()

        with open(self.priv_key_path, "rb") as f:
            return RSA.import_key(f.read(), password)

    def generate_sym_key(self):
        return get_random_bytes(16)
    
    def generate_password_hash(self,password,salt):
        return PBKDF2( pad(password, 32), salt, 24, count=100000, hmac_hash_module=SHA512)

    def load_rsa_key(self,key):
        return RSA.import_key(key)
    
    def delete_client_keys(self):
        self.client_public_key = b''
        self.sym_key = b''

