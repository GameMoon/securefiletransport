import os.path
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import json

class FileController:
    key_path = "./keys/"
    sym_key_path = 'file_sym.pem'
    private_key_path = 'file_priv.pem'

    def __init__(self,initiator, password):
        self.initiator = initiator
        self.set_key_location(password)
        self.sym_key = b''
        
        if os.path.isfile(self.sym_key_path) and os.path.isfile(self.private_key_path):
            self.load_private_key(password)
            self.load_sym_key(self.private_key)
        else:
            print("Missing decoding key file. Would you like to generate new one? (Y/n)")
            if str(input()) == "n": sys.exit()

            print("Generating file encrypting keys")
            if os.path.isfile(self.private_key_path):
                self.load_private_key(password)
                self.generate_sym_key(self.private_key)
            else:
                self.generate_private_key(password)
                self.generate_sym_key(self.private_key)

    def decrypt_file(self, file_name, json_input):
        b64 = json.loads(json_input)
        json_k = ['nonce', 'header', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}
        cipher = AES.new(self.sym_key, AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plain_text = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

        with open(file_name, "wb") as f:
            f.write(plain_text)
            f.close()

    def encrypt_file(self,file_name):
        with open(file_name, "rb") as f:
            header = self.initiator.encode()
            cipher = AES.new(self.sym_key, AES.MODE_GCM)
            cipher.update(header)
            ciphertext, tag = cipher.encrypt_and_digest(f.read())
            f.close()
            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            json_v = [b64encode(x).decode('utf-8')
                    for x in (cipher.nonce, header, ciphertext, tag)]
            return json.dumps(dict(zip(json_k, json_v))).encode()
            

    def set_key_location(self,password):
        # Generate unique symmetric keys for every password
        password_hash = SHA256.new(password.encode()) 
        prefix = str(password_hash.hexdigest())[:64]+"_"

        if not os.path.isdir(self.key_path): os.mkdir(self.key_path)

        self.sym_key_path = self.key_path+prefix + self.sym_key_path
        self.private_key_path = self.key_path + self.private_key_path

    def load_private_key(self,password):
        with open(self.private_key_path,"rb") as f:
            self.private_key = RSA.import_key(f.read(),password)
            f.close()

    def load_sym_key(self,private_key):
        with open(self.sym_key_path, "rb") as f:
            cipher_rsa = PKCS1_OAEP.new(private_key)
            self.sym_key = cipher_rsa.decrypt(f.read())
            f.close()

    def generate_private_key(self,password):
        self.private_key = RSA.generate(2048)
        with open(self.private_key_path, "wb") as f:
            f.write(self.private_key.export_key(format='PEM', pkcs=8, passphrase=password))
            f.close()

    def generate_sym_key(self, private_key):
        with open(self.sym_key_path, "wb") as f:
            key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            f.write(cipher_rsa.encrypt(key))
            f.close()


