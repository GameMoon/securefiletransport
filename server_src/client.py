

class Client:
    def __init__(self):
        self.addr = b""
        self.public_key = b''  # Short term client public key
        self.sym_key = b''  # Short term symmetric key
        self.current_dir = 0
        self.base_dir = 0

    def set(self,addr, public_key,sym_key):
        self.addr = addr
        self.public_key = public_key
        self.sym_key = sym_key

    def delete_keys(self):
        self.sym_key = b''
        self.public_key = b''