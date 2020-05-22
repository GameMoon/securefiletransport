import sqlite3
import os

class DBController:
    file_path = 'server.db'

    def __init__(self, key_controller):
        self.key_controller = key_controller

        exists = os.path.isfile(self.file_path)
        self.conn = sqlite3.connect(self.file_path)
        if not exists: self.create()

    def create(self):
        c = self.conn.cursor()
        password = "test" # test password
        salt = "ZNDkeLayf7YQWJDT" # test salt
        key = self.key_controller.generate_password_hash(password.encode(),salt.encode())
       
        c.execute('''CREATE TABLE users (userid, password, salt)''')
        c.execute("INSERT INTO users VALUES (?,?,?)", ('B', key, salt))

        c.execute(
            '''CREATE TABLE folders (id INTEGER PRIMARY KEY AUTOINCREMENT, userid, name, parentid INTEGER)''')
        c.execute("INSERT INTO folders (userid,name,parentid) VALUES (?,?,?)", ('B', "/","0"))

        c.execute(
            '''CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, folderid INTEGER, name, userid, content)''')
        self.conn.commit()
        print("DB created")

    def check_password(self, userid, password):
        c = self.conn.cursor()
        c.execute('SELECT password,salt FROM users WHERE userid=?', userid)
        password_hash, salt = c.fetchone()
        new_hash = self.key_controller.generate_password_hash(password, salt)

        if password_hash == new_hash:
            return True
        else:
            return False
    
    def get_base_folder(self,userid):
        c = self.conn.cursor()
        c.execute('SELECT id FROM folders WHERE userid=?', userid)
        return c.fetchone()[0]
    
    def get_folder_name(self,userid,folderid):
        c = self.conn.cursor()
        c.execute('SELECT name FROM folders WHERE id=? and userid=?', (folderid,userid))
        return c.fetchone()[0]
    
    def create_folder(self,userid,parentid, name):
        c = self.conn.cursor()
        c.execute("INSERT INTO folders (userid,name,parentid) VALUES (?,?,?)", (userid, name, parentid))
        self.conn.commit()
    
    def get_parent_folder(self,userid,folderid):
        c = self.conn.cursor()
        c.execute('SELECT parentid FROM folders WHERE id=? AND userid=?', (folderid,userid))
        return c.fetchone()[0]

    def get_folder(self,userid, parentid, name):
        c = self.conn.cursor()
        c.execute('SELECT id FROM folders WHERE userid=? AND parentid=? AND name=?', (userid,parentid,name))
        return c.fetchone()[0]
    
    def get_folders(self,userid,folderid,formatted = True):
        c = self.conn.cursor()
        if formatted: c.row_factory = lambda cursor, row: row[0]+"/"
        c.execute('SELECT name,id FROM folders WHERE userid=? AND parentid=?', (userid,folderid))
        return c.fetchall()

    def get_files(self,userid,folderid,formatted = True):
        c = self.conn.cursor()
        if formatted: c.row_factory = lambda cursor, row: row[0]
        c.execute('SELECT name,id FROM files WHERE userid=? AND folderid=?', (userid,folderid))
        return c.fetchall()
    
    def remove_file(self,userid,filename,folderid):
        c = self.conn.cursor()
        c.execute("DELETE FROM files WHERE userid=? AND name=? AND folderid=?", (userid, filename,folderid))
        self.conn.commit()

    def remove_folder(self,userid,folderid):
        c = self.conn.cursor()
        c.execute("DELETE FROM files WHERE userid=? AND folderid=?", (userid, folderid))
        c.execute("DELETE FROM folders WHERE userid=? AND id=?",(userid, folderid))
        self.conn.commit()

    def download_file(self, userid, folderid, file_name):
        print("FolderID: ", folderid," Foldername: ", file_name)
        c = self.conn.cursor()
        c.execute('SELECT content FROM files WHERE userid=? AND folderid=? AND name=?', (userid,folderid,file_name))
        return c.fetchone()[0]

    def upload_file(self, userid, folderid, file_name, data):
        c = self.conn.cursor()
        c.execute("INSERT INTO files (userid,folderid,name,content) VALUES (?,?,?,?)", (userid, folderid, file_name, data))
        self.conn.commit()
