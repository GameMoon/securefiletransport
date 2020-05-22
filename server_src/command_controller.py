from messages.cmd_message import CmdMessage
from server_src.db_controller import DBController 
from server_src.client import Client

import re

class CommandController:

    def __init__(self,db_controller):
        self.db = db_controller
        self.incoming_file = ""

    def execute(self,cmd_message,client):
        cmd = cmd_message.command.decode()
        print("Command:",cmd)
        try: 
            CmdMessage.check_command(cmd)
            cmd_args = cmd.split()
            func = getattr(self,cmd_args[0])
            return func(cmd_args,client)
        except:
            return "invalid command"
    
    def mkdir(self, args, client):
        p = re.compile('^(\w+\.?)*\w+$')
        if not p.match(args[1]): raise Exception("Invalid folder name")
        
        exists = False
        try:
            exists = self.db.get_folder(client.addr, client.current_dir, args[1])
        except:
            pass
        if exists: raise Exception("Already exists")

        self.db.create_folder(client.addr, client.current_dir,args[1])
        return ("ok", b'TXT')

    def rmdir(self, args, client):
        tmpdir = client.current_dir
        self.cd(args, client)

        folders = self.db.get_folders(client.addr, client.current_dir, formatted = False)
        i = 0
        while i < len(folders):
            folders = folders + self.db.get_folders(client.addr, folders[i][1], formatted = False)
            self.db.remove_folder(client.addr, folders[i][1])
            i += 1

        self.db.remove_folder(client.addr, client.current_dir)
        client.current_dir = tmpdir
        return ("ok", b'TXT')

    def rm(self, args, client):
        if(args[1] == "-r"):
            self.rmdir(args[:1]+args[2:],client)
        else:
            self.db.remove_file(client.addr,args[1],client.current_dir)
        return ("ok", b'TXT')

    def cd(self, args, client):
        if args[1] == "..":
            parent_dir = self.db.get_parent_folder(client.addr, client.current_dir)
            if parent_dir == 0:
                return ("ok", b'TXT')
            client.current_dir = parent_dir
        else:
            dirs = args[1].split("/")
            if len(dirs) == 1 and not dirs[0]: dir = client.base_dir
            elif not dirs[0]:
                dir = client.base_dir
                dirs = dirs[1:]
            else: dir = client.current_dir

            for cdir in dirs:
               if not cdir: break
               dir = self.db.get_folder(client.addr, dir , cdir)
            client.current_dir = dir
        return ("ok", b'TXT')

    def ls(self, args, client):
        folders = self.db.get_folders(client.addr, client.current_dir)
        files = self.db.get_files(client.addr, client.current_dir)

        return (" ".join(folders)+" "+" ".join(files), b'TXT')
    
    def pwd(self, args, client,c_dir = -1):
        if c_dir == -1:
            c_dir = client.current_dir
        foldername = self.db.get_folder_name(client.addr, c_dir)

        if foldername != "/":
            parent_id = self.db.get_parent_folder( client.addr, c_dir)
            new_foldername, msg_type = self.pwd(args, client, parent_id)
            foldername = new_foldername +"/"+foldername
        if foldername[:2] == "//": foldername = foldername[1:]

        return (foldername, b'TXT')
    
    def upload(self,args, client):
        if len(args) == 3:
            self.incoming_file = args[2]
        else: self.incoming_file = args[1]
        return ("ok",b'INC')
    
    def disconnect(self, args, client):
        return ("disconnect", b'TXT')

    def download(self, args, client):
        tmpdir = client.current_dir
        dir = args[1].split("/")
        if len(dir) == 1:
            file_name = args[1]
        else: file_name = dir[-1]

        args[1] = "/".join(dir[:-1])
        if args[1]:  self.cd(args, client)

        data = self.db.download_file(client.addr,client.current_dir,file_name)
        client.current_dir = tmpdir
        return (data, b'BIN')

    def upload_file(self,client,data):
        tmpdir = client.current_dir
        dir = self.incoming_file.split("/")
        if len(dir) == 1:
            file_name = self.incoming_file
        else: file_name = dir[-1]

        path = "/".join(dir[:-1])
        if path: self.cd([0,path], client)

        self.db.upload_file(client.addr,client.current_dir,file_name, data)
        client.current_dir = tmpdir
        self.incoming_file = ""
        return "ok"

  
