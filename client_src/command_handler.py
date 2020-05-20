from messages.cmd_message import CmdMessage

class CommandHandler:
    def __init__(self,initiator):
        self.all_commands = {"upload": 2, "mkdir": 2, "rm": 2, "cd":2, "ls":1, "pwd": 1}
        self.initiator = initiator

    def create_message(self, command, sym_key, sign_priv_key):
        cmd_params = command.split()
        if cmd_params[0] not in self.all_commands.keys():
            raise Exception("Command not found")
        if len(cmd_params) != self.all_commands[cmd_params[0]]:
            raise Exception("Missing args")

        cmd_message = CmdMessage(self.initiator)
        cmd_message.sym_key = sym_key
        cmd_message.sign_priv_key = sign_priv_key
        cmd_message.command = command.encode()

        return cmd_message.get_bytes()

        


