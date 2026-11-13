#python3

import sys, os, threading, socket, getpass
from pathlib import Path
from Crypto.PublicKey import ECC
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftinit import SiFT_INIT, SiFT_INIT_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error

class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        # Resolve all paths relative to this script's directory so the
        # server works regardless of the current working directory
        # (e.g. when launched from a virtual environment or elsewhere).
        self.base_dir = Path(__file__).resolve().parent
        self.server_usersfile = str(self.base_dir / 'users.txt')
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        # Keep a trailing separator so the string concatenation used in
        # siftcmd.py (server_rootdir + user_rootdir + ...) keeps working.
        self.server_rootdir = str(self.base_dir / 'users') + '/'
        # Encrypted (passphrase protected) long-term Ed25519 private key
        self.server_privkeyfile = self.base_dir / 'server_privkey.pem'
        self.server_ip = socket.gethostbyname('localhost')
        # self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_port = 5150
        # -------------------------------------------------------------
        self.server_sigkey = self.load_server_key(self.server_privkeyfile)
        pubkey_der = SiFT_INIT.export_server_pubkey(self.server_sigkey)
        print('Server key fingerprint (SHA-256): ' + SiFT_INIT.fingerprint(pubkey_der))

        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))
        self.accept_connections()


    def load_server_key(self, keyfile):
        try:
            with open(keyfile, 'r') as f:
                key_pem = f.read()
        except OSError:
            print('Cannot read server private key file ' + str(keyfile))
            print('Generate a key pair first with: python3 keygen.py')
            sys.exit(1)
        # the passphrase can be given in the SIFT_KEY_PASSPHRASE environment
        # variable (e.g., for automated tests), otherwise it is asked for
        passphrase = os.environ.get('SIFT_KEY_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass.getpass('Passphrase for server private key: ')
        try:
            key = ECC.import_key(key_pem, passphrase=passphrase)
        except (ValueError, IndexError, TypeError):
            print('Unable to load server private key (wrong passphrase?)')
            sys.exit(1)
        if not key.has_private() or key.curve != 'Ed25519':
            print('Server private key must be an Ed25519 private key')
            sys.exit(1)
        return key


    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            if not r: continue
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr, )).start()


    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        mtp = SiFT_MTP(client_socket)

        initp = SiFT_INIT(mtp)
        initp.set_server_sigkey(self.server_sigkey)
        try:
            initp.handle_init_server()
        except SiFT_INIT_Error as e:
            print('SiFT_INIT_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        loginp = SiFT_LOGIN(mtp)
        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        # make sure the user's root directory exists on the server
        os.makedirs(self.server_rootdir + users[user]['rootdir'], exist_ok=True)

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return


# main
if __name__ == '__main__':
    server = Server()
