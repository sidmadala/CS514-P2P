from msgParser import MsgParser

import os
import random
import socket
import threading
import hashlib
from dotenv import load_dotenv

PRIVATE_KEY = 251
PUBLIC_BASE = 13
PUBLIC_MOD = 97

class Listener(threading.Thread, MsgParser):
    def __init__(self, address='', port=8080, name='Anon'):
        threading.Thread.__init__(self)
        MsgParser.__init__(self)

        self.address = address
        self.port = port
        self.listener = socket.socket()
        self.clientName = name
        self.activeConnections = {}
        self.privateKey = random.randint(1001, 9999)

        self.listener.bind((self.address, self.port))
        self.listener.listen(5)
        return

    def _get_shared_key(self, conn):
        print('computing diffie-hellman ...')

        clientPublicKey = int(conn.recv(2048).decode())
        serverPublicKey = (PUBLIC_BASE**self.privateKey)%PUBLIC_MOD
        conn.send(str(serverPublicKey).encode())
        sharedKey = str((clientPublicKey**self.privateKey)%PUBLIC_MOD)
        self.activeConnections[conn] = sharedKey

        print('diffie-hellman shared key computed, ready to chat')

        return sharedKey

    def client_handler(self, conn:socket.socket):
        while True:
            msgInEncrypted = conn.recv(2048)

            if not msgInEncrypted:
                print('Disconnected')
                break
            else:
                msgInEncrypted = msgInEncrypted.decode('utf-8')
                msgIn = self.decrypt(msgInEncrypted, self.activeConnections.get(conn))
                messageType, senderName, msgBody = self.deparse_message(msgIn)
                
                if messageType == self.messageType.get('TEXT'):
                    print(senderName+': '+msgBody)
                    bodyAck = hashlib.sha256(str.encode(msgIn)).hexdigest()
                    msgAck = self.parse_message(self.clientName, bodyAck, messageType='ACK')
                    msgAckEncrypted = self.encrypt(msgAck, self.activeConnections.get(conn))
                    conn.send(msgAckEncrypted)

        self.activeConnections.pop(conn)
        conn.close()

    def run(self):
        while True:
            conn, addr = self.listener.accept()
            print('got connection from', addr)

            sharedKey = self._get_shared_key(conn)
            print('the shared secret key is:', sharedKey)

            newClient = threading.Thread(target=self.client_handler, args=(conn, ))
            newClient.start()

if __name__ == '__main__':

    load_dotenv()

    address = os.getenv('ADDRESS')
    if address is None:
        errMsg = '''
            no field named \'ADDRESS\' in .env file.
            Create a .env file with ADDRESS as the target peer IP address
        '''
        print(errMsg)
        exit()

    listener = Listener(address=address, port=8080, name='Gunther')
    listener.start()
