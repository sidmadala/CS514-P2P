from msgParser import MsgParser

import random
import socket
import threading
import hashlib

PRIVATE_KEY = 131
PUBLIC_BASE = 13
PUBLIC_MOD = 97

class Blaster(threading.Thread, MsgParser):
    def __init__(self, address='127.0.0.1', port=8080, name='Anon'):
        threading.Thread.__init__(self)
        MsgParser.__init__(self)

        self.address = address
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientName = name
        self.privateKey = random.randint(1001, 9999)

    def _get_shared_key(self):
        print('computing diffie-hellman ...')
        clientPublicKey = (PUBLIC_BASE**self.privateKey)%PUBLIC_MOD
        self.socket.send(str(clientPublicKey).encode())
        serverPublicKey = int(self.socket.recv(4096).decode())
        sharedKey = str((serverPublicKey**self.privateKey)%PUBLIC_MOD)
        print('diffie-hellman shared key computed, ready to chat')

        return sharedKey
        
    def run(self):
        self.socket.connect((self.address, self.port))
        
        sharedKey = self._get_shared_key()
        print('the shared secret key is:', sharedKey)

        while True:
            msgOut = input('Me: ')
            msgOut = self.parse_message(self.clientName, msgOut)
            msgOutEncrypted = self.encrypt(msgOut, sharedKey)
            self.socket.send(msgOutEncrypted)

            msgAckEncrypted = self.socket.recv(4096).decode()
            msgAck = self.decrypt(msgAckEncrypted, sharedKey)
            messageType, receiverName, msgAckBody = self.deparse_message(msgAck)
            computedHash = hashlib.sha256(str.encode(msgOut)).hexdigest()

            if(messageType != self.messageType.get('ACK')):
                print('invalid acknowledgement format')
            elif(computedHash != msgAckBody):
                print('invalid acknowledgement hash')
            else:
                print(f"[ACK received from {receiverName}]")

if __name__ == '__main__':
    nameInput = input("What is your name? ")

    address = input("enter target peer address:")

    blaster = Blaster(address=address, port=8080, name=nameInput)
    blaster.start()
    