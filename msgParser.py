import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class MsgParser():
    def __init__(self):
        self.bs = AES.block_size
        self.messageType = {
        'TEXT': 'text',
        'ACK': 'ack',
        'FILE': 'file'
        }

        return

    def encrypt(self, raw, key):
        key = hashlib.sha256(key.encode()).digest()

        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc, key):
        key = hashlib.sha256(key.encode()).digest()

        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def parse_message(self, clientName, msgBody, messageType='TEXT'):
        msgParsed  = f"{self.messageType[messageType]}%%{clientName}%%{msgBody}"

        return msgParsed

    def deparse_message(self, msg:str):
        messageType, clientName, body = msg.split('%%')
        return messageType, clientName, body

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]