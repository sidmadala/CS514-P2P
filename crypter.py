import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size

class Crypter():
    @staticmethod
    def encrypt(raw, key):
        def _pad(s):
            return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

        key = hashlib.sha256(key.encode()).digest()

        raw = _pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    @staticmethod
    def decrypt(enc, key):
        def _unpad(s):
            return s[:-ord(s[len(s)-1:])]

        key = hashlib.sha256(key.encode()).digest()

        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return _unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
