"""
Created by Xianghui on 2021/11/16.
"""

from socketserver import UDPServer, BaseRequestHandler
import jwt
import redis
import json
from loguru import logger
from common import CRLF

SERVER_SECRET = "hdrw9jytsQRTjbV"


class UDPRequestHandler(BaseRequestHandler):

    @logger.catch
    def handle(self) -> None:
        try:
            msg, sock = self.request
            msg_lst = msg.decode().split(CRLF)
            for msg_text in msg_lst:
                msg = json.loads(msg_text.strip(CRLF))
                if 'token' in msg.keys():
                    content = jwt.decode(msg['token'], SERVER_SECRET, algorithms="HS256")
                    self.server.redis.hset(content['username'], mapping={'ip': self.client_address[0], 'port': self.client_address[1]})

        except Exception as e:
            print(e)


def run_server_udp():
    logger.add('server_udp.log')
    UDPServer.allow_reuse_address = True
    server = UDPServer(('0.0.0.0', 9996), UDPRequestHandler)
    server.redis = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    server.serve_forever()


if __name__ == '__main__':
    run_server_udp()
