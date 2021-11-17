"""
Created by Xianghui on 2021/11/16.
"""

import json
import threading
from datetime import datetime
from json import JSONDecodeError
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket
import redis
from pymongo import MongoClient
from loguru import logger
import jwt

from common import CRLF, ServerResponse, MsgType, ClientChildCmd
from ServerUDP import run_server_udp

mongo = MongoClient("mongodb+srv://xianghui:hdrw9jytsQRTjbV@cluster0.gvzcr.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = mongo['myFirstDatabase']
client_addr = {}
client_name = {}
redis_0 = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
redis_1 = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
SERVER_SECRET = "hdrw9jytsQRTjbV"


class ServerHandler(WebSocket):

    def reply_error(self, msg):
        reply = {'result': ServerResponse.FAIL, 'content': msg}
        reply_str = json.dumps(reply).encode()
        self.sendMessage(reply_str)

    def reply_success(self, msg):
        reply = {'result': ServerResponse.SUCCESS, 'content': msg}
        reply_str = json.dumps(reply).encode()
        self.sendMessage(reply_str)

    def login_handler(self, data):
        if 'username' not in data.keys() or 'password' not in data.keys():
            self.reply_error('Invalid message.')
        users = db.users
        user = users.find_one({'username': data['username']})
        if user is None:
            self.reply_error('User not exists.')
            return
        if user['password'] != data['password']:
            self.reply_error('Incorrect password.')
            return

        encoded_jwt = jwt.encode({"username": data['username'], 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
                                 SERVER_SECRET, algorithm="HS256")
        redis_0.setex(data['username'], 3600, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        reply = {'result': ServerResponse.LOGIN_SUCCESS, 'token': encoded_jwt.decode(), 'username': data['username']}
        reply_str = json.dumps(reply).encode()
        client_addr[data['username']] = self
        client_name[self.address] = data['username']
        self.sendMessage(reply_str)

    def register_handler(self, data):
        if 'username' not in data.keys() or 'password' not in data.keys():
            self.reply_error('Invalid message.')
        users = db.users
        if users.find({'username': data['username']}).count() > 0:
            self.reply_error('User already exists.')
            return
        users.insert_one({'username': data['username'], 'password': data['password']})

        encoded_jwt = jwt.encode({"username": data['username'], 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, SERVER_SECRET, algorithm="HS256")
        redis_0.setex(data['username'], 3600, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        reply = {'result': ServerResponse.LOGIN_SUCCESS, 'token': encoded_jwt.decode(), 'username': data['username']}
        reply_str = json.dumps(reply).encode()
        client_addr[data['username']] = self
        client_name[self.address] = data['username']
        self.sendMessage(reply_str)

    def get_user_handler(self, data):
        if 'token' not in data.keys():
            self.reply_error('Please log in first')
        content = jwt.decode(data['token'], SERVER_SECRET, algorithms="HS256")
        username = content['username']
        all_users = list(client_addr.keys())
        other_user = list(filter(lambda u: u != username, all_users))
        reply = {'result': ServerResponse.USER_LIST, 'content': other_user}
        reply_str = json.dumps(reply).encode()
        self.sendMessage(reply_str)

    def request_connection_handler(self, data):
        if 'token' not in data.keys():
            self.reply_error('Please log in first')
        content = jwt.decode(data['token'], SERVER_SECRET, algorithms="HS256")
        username = data['target']
        request_from = content['username']
        if 'target' not in data.keys():
            self.reply_error('No target user specified.')
        if username in client_addr.keys():
            self.reply_success('Send starting chat request to {}. If he/she agrees, UDP punching will start.'.format(username))
            notify = {'result': ServerResponse.REQUEST, 'content': {'username': request_from}}
            client_addr[username].sendMessage(json.dumps(notify).encode())
        else:
            self.reply_error('{} seems offline, try later.'.format(username))

    def p2p_agree_handler(self, data):
        if 'token' not in data.keys():
            self.reply_error('Please log in first')
        content = jwt.decode(data['token'], SERVER_SECRET, algorithms="HS256")
        peer1 = content['username']
        peer2 = data['peer']
        peer1_addr = redis_1.hgetall(peer1)
        peer2_addr = redis_1.hgetall(peer2)
        if peer1 in client_addr.keys() and peer2 in client_addr.keys() and peer1_addr is not None and peer2_addr is not None:
            reply1 = json.dumps({'result': ServerResponse.PUNCH,
                                 'content': {'target': peer2, 'me': peer1, 'ip': peer2_addr['ip'],
                                             'port': peer2_addr['port'], 'cmd': ClientChildCmd.PUNCH}})
            reply2 = json.dumps({'result': ServerResponse.PUNCH,
                                 'content': {'target': peer1, 'me': peer2, 'ip': peer1_addr['ip'],
                                             'port': peer1_addr['port'], 'cmd': ClientChildCmd.PUNCH}})
            client_addr[peer1].sendMessage(reply1.encode())
            client_addr[peer2].sendMessage(reply2.encode())
        else:
            reply = json.dumps({'result': ServerResponse.FAIL,
                                'content': 'Fail to init p2p client between {} and {}'.format(peer1, peer2)})
            client_addr[peer1].sendMessage(reply.encode())
            client_addr[peer2].sendMessage(reply.encode())

    @logger.catch
    def handleMessage(self):
        msg_lst = self.data.split(CRLF)
        msg_lst = list(filter(lambda s: s != "", msg_lst))
        for msg_text in msg_lst:
            try:
                logger.info('[{}] Client message is: {}'.format(self.address, msg_text))
                msg = json.loads(msg_text.strip(CRLF))
                if ('type' not in msg.keys()) or ('data' not in msg.keys()):
                    self.reply_error('Invalid message.')
                    continue
                if msg['type'] == MsgType.LOGIN:
                    self.login_handler(msg['data'])
                elif msg['type'] == MsgType.REGISTER:
                    self.register_handler(msg['data'])
                elif msg['type'] == MsgType.GET_ACTIVE_USER:
                    self.get_user_handler(msg['data'])
                elif msg['type'] == MsgType.REQUEST_CONNECT:
                    self.request_connection_handler(msg['data'])
                elif msg['type'] == MsgType.AGREE_P2P:
                    self.p2p_agree_handler(msg['data'])

            except JSONDecodeError as e:
                self.reply_error('Invalid message.')

    def handleConnected(self):
        logger.info('[{}] connected to the server.'.format(self.address))

    @logger.catch
    def handleClose(self):
        if self.address in client_name.keys():
            username = client_name[self.address]
            redis_0.delete(username)
            redis_1.delete(username)
            del client_name[self.address]
            if username in client_addr.keys():
                del client_addr[username]
        logger.info('[{}] disconnected.'.format(self.address))


if __name__ == '__main__':
    logger.add('server.log')
    server = SimpleWebSocketServer('', 9995, ServerHandler)
    udp_thread = threading.Thread(target=run_server_udp, args=())
    udp_thread.start()
    server.serveforever()

    # never reach here
    udp_thread.join()