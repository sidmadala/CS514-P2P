"""
Created by Xianghui on 2021/11/16.
"""

from enum import Enum, unique

CRLF = "\r\n"
SERVER_IP = "localhost"
SERVER_PORT = 9995
SERVER_UDP_PORT = 9996
PUBLIC_BASE = 13
PUBLIC_MOD = 97

@unique
class MsgType(str, Enum):
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    GET_ACTIVE_USER = "GET_ACTIVE_USER"
    REQUEST_CONNECT = "REQUEST_CONNECT"
    AGREE_P2P = "AGREE_P2P"
    PING = "PING"
    EXCHANGE = "EXCHANGE"


@unique
class ServerResponse(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    USER_LIST = "USER_LIST"
    REQUEST = "REQUEST"
    UDP_PING = "UDP_PING"
    PUNCH = "PUNCH"
    EXCHANGE = "EXCHANGE"


@unique
class ClientChildCmd(str, Enum):
    PUNCH = "PUNCH"
    SEND = "SEND"
    CLOSE = "CLOSE"


@unique
class ChatType(str, Enum):
    MESSAGE = "MESSAGE"
    HEARTBEAT = "HEARTBEAT"
    SEND = "SEND"
    PUNCH = "PUNCH"
