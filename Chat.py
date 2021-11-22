"""
Created by Xianghui on 2021/11/16.
"""

import errno
import json
import select
import socket
import time

from common import SERVER_IP, SERVER_UDP_PORT, ClientChildCmd, ChatType


def event_loop(token, msg_queue, recv_queue, evefd, udp_socket):
    """
    Simple reactor based on epoll. Monitor EPOLLIN event from eventfd and UDP socket
    :param token: user token
    :param msg_queue: for delivering chatting message to main thread GUI
    :param recv_queue: for receiving commands from main thread
    :param evefd: eventfd, to wake up from epoll
    :param udp_socket: for p2p udp chatting
    """
    udp_socket.setblocking(False)
    epoll = select.epoll()
    epoll.register(evefd.fileno(), select.EPOLLIN | select.EPOLLET)
    epoll.register(udp_socket.fileno(), select.EPOLLIN | select.EPOLLET)
    peer_ip = None
    peer_port = None
    while True:
        events = epoll.poll(3)
        for fileno, event in events:
            if fileno == evefd.fileno() and evefd.is_set() and event & select.EPOLLIN:  # from eventfd
                while not recv_queue.empty():  # process all commands from main thread
                    msg = recv_queue.get()
                    print('Child process receive from parent: ', msg)
                    if msg['cmd'] == ClientChildCmd.PUNCH:  # send UDP punching packet
                        udp_socket.sendto(json.dumps({'type': ChatType.PUNCH}).encode(), (msg['ip'], int(msg['port'])))
                        # msg_queue.put(msg)
                        peer_ip = msg["ip"]
                        peer_port = int(msg['port'])
                    elif msg['cmd'] == ClientChildCmd.SEND:  # send chat message
                        udp_socket.sendto(json.dumps({'type': ChatType.MESSAGE, 'content': msg['content']}).encode(), (msg['ip'], msg['port']))
                        msg_queue.put({'type': ChatType.SEND, 'content': msg['content']})
                    else:
                        return
                evefd.clear()
            if fileno == udp_socket.fileno() and event & select.EPOLLIN:
                while True:
                    try:
                        msg, peer_addr = udp_socket.recvfrom(1024)  # receive from another peer
                        print('Child process receive {} from {}'.format(msg, peer_addr))
                        msg_load = json.loads(msg.decode())
                        if msg_load['type'] == ChatType.MESSAGE:
                            # buffer the chat message to msg_queue and main thread will check msg_queue and display
                            msg_queue.put({"type": ChatType.MESSAGE, "ip": peer_addr[0], "port": peer_addr[1], "content": msg_load["content"]})
                        if msg_load['type'] == ChatType.HEARTBEAT:
                            pass
                    except socket.error as e:
                        err = e.args[0]
                        # No new more message
                        if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                            break
        if peer_ip is not None and peer_port is not None:
            # keep heartbeat between peers in case NAT closes connection
            udp_socket.sendto(json.dumps({'type': ChatType.HEARTBEAT}).encode(), (peer_ip, peer_port))
            time.sleep(1)
        # Keep heartbeat with server, in case client NAT address changes. No chatting message will send to server, just heartbeat.
        udp_socket.sendto(json.dumps({'token': token}).encode(), (SERVER_IP, SERVER_UDP_PORT))


def child_process(token, evefd, msg_queue, recv_queue):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    event_loop(token, msg_queue, recv_queue, evefd, udp_sock)
