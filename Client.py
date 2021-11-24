"""
Created by Xianghui on 2021/11/16.
"""

import json, random
import threading
from tkinter import messagebox
from tkinter.messagebox import askyesno
from autobahn.twisted.websocket import WebSocketClientProtocol
from twisted.python import log
from twisted.internet import reactor, tksupport
from autobahn.twisted.websocket import WebSocketClientFactory
from tkinter import *
from eventfd import EventFD
import queue

from common import CRLF, MsgType, ServerResponse, ClientChildCmd, ChatType, SERVER_IP, SERVER_PORT
from common import PUBLIC_MOD, PUBLIC_BASE
from Chat import child_process
from crypter import Crypter

token = None  # user's token
child = None  # child thread to run UDP socket
peer_ip = None  # set when receive ServerResponse.PUNCH, peer's IP
peer_port = None  # set when receive ServerResponse.PUNCH, peer's port
evefd = EventFD()  # fd used to wake child thread when new commands inserted to recv_queue
msg_queue = queue.Queue()  # thread safe queue, containing message from child thread to main thread
recv_queue = queue.Queue()  # thread safe queue, containing message from client's main thread (run WS and GUI) to
                            # child thread (run UDP socket)


class MyClientProtocol(WebSocketClientProtocol):

    def onConnect(self, response):
        self.factory.connected = self  # needs send message later

        self.privateKey = random.randint(1001, 9999)
        clientPublicKey = (PUBLIC_BASE**self.privateKey)%PUBLIC_MOD

        reply = {
            'type': MsgType.EXCHANGE, 
            'data': {
                'clientPublicKey': clientPublicKey
            }
        }
        self.sendMessage(json.dumps(reply).encode())

    # def onClose(self, wasClean, code, reason):
    #     global app
    #     print(code)
    #     print(reason)
    #     app.master.stop()

    def onMessage(self, payload, isBinary):
        global root
        if isBinary:
            #msg = json.loads(payload.decode())

            # attempt to decrypt the message
            try:
                msg = Crypter.decrypt(payload, self.sharedKey)
                msg = json.loads(msg)
            except:
                msg = json.loads(payload.decode())

            if msg['result'] == ServerResponse.SUCCESS:
                messagebox.showinfo(title='success', message=msg['content'])
            elif msg['result'] == ServerResponse.FAIL:
                messagebox.showerror(title='fail', message=msg['content'])
            elif msg['result'] == ServerResponse.LOGIN_SUCCESS:
                messagebox.showinfo(title='info', message='Login in success')
                global token
                token = msg['token']

                # display login message
                app.text.configure(state='normal')
                app.text.insert(END, "[INFO] successfully login as {}\n".format(msg['username']))
                app.text.configure(state='disabled')

                # launch child thread
                global child
                child = threading.Thread(target=child_process, args=(token, evefd, msg_queue, recv_queue))
                child.start()
            elif msg['result'] == ServerResponse.USER_LIST:

                if len(msg['content']) == 0:
                    messagebox.showinfo(title='success', message='Sorry, no other users online now.')
                else:
                    # display all online users except the current user
                    app.text.configure(state='normal')
                    app.text.insert(END, '[INFO] current online user:\n')
                    # app.text.delete(1.0, "end")
                    for u in msg['content']:
                        app.text.insert(END, u + '\n')
                    app.text.configure(state='disabled')
            elif msg['result'] == ServerResponse.REQUEST:
                # another peer wants to establish connection with the current
                answer = askyesno(title='chat request',
                                  message='{} wants to start chat with you. Do you allow the chat to start?'.format(msg['content']['username']))
                if answer:
                    # if agrees, let server sends peer's IP and port
                    reply = {'type': MsgType.AGREE_P2P, 'data': {'token': token, 'peer': msg['content']['username']}}
                    # self.sendMessage(json.dumps(reply).encode())
                    reply = json.dumps(reply)
                    self.sendMessage(Crypter.encrypt(reply, self.sharedKey))

            elif msg['result'] == ServerResponse.PUNCH:
                # push PUNCH to recv_queue so the child thread will send packet
                recv_queue.put(msg['content'], block=False)
                evefd.set()
                global peer_ip, peer_port
                peer_ip = msg['content']['ip']
                peer_port = int(msg['content']['port'])
                app.text.configure(state='normal')
                app.text.insert(END, "[INFO] start UDP punching\n")
                app.text.configure(state='disabled')
            elif msg['result'] == ServerResponse.EXCHANGE:
                # receive public key from server
                serverPublicKey = int(msg['content']['serverPublicKey'])
                self.sharedKey = str((serverPublicKey**self.privateKey)%PUBLIC_MOD)

            print("Text message received: {0}".format(payload.decode('utf8')))

    def sendTask(self, payload):
        self.sendMessage(payload)


class App(object):

    def send(self, payload: str):
        m = self.factory.connected
        if m is None:
            print('No connection. This should not happen.')
        else:
            reactor.callFromThread(m.sendTask, payload.encode())

    def onQuit(self):
        if child is not None:
            recv_queue.put({'cmd': ClientChildCmd.CLOSE})
            evefd.set()
            child.join()
        reactor.stop()


    def login(self):
        self.login_screen = Toplevel(self.master)
        self.login_screen.title("login")
        self.login_screen.geometry("300x250")

        username = StringVar()
        password = StringVar()

        # Set label for user's instruction
        Label(self.login_screen, text="Please enter details below", bg="blue").pack()
        Label(self.login_screen, text="").pack()

        # Set username label
        username_lable = Label(self.login_screen, text="Username * ")
        username_lable.pack()

        # Set username entry
        # The Entry widget is a standard Tkinter widget used to enter or display a single line of text.
        self.username_entry = Entry(self.login_screen, textvariable=username)
        self.username_entry.pack()

        # Set password label
        password_lable = Label(self.login_screen, text="Password * ")
        password_lable.pack()

        # Set password entry
        self.password_entry = Entry(self.login_screen, textvariable=password, show='*')
        self.password_entry.pack()
        Label(self.login_screen, text="").pack()
        # Set login button
        Button(self.login_screen, text="Login", width=10, height=1, bg="blue", command=self.login_action).pack()

    def login_action(self):
        """
        sends login information to the server
        """
        if token is None:
            username = self.username_entry.get()
            password = self.password_entry.get()
            msg = json.dumps({'type': MsgType.LOGIN, 'data':
                             {'username': username, 'password': password}})
            msg += CRLF
            self.send(msg)
            self.login_screen.destroy()
        else:
            messagebox.showinfo(title='info', message='Already Log in.')

    def register(self):
        self.register_screen = Toplevel(self.master)
        self.register_screen.title("login")
        self.register_screen.geometry("300x250")

        username = StringVar()
        password = StringVar()

        # Set label for user's instruction
        Label(self.register_screen, text="Please enter details below", bg="blue").pack()
        Label(self.register_screen, text="").pack()

        # Set username label
        username_lable = Label(self.register_screen, text="Username * ")
        username_lable.pack()

        # Set username entry
        # The Entry widget is a standard Tkinter widget used to enter or display a single line of text.
        self.register_username_entry = Entry(self.register_screen, textvariable=username)
        self.register_username_entry.pack()

        # Set password label
        password_lable = Label(self.register_screen, text="Password * ")
        password_lable.pack()

        # Set password entry
        self.register_password_entry = Entry(self.register_screen, textvariable=password, show='*')
        self.register_password_entry.pack()
        Label(self.register_screen, text="").pack()
        Button(self.register_screen, text="Register", width=10, height=1, bg="blue", command=self.register_action).pack()

    def register_action(self):
        if token is None: # if user already login, he/she cannot register
            username = self.register_username_entry.get()
            password = self.register_password_entry.get()
            msg = json.dumps({'type': MsgType.REGISTER, 'data':
                             {'username': username, 'password': password}})
            msg += CRLF
            self.send(msg)
            self.register_screen.destroy()
        else:
            messagebox.showinfo(title='info', message='Already Log in.')

    def get_user_action(self):
        # send request to get all online users to server
        if token is not None:
            msg = json.dumps({'type': MsgType.GET_ACTIVE_USER, 'data':
                             {'token': token}})
            msg += CRLF
            self.send(msg)
        else:
            messagebox.showerror(title='error', message='Please log in first.')

    def request_connection_action(self):
        # request to start p2p with another peer
        if token is not None:
            username = self.connect_entry.get()
            msg = json.dumps({'type': MsgType.REQUEST_CONNECT, 'data': {'token': token, 'target': username}})
            msg += CRLF
            self.send(msg)
        else:
            messagebox.showerror(title='error', message='Please log in first.')

    def send_chat_message_action(self):
        # send chatting message. First push the message to recv_queue, then the child thread sends the message using UDP socket
        if token is not None:
            if peer_port is not None and peer_ip is not None:
                chat_message = self.chat_entry.get()
                recv_queue.put({'cmd': ClientChildCmd.SEND, 'content': chat_message.strip(), 'ip': peer_ip, 'port': peer_port}, block=False)
                evefd.set()
            else:
                messagebox.showerror(title='error', message='Please connect to a peer first.')
        else:
            messagebox.showerror(title='error', message='Please log in first.')

    def refresh_chat(self):
        """
        refresh GUI every 1000ms
        """
        while not msg_queue.empty():
            msg = msg_queue.get()
            if msg['type'] == ChatType.SEND:
                tmp = "[me] {}\n".format(msg['content'])
            else:
                tmp = "[{}:{}] {}\n".format(msg["ip"], msg["port"], msg['content'])
            self.chat_text.configure(state='normal')
            self.chat_text.insert(END, tmp)
            self.chat_text.configure(state='disabled')
        self.chat_text.after(1000, self.refresh_chat)

    def __init__(self, master, factory):
        self.master = master
        self.factory = factory
        frame = Frame(master)
        frame.pack()

        Button(frame, text="Login", command=self.login).grid(row=0)
        Button(frame, text="Register", command=self.register).grid(row=0, column=1)
        Button(frame, text="Users", command=self.get_user_action).grid(row=0, column=2)
        Label(frame, text="Server info").grid(row=1)
        self.text = Text(frame, width=40, height=15, undo=True, autoseparators=False)
        self.text.grid(row=2)
        self.text.configure(state='disabled')
        Label(frame, text="Chat info").grid(row=1, column=2)
        global chat_text
        self.chat_text = Text(frame, width=40, height=15, undo=True, autoseparators=False)
        self.chat_text.grid(row=2, column=2)
        self.chat_text.configure(state='disabled')
        self.chat_text.after(1000, self.refresh_chat)
        Label(frame, text="Who do you want to chat with?").grid(row=3)
        username = StringVar()
        self.connect_entry = Entry(frame, textvariable=username)
        self.connect_entry.grid(row=4)
        Button(frame, text="Send Request", command=self.request_connection_action).grid(row=5)

        Label(frame, text="Enter chat message here").grid(row=3, column=2)
        chat_message = StringVar()
        self.chat_entry = Entry(frame, textvariable=chat_message)
        self.chat_entry.grid(row=4, column=2)
        Button(frame, text="Send Chat Message", command=self.send_chat_message_action).grid(row=5, column=2)
        self.master.protocol("WM_DELETE_WINDOW", self.onQuit)


if __name__ == '__main__':
    log.startLogging(sys.stdout)
    factory = WebSocketClientFactory()
    factory.protocol = MyClientProtocol
    root = Tk()
    root.title("Xianghui's p2p Chat")
    root.geometry('800x600')
    tksupport.install(root)
    app = App(root, factory)
    # reactor.connectTCP("3.144.204.128", 9995, factory)
    reactor.connectTCP(SERVER_IP, SERVER_PORT, factory)
    reactor.run()
