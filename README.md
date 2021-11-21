# CS514-P2P
P2P chat and file sharing application written in Python




# Description of Files
**Common.py**

The Common.py class is used by a variety of the other files in our project. Its purpose is to set some variables, such as the server's IP address and port, and to define types of packets that can be sent across our P2P network. First, a configuration message can be sent. A configuration message can be of several types, which correspond to actions users can do. These include registering, logging in, getting the active user, request to connect, agreeing to a connection, and pinging a user. Next, the server can respond with a message, which correspond to a successful login, a successful/failure to connect, getting a list of users, requesting to connect, performing a UDP ping and punch. Next, a child process can send a command of a couple types- punch, send and close. Finally, we define the different types of chat messages that can be sent which include a simple message, a heartbeat, sending data, and punching.

**Chat.py**

The Chat.py class is how we configure the messages to be sent across our P2P chat system. In this file, we establish a socket connection and then have an event loop that basically listens for incoming packets. It then processes each of the messages in this queue and then performs the action corresponding to the type of message in the queue. The types of messages that this event loop can process include UDP hole punching, sending data, sending a message, and sending a heartbeat. The data is then sent over the UDP socket that was established. 

