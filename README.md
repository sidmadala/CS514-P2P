# CS514-P2P
P2P chat and file sharing application written in Python




# Description of Files
**Common.py**

The Common.py class is used by a variety of the other files in our project. Its purpose is to set some variables, such as the server's IP address and port, and to define types of packets that can be sent across our P2P network. First, a configuration message can be sent. A configuration message can be of several types, which correspond to actions users can do. These include registering, logging in, getting the active user, request to connect, agreeing to a connection, and pinging a user. Next, the server can respond with a message, which correspond to a successful login, a successful/failure to connect, getting a list of users, requesting to connect, performing a UDP ping and punch. Next, a child process can send a command of a couple types- punch, send and close. Finally, we define the different types of chat messages that can be sent which include a simple message, a heartbeat, sending data, and punching.

**Chat.py**

The Chat.py class is how we configure the messages to be sent across our P2P chat system. In this file, we establish a socket connection and then have an event loop that basically listens for incoming packets. It then processes each of the messages in this queue and then performs the action corresponding to the type of message in the queue. The types of messages that this event loop can process include UDP hole punching, sending data, sending a message, and sending a heartbeat. The data is then sent over the UDP socket that was established. 


# Challenges and Future Work
We face a couple of key challenges while completing this project. Given the time constraints of the end of the semester, we were able to overcome some of the challenges, but for the others, we have decided to leave for future work. The first difficulty that we had to overcome was working under different environments. Two of us have Mac computers, while the others were working in a linux environment. As a result, some of the code of the project was not compatible across environments. We understand that this puts a constraint on the ability for everyone to use our P2P network, but we were unable to expand compatibility in such a short time period. This will be one of the primary focuses for the future. Similar to this environment issue, we also had to adjust based off of the network we each used. The Duke wifi network blocked UDP packets, and as a result, we had to make sure to work on our project with a hotspot or off campus. While we initially planned on implementing file sharing over the P2P network, we were not able to get this done in conjunction with the messaging system. We decided that the base functionality of sending messages and encrypting connections to the network was more important. Finally, as this project was more of a proof of concept, we made some concessions on the scalability of our network. In particular, we decided to use a simple dictionary of user's connected to the network instead of a proper database. This will need to be fixed in the future in order to expand our P2P network.   
