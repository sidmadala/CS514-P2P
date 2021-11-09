# SocketP2P
A P2P messaging system, featuring Diffie-Hellman session key exchange and AES symmetric encryption

## Components
### - Message parser (MsgParser)
A collection of processes used to encrypt/decrypt and encode/decode packets

### - Blaster 
A thread used to handle the delivery of messages to target peer

### - Listener
A thread used to monitor and respond to connection and messages from other peers

## Application layer protocol
```
message_type%%sender_name%%message
```
note: ```%%``` is used as the protocol delimiter between fields

### - field:message_type
```
TEXT|ACK|FILE
```