# Secure Relay-Based Chat System
A secure relay-based chat system implementing encrypted communication using RSA, Diffie–Hellman, and AES-GCM.


## Features
- RSA-2048 authentication
- Ephemeral Diffie–Hellman key exchange
- AES-128-GCM encryption
- Nonce-based replay protection
- Multi-threaded TCP socket architecture


## System Components
- **Client.java** – Handles registration, key exchange, messaging
- **Relay.java** – Central relay server for message routing
- **Node.java** – Cryptographic operations and key management
- **Message.java** – Structured message builder
- **MessageType.java** – Enum for supported protocol messages


## Protocol Phases
### 1. Registration
- Client sends RSA public key + nonce
- Relay registers client and returns `nonce - 1`


### 2. Session Key Establishment
- Ephemeral Diffie–Hellman exchange
- Shared AES key derived via SHA-256
- Three-way handshake ensures key confirmation


### 3. Secure Messaging
- AES-GCM used for confidentiality + integrity
- Fresh IV per message


## Running the System
### Terminal 1
```bash
make
java Relay
```
### Terminal 2
```bash
java Client Bob
```
### Terminal 3
```bash
java Client Alice Bob
```


## File Structure
```
project/
├── Client.java
├── Relay.java
├── Node.java
├── Message.java
├── MessageType.java
├── Makefile
└── keys/
```


## Message Types
- REGISTRATION
- REGISTRATION_ACK
- SESSIONKEY_INIT
- SESSIONKEY_ACK
- SESSIONKEY_VERIFY
- CHAT_MESSAGE


## Security Guarantees
- Confidentiality: AES-GCM
- Authentication: RSA keys
- Integrity: GCM auth tag
- Forward secrecy: Ephemeral DH
- Replay protection: Nonces


## Future Enhancements
- Group chat support
- Key rotation
- PKI-based authentication
- Cross-platform clients