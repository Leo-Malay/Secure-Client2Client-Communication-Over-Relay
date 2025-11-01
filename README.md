# Secure Client-2-Client Communication Over Relay

## Goal

Design and implement a secure messaging system where multiple clients communicate indirectly through a central Relay Server—without revealing identities or allowing the Relay to read or tamper with messages.

## System Components

| Component    | Description                                                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| Relay Server | A central router that forwards messages between clients, but should learn nothing about contents or identities beyond pseudonyms. |
| Clients      | Users of the chat system. They do not communicate directly with each other but send/receive ciphertext via the Relay.             |

## Run
