# secure-tcp-multiprocess-server
Secure TCP client-server application implemented in C and Python featuring custom protocol framing, fork-based multiprocessing, session management, authentication, salted password hashing, rate limiting, audit logging, and abuse protection.

Secure Multiprocess TCP Server with Custom Protocol
Overview

This project implements a secure client-server application for the IE2102 Network Programming module. The system consists of a TCP server written in C and a client application written in Python. The server uses multiprocessing with fork() to handle multiple concurrent clients and provides secure authentication, session management, custom protocol framing, abuse protection, and audit logging.

Features
TCP-based client-server communication
Custom message framing protocol (LEN:<n>)
Concurrent client handling using fork()
Secure user registration and login
Salted password hashing
Session token generation and validation
Session timeout after inactivity
Rate limiting for clients
Brute-force login protection
Username validation
Payload overflow detection and rejection
Persistent audit logging
Proper SIGCHLD handling to prevent zombie processes
Makefile-based build system
Technologies Used
C (Server)
Python (Client)
TCP Sockets
Linux System Programming
Process Management (fork, waitpid)
Cryptographic Hashing
File-based Logging
Project Structure
.
├── server_XXXX.c
├── client_XXXX.py
├── Makefile_XXXX
├── server_<regno>.log
├── users/
├── sessions/
└── README.md
Learning Outcomes

This project demonstrates:

Socket programming using TCP
Multiprocess server design
Secure authentication mechanisms
Session management techniques
Network protocol implementation
Linux process management
Secure software development practices
Assignment Information

Module: IE2102 – Network Programming
Institution: Sri Lanka Institute of Information Technology (SLIIT)
Academic Year: 2026
