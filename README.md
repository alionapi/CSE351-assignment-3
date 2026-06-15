# CSE351-assignment-3
CSE351: Computer Networks | Fall 2025 | Programming Assignment 3

Simple TCP (STCP) Transport Layer Implementation

## Overview

This project implements a simplified TCP transport layer (STCP) in C using the provided MYSOCK framework. The implementation supports reliable, connection-oriented communication through connection establishment, data transfer, and graceful connection termination.

## Features

* TCP-style 3-way handshake
* TCP-style 4-way connection teardown
* Reliable full-duplex data transfer
* Packet segmentation and reassembly
* Sequence number and acknowledgment management
* Delayed ACK mechanism
* Sender-side flow control
* In-order delivery of application data
* Compatible with the provided client and server framework

## Repository Structure

```text
.
├── CSE351_PA3.pdf              # Assignment specification
├── README.md                   # Repository documentation
├── transport.c                 # STCP implementation
└── project3/                   # files provided by the course instructor
    ├── Makefile
    ├── ENVCFG.MK
    ├── client.c
    ├── server.c
    ├── transport.h
    ├── mysock.c
    ├── mysock.h
    ├── mysock_api.c
    ├── network.c
    ├── network.h
    ├── network_io.c
    ├── network_io_socket.c
    ├── network_io_tcp.c
    ├── connection_demux.c
    ├── stcp_api.c
    ├── tcp_sum.c
    ├── report.txt
    └── additional framework and build files
```

## Building

Compile the project with:

```bash
cd project3
make all
```

## Running

Start the server:

```bash
./server
```

The server prints its listening address and port.

In another terminal, start the client:

```bash
./client <server_ip>:<server_port>
```

Example:

```bash
./client 127.0.0.1:33451
```

## File Transfer

To request a file from the server:

```bash
./client <server_ip>:<server_port> -f <filename>
```

Example:

```bash
./client 127.0.0.1:33451 -f test.txt
```

The downloaded file is saved locally as `rcvd`.

## Implemented Functionality

### Connection Establishment

* Active and passive connection setup
* 3-way handshake using SYN, SYNACK, and ACK packets
* Connection state management

### Connection Termination

* Graceful 4-way handshake
* FINACK and ACK processing
* Support for active and passive close

### Reliable Data Transfer

* Segmentation of application data into STCP packets
* Sequence number tracking
* Acknowledgment processing
* In-order delivery to the application layer

### Delayed ACK

Acknowledgments are transmitted using a delayed ACK policy to improve communication efficiency while maintaining reliable delivery.

### Flow Control

The sender limits outstanding unacknowledged data according to the receiver window to avoid buffer overflow.

## Main Implementation

The primary implementation is contained in `transport.c`, which provides:

* Connection setup and teardown
* Packet construction and parsing
* Sequence and acknowledgment handling
* Data transmission and reception
* Delayed ACK logic
* Flow control
