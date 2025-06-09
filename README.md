# Network Packet Sniffer in Python

A simple network packet sniffer built using raw sockets in Python. It captures Ethernet frames and parses IPv4, TCP, UDP, and ICMP packets. Data payloads are also extracted and formatted for inspection.

## Features
- Raw socket capture using AF_PACKET
- Ethernet frame parsing
- IPv4 header parsing
- TCP, UDP, and ICMP protocol parsing
- ASCII formatted data output

## Requirements
- Python 3
- Root privileges (for socket access)
- Linux system (AF_PACKET is Linux-specific)

## Usage

```bash
sudo python3 sniffer.py

