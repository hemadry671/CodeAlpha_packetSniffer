# CodeAlpha Internship – Tasks 1 & 3 Submission  
**Author:** Hemadry Biswas  

This repository contains my submission for the following CodeAlpha internship tasks:

- **Task 1: Network Packet Sniffer** – Developed a Python-based packet sniffer using raw sockets.  
- **Task 3: Secure Coding Review** – Performed a manual security audit of the same packet sniffer, identified vulnerabilities, and implemented mitigations.

The updated and hardened script is included in this repository along with a `Fixes.txt` file documenting all discovered issues and their corresponding fixes.

---

## Network Packet Sniffer in Python

A simple network packet sniffer built using raw sockets in Python. It captures Ethernet frames and parses IPv4, TCP, UDP, and ICMP packets. Data payloads are also extracted and formatted for inspection.

### Features

- Raw socket capture using AF_PACKET  
- Ethernet frame parsing  
- IPv4 header parsing  
- TCP, UDP, and ICMP protocol parsing  
- ASCII formatted data output  

### Requirements

- Python 3  
- Root privileges (for socket access)  
- Linux system (AF_PACKET is Linux-specific)  

### Usage

```bash
sudo python3 sniffer.py
