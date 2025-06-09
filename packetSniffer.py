#!/usr/bin/env python3

import socket
import struct
import sys

def get_mac(addr):
    return ':'.join(f'{b:02x}' for b in addr)

def unpack_ethernet(data):
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest), get_mac(src), socket.htons(proto), data[14:]

def unpack_ipv4(data):
    version_ihl = data[0]
    ihl = (version_ihl & 15) * 4
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(dst), data[ihl:]

def unpack_tcp(data):
    src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    urg = (offset_flags & 32) >> 5
    ack_f = (offset_flags & 16) >> 4
    psh = (offset_flags & 8) >> 3
    rst = (offset_flags & 4) >> 2
    syn = (offset_flags & 2) >> 1
    fin = offset_flags & 1
    return src_port, dst_port, seq, ack, urg, ack_f, psh, rst, syn, fin, data[offset:]

def unpack_udp(data):
    src_port, dst_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, length, data[8:]

def unpack_icmp(data):
    type_, code, checksum = struct.unpack('! B B H', data[:4])
    return type_, code, checksum, data[4:]

def format_payload(data):
    if len(data) > 100:
        data = data[:100]
    
    result = ''
    for b in data:
        if 32 <= b <= 126:
            result += chr(b)
        else:
            result += '.'
    return result

def main():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Need root privileges")
        sys.exit(1)
    
    count = 0
    print("Capturing packets...")
    
    try:
        while True:
            data, addr = sock.recvfrom(65536)
            count += 1
            
            print(f"\nPacket {count}:")
            
            dst_mac, src_mac, eth_proto, eth_payload = unpack_ethernet(data)
            print(f"  ETH: {src_mac} -> {dst_mac}")
            
            if eth_proto == 8:
                ttl, ip_proto, src_ip, dst_ip, ip_payload = unpack_ipv4(eth_payload)
                print(f"  IP:  {src_ip} -> {dst_ip} (TTL: {ttl})")
                
                if ip_proto == 6:
                    src_port, dst_port, seq, ack, urg, ack_f, psh, rst, syn, fin, tcp_payload = unpack_tcp(ip_payload)
                    print(f"  TCP: {src_port} -> {dst_port}")
                    
                    flags = []
                    if syn: flags.append('SYN')
                    if ack_f: flags.append('ACK')
                    if fin: flags.append('FIN')
                    if rst: flags.append('RST')
                    if psh: flags.append('PSH')
                    if urg: flags.append('URG')
                    
                    if flags:
                        print(f"       Flags: {', '.join(flags)}")
                    
                    if len(tcp_payload) > 0:
                        payload = format_payload(tcp_payload)
                        if payload.strip():
                            print(f"       Data: {payload}")
                
                elif ip_proto == 17:
                    src_port, dst_port, length, udp_payload = unpack_udp(ip_payload)
                    print(f"  UDP: {src_port} -> {dst_port} (len: {length})")
                    
                    if len(udp_payload) > 0:
                        payload = format_payload(udp_payload)
                        if payload.strip():
                            print(f"       Data: {payload}")
                
                elif ip_proto == 1:
                    icmp_type, code, checksum, icmp_payload = unpack_icmp(ip_payload)
                    print(f"  ICMP: Type {icmp_type}, Code {code}")
                    
                    if len(icmp_payload) > 0:
                        payload = format_payload(icmp_payload)
                        if payload.strip():
                            print(f"        Data: {payload}")
                
                else:
                    print(f"  Unknown protocol: {ip_proto}")
    
    except KeyboardInterrupt:
        print(f"\nStopped. Captured {count} packets")

if __name__ == "__main__":
    main()
