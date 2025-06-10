#!/usr/bin/env python3

import socket
import struct
import sys
import os

def get_mac(addr):
    return ':'.join(f'{b:02x}' for b in addr)

def unpack_ethernet(data):
    if len(data) < 14:
        return None
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest), get_mac(src), socket.htons(proto), data[14:]

def unpack_ipv4(data):
    if len(data) < 20:
        return None
    version_ihl = data[0]
    ihl = (version_ihl & 15) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(dst), data[ihl:]

def unpack_tcp(data):
    if len(data) < 14:
        return None
    src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    if offset < 14 or len(data) < offset:
        return None
    urg = (offset_flags & 32) >> 5
    ack_f = (offset_flags & 16) >> 4
    psh = (offset_flags & 8) >> 3
    rst = (offset_flags & 4) >> 2
    syn = (offset_flags & 2) >> 1
    fin = offset_flags & 1
    return src_port, dst_port, seq, ack, urg, ack_f, psh, rst, syn, fin, data[offset:]

def unpack_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack('! H H 2x H', data[:8])
    if length < 8 or len(data) < length:
        return None
    return src_port, dst_port, length, data[8:]

def unpack_icmp(data):
    if len(data) < 4:
        return None
    type_, code, checksum = struct.unpack('! B B H', data[:4])
    return type_, code, checksum, data[4:]

def format_payload(data):
    if not data:
        return ""
    if len(data) > 100:
        data = data[:100]
    
    result = ''
    for b in data:
        if 32 <= b <= 126:
            result += chr(b)
        else:
            result += '.'
    return result

def drop_privileges():
    if os.getuid() != 0:
        return
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)

def main():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Need root privileges")
        sys.exit(1)
    
    drop_privileges()
    
    count = 0
    max_packets = 10000
    print(f"Capturing packets (max {max_packets})...")
    
    try:
        while count < max_packets:
            try:
                data = sock.recv(65536)
                if not data:
                    continue
                
                count += 1
                print(f"\nPacket {count}:")
                
                eth = unpack_ethernet(data)
                if not eth:
                    continue
                dst_mac, src_mac, eth_proto, eth_payload = eth
                print(f"  ETH: {src_mac} -> {dst_mac}")
                
                if eth_proto == 8:
                    ipv4 = unpack_ipv4(eth_payload)
                    if not ipv4:
                        continue
                    ttl, ip_proto, src_ip, dst_ip, ip_payload = ipv4
                    print(f"  IP:  {src_ip} -> {dst_ip} (TTL: {ttl})")
                    
                    if ip_proto == 6:
                        tcp = unpack_tcp(ip_payload)
                        if not tcp:
                            continue
                        src_port, dst_port, seq, ack, urg, ack_f, psh, rst, syn, fin, tcp_payload = tcp
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
                        
                        if tcp_payload:
                            payload = format_payload(tcp_payload)
                            if payload.strip():
                                print(f"       Data: {payload}")
                    
                    elif ip_proto == 17:
                        udp = unpack_udp(ip_payload)
                        if not udp:
                            continue
                        src_port, dst_port, length, udp_payload = udp
                        print(f"  UDP: {src_port} -> {dst_port} (len: {length})")
                        
                        if udp_payload:
                            payload = format_payload(udp_payload)
                            if payload.strip():
                                print(f"       Data: {payload}")
                    
                    elif ip_proto == 1:
                        icmp = unpack_icmp(ip_payload)
                        if not icmp:
                            continue
                        icmp_type, code, checksum, icmp_payload = icmp
                        print(f"  ICMP: Type {icmp_type}, Code {code}")
                        
                        if icmp_payload:
                            payload = format_payload(icmp_payload)
                            if payload.strip():
                                print(f"        Data: {payload}")
                    
                    else:
                        print(f"  Unknown protocol: {ip_proto}")
            
            except struct.error:
                continue
            except KeyboardInterrupt:
                break
    
    finally:
        sock.close()
        print(f"\nStopped. Captured {count} packets")

if __name__ == "__main__":
    main()
