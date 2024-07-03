# -*- coding: utf-8 -*-
"""
Created on Wed Jul  3 18:10:45 2024

@author: Hxtreme
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP Protocol
            proto_str = "TCP"
        elif protocol == 17:  # UDP Protocol
            proto_str = "UDP"
        else:
            proto_str = "Other"

        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {proto_str}")

        if packet.haslayer(TCP):
            tcp_payload = packet[TCP].payload
            print(f"TCP Payload: {tcp_payload}")
        elif packet.haslayer(UDP):
            udp_payload = packet[UDP].payload
            print(f"UDP Payload: {udp_payload}")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
