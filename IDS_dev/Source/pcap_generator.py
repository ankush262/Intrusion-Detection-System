from scapy.all import IP, TCP, UDP, ICMP, send, wrpcap
import random

# Define the output PCAP file
pcap_filename = "synthetic_attack_traffic.pcap"
packets = []

# Simulate DoS Attack (Flooding TCP SYN packets)
for _ in range(100):
    pkt = IP(dst="192.168.0.4") / TCP(dport=80, flags="S")
    packets.append(pkt)

# Simulate Port Scanning (TCP SYN packets to multiple ports)
for port in range(20, 1024, 50):
    pkt = IP(dst="192.168.0.4") / TCP(dport=port, flags="S")
    packets.append(pkt)

# Simulate Botnet-like Behavior (Random UDP traffic)
for _ in range(50):
    pkt = IP(dst="192.168.0.4") / UDP(dport=random.randint(1024, 65535)) / b"Botnet Traffic"
    packets.append(pkt)

# Simulate ICMP-based Attack (Ping Flood)
for _ in range(30):
    pkt = IP(dst="192.168.0.4") / ICMP()
    packets.append(pkt)

# Save packets to PCAP file
wrpcap(pcap_filename, packets)
print(f"Synthetic attack traffic saved to {pcap_filename}")
