from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")

        # If the packet has TCP layer, print TCP information
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"Source Port: {sport}, Destination Port: {dport}")

        # If the packet has UDP layer, print UDP information
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"Source Port: {sport}, Destination Port: {dport}")

        # Print packet summary
        print(packet.summary())

# Start sniffing packets
sniff(prn=packet_callback, store=0)
