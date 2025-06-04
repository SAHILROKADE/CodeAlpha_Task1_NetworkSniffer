from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Packet Captured at {timestamp}")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("Protocol: ", end="")

        if protocol == 6:
            print("TCP")
            print(f"Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif protocol == 17:
            print("UDP")
            print(f"Ports: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif protocol == 1:
            print("ICMP")
        else:
            print(f"Other ({protocol})")

        raw_data = bytes(packet.payload)
        print(f"Payload (first 100 bytes): {raw_data[:100]}")
    else:
        print("Non-IP Packet")

print("Sniffing started... Press Ctrl+C to stop.\n")
sniff(prn=packet_callback, store=False)
