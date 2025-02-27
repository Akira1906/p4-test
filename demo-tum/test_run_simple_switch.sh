#!/bin/bash

# Run the script as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "[INFO] Sending TCP handshake packets..."

# Execute Python script to send packets
python3 - <<EOF
from scapy.all import Ether, IP, TCP, sendp
import time

# Define MAC addresses
client_mac = "00:00:0a:00:01:01"  # h1 MAC
attacker_mac = "00:00:0a:00:01:02"  # h2 MAC
server_mac = "00:00:0a:00:01:03"  # h3 MAC
switch_client_mac = "00:01:0a:00:01:01"  # s1 client MAC
switch_server_mac = "00:01:0a:00:01:03"  # s1 server MAC

# Define IP addresses
client_ip = "10.0.1.1"
server_ip = "10.0.1.3"

# Define ports
client_port = 1234
server_port = 80

# Define interfaces
client_iface = "veth1"
server_iface = "veth5"

# Step 1: SYN (Client -> Server)
print("[INFO] Sending SYN from Client to Server...")
syn_pkt = (
    Ether(dst=switch_client_mac, src=client_mac) /
    IP(src=client_ip, dst=server_ip, ttl=64, id=1, flags=0) /
    TCP(sport=client_port, dport=server_port, flags="S")
)
sendp(syn_pkt, iface=client_iface)

# time.sleep(1)  # Wait before sending next packet

# # Step 2: SYN-ACK (Server -> Client)
# print("[INFO] Sending SYN-ACK from Server to Client...")
# syn_ack_pkt = (
#     Ether(dst=client_mac, src=switch_server_mac) /
#     IP(src=server_ip, dst=client_ip, ttl=63, id=1, flags=0) /
#     TCP(sport=server_port, dport=client_port, flags="SA", seq=2030043157, ack=1, window=8192)
# )
# sendp(syn_ack_pkt, iface=server_iface)

time.sleep(1)

# Step 3: ACK (Client -> Server)
print("[INFO] Sending ACK from Client to Server...")
ack_pkt = (
    Ether(dst=switch_client_mac, src=client_mac) /
    IP(src=client_ip, dst=server_ip, ttl=64, id=1, flags=0) /
    TCP(sport=client_port, dport=server_port, flags="A", seq=1, ack=2030043158, window=8192)
)
sendp(ack_pkt, iface=client_iface)

time.sleep(1)

# # Step 4: Proxy -> Server SYN
# print("[INFO] Sending Proxy SYN to Server...")
# proxy_syn_pkt = (
#     Ether(dst=server_mac, src=client_mac) /
#     IP(src=client_ip, dst=server_ip, ttl=63, id=1, flags=0) /
#     TCP(sport=client_port, dport=server_port, flags="S")
# )
# sendp(proxy_syn_pkt, iface=server_iface)

# time.sleep(1)

# Step 5: Server -> Proxy SYN-ACK
print("[INFO] Sending SYN-ACK from Server to Proxy...")
server_syn_ack_pkt = (
    Ether(dst=client_mac, src=server_mac) /
    IP(src=server_ip, dst=client_ip, ttl=64, id=1, flags=0) /
    TCP(sport=server_port, dport=client_port, flags="SA", seq=37, ack=1, window=8192)
)
sendp(server_syn_ack_pkt, iface=server_iface)

time.sleep(1)

# # Step 6: Proxy -> Server ACK
# print("[INFO] Sending Proxy ACK to Server...")
# proxy_ack_pkt = (
#     Ether(dst=server_mac, src=switch_server_mac) /
#     IP(src=client_ip, dst=server_ip, ttl=63, id=1, flags=0) /
#     TCP(sport=client_port, dport=server_port, flags="A", seq=1, ack=38, window=8192)
# )
# sendp(proxy_ack_pkt, iface=server_iface)

print("[INFO] TCP Handshake packets sent successfully.")
EOF
