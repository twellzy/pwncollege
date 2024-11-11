from scapy.all import *

# Get the MAC address of eth0
iface = "eth0"
src_mac = get_if_hwaddr(iface)

# Create an Ethernet packet
packet = Ether(dst="FF:FF:FF:FF:FF:FF", src=src_mac) / "Hello, world!"

# Send the packet
sendp(packet, iface=iface)
