#! /usr/bin/env python

from scapy.all import *

done = False
server = '3e:1a:b3:e6:6b:68'
sender = 'f2:e5:fb:14:52:b2'
while not done:
	pkt = sniff(iface='eth0', count=2)
	if pkt[0].src == sender:
		ans = sr1(pkt[0], iface='eth0')
		
