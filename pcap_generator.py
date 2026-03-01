from scapy.all import *

# with open("simple_packet.pcap", "rb") as f:
#     pkts = rdpcap(f)
t = time.time()
pkts = []
for i in range(1, 11):

    pkt = Ether(dst="01:02:03:04:05:06")/\
        IP(dst="192.168.1.1")
    pkt.time = t
    t += 0.1*i
    pkts.append(pkt)

ls(pkts[0])

with open("test.pcap", "wb") as f:
    wrpcap("test.pcap", pkts)
