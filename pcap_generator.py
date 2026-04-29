from scapy.all import *

# with open("simple_packet.pcap", "rb") as f:
#     pkts = rdpcap(f)
t = time.time()
pkts = []
for i in range(1, 10):

    pkt = Ether(dst="01:02:03:04:05:06", src="06:05:04:03:02:01")/\
        IP(dst="192.168.1.1", src="192.168.1.2",)/\
        TCP(sport=2048, dport=22, flags="S")
    pkt.time = t
    t += 0.1*i
    pkts.append(pkt)

pkts.append(Ether(dst="01:02:03:04:05:06", src="06:05:04:03:02:01")/\
        IP(dst="192.168.1.1", src="192.168.1.2",)/\
        TCP(sport=2048, dport=22, flags="R"))
pkts[-1].time = t
t += 1

for i in range(10):
    pkt = Ether(dst="01:02:03:04:05:06", src="06:05:04:03:02:01")/\
        IP(dst="192.168.1.1", src="192.168.1.2")/\
        UDP(sport=2048, dport=3072)/Raw("test")

    pkt.time = t
    t += 1
    pkts.append(pkt)

with open("test.pcap", "wb") as f:
    wrpcap("test.pcap", pkts)
