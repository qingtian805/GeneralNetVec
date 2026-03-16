import sys
import os
sys.path.append(f"{os.path.abspath(".")}")
from net_vec.algorithum import NetAlg, cfg

from scapy.utils import rdpcap
with open("test.pcap", "rb") as f:
    pkt_list = rdpcap(f)

alg = NetAlg(pkt_list, pkt_list[-1].time)

for name, value in cfg.__dict__.items():
    print(name, value)
print()

for name, value in alg.__dict__.items():
    print(name, value)