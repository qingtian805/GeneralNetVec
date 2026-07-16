import sys
import os
sys.path.append(f"{os.path.abspath(".")}")
from net_vec import NetAlg, cfg

from scapy.utils import rdpcap
with open("test/simple_packet.pcap", "rb") as f:
    pkt_list = rdpcap(f)

cfg.set_pkt_list(pkt_list)

alg = NetAlg()

for name, value in cfg.__dict__.items():
    print(name, value)
print()

for name, value in alg.__dict__.items():
    print(name, value)