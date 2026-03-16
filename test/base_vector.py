import os, sys
sys.path.append(f"{os.path.abspath(".")}")

from scapy.all import *
from net_vec.vector import Unit
from net_vec.algorithum import NetAlg
with open("./test.pcap", "rb") as f:
    pkt_list = rdpcap(f)

alg = NetAlg()
alg.set_pkt_list(pkt_list, pkt_list[0].time)

t = Unit()

print(t.mal)
print(t.craft)

t.restrict()

print(t.mal)
print(t.craft)

r = t.rebuild()

for i in r:
    i.show()

# for name, value in cfg.__dict__.items():
#     print(name, value)

# print()

# for name, value in alg.__dict__.items():
#     print(name, value)

# print(cfg == alg.cfg)

# cfg.pkt_num = 20

# print(cfg == alg.cfg)