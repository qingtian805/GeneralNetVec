from scapy.utils import PcapReader, wrpcap, EDecimal
from scapy.packet import Packet
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.all import *
import os


PCAP_FILE = "test.pcap"
BUFFER_SIZE = 10000
CON_SAVE_PATH = "./pcaps/test"
UDP_TIMEOUT = 2.

def phrase(pkt:Packet):
    if pkt.haslayer(IP):
        ip1 = pkt[IP].src
        ip2 = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        ip1 = pkt[IPv6].src
        ip2 = pkt[IPv6].dst

    if pkt.haslayer(TCP):
        port1 = pkt[TCP].sport
        port2 = pkt[TCP].dport
        protocal = "TCP"

    elif pkt.haslayer(UDP):
        port1 = pkt[UDP].sport
        port2 = pkt[UDP].dport
        protocal = "UDP"

    return ip1, port1, ip2, port2, protocal

def pop_conn(ip1, p1, ip2, p2, proto):
    """
    Pop mappings from conns
    """
    # Delete connection from map
    conns.pop((ip1, p1, ip2, p2, proto))
    conns.pop((ip2, p2, ip1, p1, proto))

def write_conn(ip1, p1, ip2, p2, proto, plist):
    """
    Save connection plist in CON_SAVE_PATH
    """
    # Save connection
    path = os.path.join(CON_SAVE_PATH, f"{ip1}:{p1}-{ip2}:{p2}-{proto}")
    i = 1
    while os.path.exists(path + f"{i}.pcap"):
        i += 1

    wrpcap(os.path.join(path + f"{i}.pcap"), plist)

# 按照会话为单位分割一个流量捕获列表
# 五元组：IP1，Port1，IP2，Port2，Protocal

if not os.path.exists(CON_SAVE_PATH):
    print("Save directory not exist, creating...")
    os.mkdir(CON_SAVE_PATH)

reader = PcapReader(PCAP_FILE) # type: PcapReader
conns = {} # type: dict[tuple[IP | IPv6], tuple[list[Packet], EDecimal]]

while True:
    pkt_list = reader.read_all(BUFFER_SIZE)

    for pkt in pkt_list:
        print(pkt)
        ip1, p1, ip2, p2, proto = phrase(pkt)

        status = conns.get((ip1, p1, ip2, p2, proto))
        if status is None:
            plist = []
            status = conns[(ip1, p1, ip2, p2, proto)] = \
                conns[(ip2, p2, ip1, p1, proto)] = [plist, EDecimal()]
        else:
            plist = status[0]

        if proto == "TCP":
            # Maintain a status to track TCP shutdown
            plist.append(pkt)
            if 'R' in pkt[TCP].flags:
                write_conn(ip1, p1, ip2, p2, proto, plist)
                pop_conn(ip1, p1, ip2, p2, proto)
            if 'F' in pkt[TCP].flags:
                status[1] += 1.
            if status[1] >= 2 and 'A' in pkt[TCP].flags:
                write_conn(ip1, p1, ip2, p2, proto, plist)
                pop_conn(ip1, p1, ip2, p2, proto)
        elif proto == "UDP":
            # Use timeout to determain a UDP connection
            if status[1] > 0. and pkt.time - status[1] > UDP_TIMEOUT:
                write_conn(ip1, p1, ip2, p2, proto, plist)
                plist.clear()
            plist.append(pkt)
            status[1] = pkt.time

    if len(pkt_list) < BUFFER_SIZE:
        break

for key in conns.keys():
    status = conns.get(key)
    if status[1] >= 0:
        write_conn(*key, conns[key][0])
        status[1] = EDecimal(-1)
