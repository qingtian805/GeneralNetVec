__all__ = [
    "EPSILON", "header_len"
]

from scapy.packet import Packet, Raw

EPSILON = 2.2204e-16

def header_len(pkt: Packet):
    try:
        length = len(pkt) - len(pkt[Raw])
    except IndexError:
        length = len(pkt)

    return length
