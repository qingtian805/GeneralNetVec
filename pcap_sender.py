from scapy.all import *
# conf.prog.tcpreplay = "/data/2024100711/bin/bin/tcpreplay"

class PcapSender:
    def __init__(self, pcap_file, traget_ip, traget_port = None):
        self.pcap_file = pcap_file
        self.target_ip = traget_ip
        self.target_port = traget_port

        with open(pcap_file, "rb") as f:
            pkts = rdpcap(f)

        self.pkt_list = []
        for pkt in pkts:
            if pkt.haslayer(Ether):
                # pkt[Ether].src = None
                pkt[Ether].dst = None
                # pkt[Ether].chksum = None

            if pkt.haslayer(IP):
                pkt[IP].src = None
                pkt[IP].dst = traget_ip
                pkt[IP].chksum = None
            
            if pkt.haslayer(TCP):
                pkt[TCP].chksum = None
                if self.target_port is not None:
                    pkt[TCP].dport = traget_port
            
            if pkt.haslayer(UDP):
                pkt[UDP].chksum = None
                if self.target_port is not None:
                    pkt[UDP].dport = traget_port

            self.pkt_list.append(pkt)
    
    def send(self):
        sendp(self.pkt_list, realtime = True)

    def send_fast(self):
        sendpfast(self.pkt_list, realtime=True)
        

if __name__ == "__main__":
    pcap_file = "./test.pcap"
    

    sender = PcapSender(pcap_file, "10.250.138.86", )
    sender.send()
    # time.sleep(5)
    # sender.send_fast()

# Send test note:
# The essential datas for sending to destination
"""
from scapy.all import *

# p = IP(dst="10.250.138.86")/ICMP()/Raw("XXXXXXXXXXXXXX")
# p.show()
# send(p)

p = Ether()/IP(dst="10.250.138.86")/UDP(dport=38881)/Raw("XXXXXXXXXXXXXX")
p.show()
sendp(p)

with open("simple_packet.pcap", "rb") as f:
    pkt_list = rdpcap(f)

# phrase = pkt_list[0]

# p = IP(dst="10.250.138.86").add_payload(pkt_list)
p = pkt_list[0]

p = pkt_list[0]
p[Ether].dst = None
# p[Ether].src = None
p[IP].dst = "10.250.138.86"
p[IP].src = None?
p[IP].chksum = None
# p[IP].ihl = None
# p[IP].len = None
p[UDP].chksum = None

p.show()
sendp(p)
"""
