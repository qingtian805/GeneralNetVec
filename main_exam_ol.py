from exam_online import OnlineExam
from examinators import OLKitsuneExam
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

exam = OLKitsuneExam("./exam_res/kitsune/model.pkl")
e = OnlineExam(exam, batch_size=20, buffer_size=10)

e.exam()
