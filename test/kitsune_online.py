import sys
import os
sys.path.append(f"{os.path.abspath(".")}")
from scapy.utils import rdpcap

from examinators import OLKitsuneExam

exam = OLKitsuneExam("./exam_res/kitsune/model.pkl")

pcap = rdpcap("test.pcap")

exam.prepare_exam()
rmse = exam.exam_pkt(pcap)

print(rmse)
