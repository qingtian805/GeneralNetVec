import sys
import os
sys.path.append(f"{os.path.abspath(".")}")
from scapy.utils import rdpcap

from examinators import OLKitsuneExam

exam = OLKitsuneExam("exp_file/models/Kitsune/TM_ben.pkl")

pcap = rdpcap("test/test.pcap")

exam.prepare_exam()
rmse = exam.exam_pkt(pcap)

print(rmse)
