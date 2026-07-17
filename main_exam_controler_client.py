import socket
import pickle as pkl
from enum import Enum, auto
from typing import Callable
from queue import Queue

from scapy.utils import rdpcap

from exam_protocal import *

class CtlCliStatus(Enum):
    IDLE      = auto()
    WAIT_RUN  = auto()
    RUNNING   = auto()
    FIN_EXAM  = auto()
    WAIT_STOP = auto()
    WAIT_SAVE = auto()
    SAVING    = auto()
    FIN_SAVE  = auto()
    ABORTING  = auto()

class LocEvent(Enum):
    LOC_FIN   = auto()
    LOC_START = auto()

STAT = CtlCliStatus
LEVNT = LocEvent
NEVNT = NetEvent

class ExamClient(FSMBase):
    def _start(self, exam_type: str, exam_paramters: dict):
        self.s.sendall(start_msg(exam_type, exam_paramters))

    def _exam(self):
        pkt_list = self.

        self.s.sendall(ack_msg())

        self.s.sendall()

    def transit(self, event: Event, **kwargs):
        """
        Event trigger, start an event use this function.
        """
        try:
            target_status, action = self.transations[(self.status, event)]
            action(**kwargs)
            self.status = target_status
        except KeyError:
            pass

    def destory(self):
        self.s.close()

    transations = {
            # Start
            (STAT.IDLE,     LEVNT.LOC_START) : (STAT.WAIT_RUN, _start),
            (STAT.WAIT_RUN, NEVNT.NET_ACK)   : (STAT.RUNNING , _exam),
            # End
            (STAT.RUNNING,  LEVNT.LOC_FIN)   : (STAT.WAIT_STOP, ),

            # Start Save
            # End Save
            # Abort
        }

    def __init__(
            self,
            host,
            port,
            pcap_file_list: list[str]
            ):
        """
        :param host: 服务器主机名，可以是 IPv4 地址，或可解析的主机名
        :param port: 服务器程序运行端口
        :param pcap_file_list: 进行测试的流量列表
        """
        super().__init__(
            init_status=STAT.IDLE,
            keep_alive=True
        )

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # IPv4, TCP
        self.s.connect((host, port))
        self.exam_index = 0
        self.pkt_list = pcap_file_list

if __name__ == "__main__":
    a = ExamClient()

