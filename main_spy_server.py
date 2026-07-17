from threading import Thread
import socket
from socketserver import UDPServer
from struct import pack, unpack
from queue import Queue
from enum import Enum, auto
from typing import Callable
import pickle as pkl
from scapy.sendrecv import AsyncSniffer
from scapy.layers.all import *
from scapy.packet import Packet
from scapy.arch import get_if_list, get_if_addr, get_if_addr6

from exam_protocal import *

"""
基本架构：
                            +----+
[Target]----[TimeSpy]-------|----|-------[Client]
                |           |NIDS|          |
            Timedata--------|----|----------/
                            +----+
                          t + rt + dt       t
我们要做什么：
  让时间序列在抵达 NIDS 时保持不变
  t 是发送时间
  rt 是指理想状态（路径上只有一条消息）下到达时间
  dt 是现实情况（拥塞、排队等）导致的时间延迟
一些想法：
  1. 消除 dt？ 做不到，dt 是一个完全随机的量（对攻击者来说），无法准确消除
  2. 我们能做的是消除 rt，需要我们对序列进行预测，在应答抵达前发送封包
  3. 但这样似乎没有意义，因为我们抓取的良性流量特征应该已经考虑到了这些问题
     我们要做的可能是将一个将一个在其他网络抓取的流量修改到当前时间序列
  4. 使用贝叶斯计算时间期望？
"""

HOST, PORT = "localhost", 50000
BUFFER_SIZE = 0

class CtlSrvStatus(Enum):
    RUNNING = auto()
    IDLE    = auto()

class Event(Enum):
    START = auto()
    STOP  = auto()

def get_addr_if(address: str) -> str | None:
    for iface in get_if_list():
        addrs = (get_if_addr(iface), get_if_addr6(iface))
        if address in addrs:
            return iface
    # If we did not get any thing
    return None

class TimeSpy(FSMBase):
    def capture(self, packet: Packet):
        if not self.buffer.full():
            self.buffer.put_nowait(packet)
        else:
            print("Too much traffic!")

    def spy(self):
        self.contact = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.contact.connect(self.client_address_save)
        while True:
            pkt = self.buffer.get()
            if pkt is None:
                break

            t_dump = pkl.dumps(pkt.time)
            msg = pack(">i", len(t_dump)) + t_dump

            self.contact.sendall(msg)

    def start(self, msg: bytes):
        host_length = unpack(">I", msg[0:4])[0] # type: int
        t_host = msg[4:4 + host_length].decode("utf-9")
        t_port = unpack(">H", msg[4 + host_length:6 + host_length])[0] # type: int
        t_proto = unpack(">H", msg[6 + host_length:8 + host_length])[0] # type: int

        iface = get_addr_if(t_host)
        protocal = None
        match t_proto:
            case 0:
                protocal = "tcp"
            case 1:
                protocal = "udp"
            case 2:
                protocal = "icmp"

        bpf = f"{protocal} port {t_port} and host {t_host}"
        self.sniffer = AsyncSniffer(prn=self.capture, iface=iface, filter=bpf)
        self.spy_thread = Thread(target=self.spy)

        self.spy_thread.start()
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop(join=True)
        self.buffer.put(None)
        self.spy_thread.join()

    transitions = {
        (CtlSrvStatus.IDLE,    Event.START): (CtlSrvStatus.RUNNING, start),
        (CtlSrvStatus.RUNNING, Event.STOP):  (CtlSrvStatus.IDLE,    stop),
    } # type: dict[tuple[CtlSrvStatus, Event], tuple[CtlSrvStatus, Callable]]
    status = CtlSrvStatus.IDLE

    def __init__(self, request, client_address, server):
        self.buffer = Queue(BUFFER_SIZE) # type: Queue[Packet | None]
        self.sniffer = None
        self.client_address_save = None
        self.spy_thread = None # type: Thread | None
        super().__init__(request, client_address, server)

if __name__ == "__main__":
    with UDPServer((HOST, PORT), TimeSpy) as server:
        # 激活服务器；它将持续运行直到你
        # 使用 Ctrl-C 中断程序
        try:
            server.allow_reuse_address = True
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
