import numpy as np

from scapy.utils import EDecimal
from scapy.packet import Packet, Raw

class Conf:
    def __init__(self):
        self.grp_list         = None # type: list[Packet]
        self.last_end_time    = None # type: EDecimal
        self.max_cft_pkt      = 1 # type: int
        self.max_cft_pkt_prob = 0.01 # type: float
        self.max_time_extend  = 6. # type: float
        self.min_time_extend  = 3. # type: float
        self.fence_time_divider = 10000 # type: int
        self.cft_time_divider = 1000 # type: int
        self.proto_min_lmt    = 1. # type: float
        self.data_max_lmt     = [np.nan, 1500., 1480., 1460.] # type: list
        self.data_min_lmt     = 0. # type: float

        self.grp_size      = None # type: int
        self.proto_max_lmt = None # type: list[float]

cfg = Conf()

class NetAlg:
    def __init__(
            self,
            grp_list: list[Packet],
            last_end_time: EDecimal,
            max_cft_pkt: int = 1,
            max_cft_pkt_prob: float = 0.01,
            max_time_extend: float = 6.,
            min_time_extend: float = 3.,
            fence_time_divider: int = 10000,
            cft_time_divider: int = 1000,
            proto_min_lmt: float = 1.,
            data_max_lmt: list = [np.nan, 1500., 1480., 1460.],
            data_min_lmt: float = 0.
        ):
        r"""
        netAlg 网络算法基类，将自动进行一些有关 Unit 类的设置

        :param grp_list: 原始恶意流量
        :param max_cft_pkt: 每个原始包对应构建包的最大数量(l_c)
        :param max_cft_pkt_prob: 在 0-1 之间的概率,限制一个slot填入构造包的最大概率,相当于 max_cft_pkt 的最大乘数
        :param max_time_extend: 新流量相较于原始的时间倍数(l_t)
        :param min_time_extend: 新流量相较于原始的时间倍数(l_t)
        :param fence_time_divider: 用于计算原始包之间的最小时间间隔,代表最大允许时间间隔中存在多少个可用时间位置
        :param cft_time_divider: 用于计算构建包与前个包之间的最小时间间隔,代表在构建包与前个包时间间隔中存在多少个可用时间位置
        :param proto_min_lmt: 用于限制构建包最小使用的协议层数
        :param data_max_lmt: 用于限制构建包的 mtu, list 的序号对应协议层数, 如序号 2 限制 2 层包的 mtu
        :param data_min_lmt: 用于限制构建包最小的 mtu, 限制构建包, 无论协议层数
        """
        self.cfg = cfg
        cfg.grp_list = grp_list
        cfg.last_end_time = last_end_time

        cfg.max_cft_pkt = max_cft_pkt
        cfg.max_cft_pkt_prob = max_cft_pkt_prob
        cfg.max_time_extend = max_time_extend
        cfg.min_time_extend = min_time_extend

        cfg.proto_min_lmt = proto_min_lmt
        cfg.data_max_lmt = data_max_lmt
        cfg.data_min_lmt = data_min_lmt

        # 用于计算原始包之间的最小时间间隔，D 代表最大允许时间间隔中存在多少个可用时间位置
        cfg.fence_time_divider = fence_time_divider
        # 用于计算构建包与前个包之间的最小时间间隔，DD 代表在构建包与前个包时间间隔中存在多少个可用时间位置
        cfg.cft_time_divider   = cft_time_divider

        # calculate grpList related data
        cfg.grp_size = len(grp_list)
        cfg.proto_max_lmt = []
        for i in grp_list:
            layers = i.layers()
            try:
                layers.remove(Raw)
            except ValueError:
                pass    
            proto_layer = len(layers)

            if proto_layer > 3:
                proto_layer = 3

            cfg.proto_max_lmt.append(float(proto_layer))

if __name__ == "__main__":
    from scapy.utils import rdpcap
    with open("test.pcap", "rb") as f:
        grp_list = rdpcap(f)

    alg = NetAlg(grp_list, grp_list[-1].time)

    for name, value in cfg.__dict__.items():
        print(name, value)
    print()

    for name, value in alg.__dict__.items():
        print(name, value)
