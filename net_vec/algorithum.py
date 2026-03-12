import numpy as np
from scapy.utils import EDecimal
from scapy.packet import Packet, Raw

from config import cfg

class NetAlg:
    def __init__(
            self,
            pkt_list: list[Packet],
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

        :param pkt_list: 原始恶意流量
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
        cfg.pkt_list = pkt_list
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

        # calculate pkt_list related data
        cfg.pkt_num = len(pkt_list)
        cfg.proto_max_lmt = []
        for i in pkt_list:
            layers = i.layers()
            try:
                layers.remove(Raw)
            except ValueError:
                pass    
            proto_layer = len(layers)

            if proto_layer > 3:
                proto_layer = 3

            cfg.proto_max_lmt.append(float(proto_layer))
    
    def execute(self) -> tuple:
        """
        优化算法执行函数
        约定返回内容数组：
        1. 增加时间
        2. 优化后最后一个包的结束时间
        3. 最佳 Unit
        4. 最佳 Unit 的评价结果
        5. 最佳 Unit 优化历史（距离记录）
        """
        pass

if __name__ == "__main__":
    from scapy.utils import rdpcap
    with open("test.pcap", "rb") as f:
        pkt_list = rdpcap(f)

    alg = NetAlg(pkt_list, pkt_list[-1].time)

    for name, value in cfg.__dict__.items():
        print(name, value)
    print()

    for name, value in alg.__dict__.items():
        print(name, value)
