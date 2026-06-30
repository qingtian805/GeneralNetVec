from scapy.utils import EDecimal
from scapy.packet import Packet
import numpy as np

class Conf:
    def __init__(self):
        # Algorithm related config
        self.pkt_list: list[Packet] | None  = None
        """ 被处理的恶意包列表，用于构建向量与重构流量 """
        self.last_end_time: EDecimal | None = None
        """ 上一条流结束的时间 """
        self.max_cft_pkt: int          = 1
        """ 每个原始包对应构建包的最大数量(l_c) """
        self.max_cft_pkt_prob: float   = 0.01
        """ 在 0-1 之间的概率,限制一个slot填入构造包的最大概率,相当于 max_cft_pkt 的最大乘数 """
        self.max_time_extend: float    = 6.
        """ 新流量相较于原始的时间倍数(l_t) """
        self.min_time_extend: float    = 3.
        """ 新流量相较于原始的时间倍数(l_t) """
        self.fence_time_divider: int   = 10000
        """ 用于计算原始包之间的最小时间间隔,代表最大允许时间间隔中存在多少个可用时间位置 """
        self.cft_time_divider: int     = 1000
        """ 用于计算构建包与前个包之间的最小时间间隔,代表在构建包与前个包时间间隔中存在多少个可用时间位置 """
        self.proto_min_lmt: float      = 1.
        """ 用于限制构建包最小使用的协议层数 """
        self.data_max_lmt: list[float] = [np.nan, 1500., 1480., 1460.]
        """ 用于限制构建包的 mtu, list 的序号对应协议层数, 如序号 2 限制 2 层包的 mtu """
        self.data_min_lmt: float       = 0.
        """ 用于限制构建包最小的 mtu, 限制构建包, 无论协议层数 """

        self.pkt_num: int | None               = None
        """ [运行时参数] 记录恶意流量的包数量 """
        self.proto_max_lmt: list[float] | None = None
        """ [运行时参数] 用于限制构建包最大使用的协议层数 """

        # Evaluator related config
        self.mimic_set: np.ndarray | None = None
        """ 被模仿的流量特征 """

cfg = Conf()
""" 在算法多个模块之间共享的参数设置 """
