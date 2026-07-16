from scapy.utils import EDecimal
from scapy.packet import Packet
import numpy as np

class Conf:
    def set_pkt_list(
            self,
            pkt_list: list[Packet],
            last_end_time: EDecimal = None
            ):
        """
        设置原始包列表和最后一个包的结束时间, 以便分组处理
        属于 Manipulater API

        :param pkt_list: 使用的原始包列表
        :param last_end_time: 上一条流结束的时间。可以为 None, 此时将使用包列表的首个包的时间,
            代表这是流捕获的的首个原始包列表
        """
        self.pkt_list = pkt_list
        if last_end_time is None:
            self.last_end_time = pkt_list[0].time
        else:
            self.last_end_time = last_end_time

        self._pkt_num = len(pkt_list)
        self._proto_max_lmt = []
        for i in pkt_list:
            layers = i.layers()
            try:
                layers.remove(Raw)
            except ValueError:
                pass
            proto_layer = len(layers)

            if proto_layer > 3:
                proto_layer = 3

            self._proto_max_lmt.append(float(proto_layer))

    def set_config(
            self,
            max_cft_pkt: int = None,
            max_cft_pkt_prob: float = None,
            max_time_extend: float = None,
            min_time_extend: float = None,
            fence_time_divider: int = None,
            cft_time_divider: int = None,
            proto_min_lmt: float = None,
            data_max_lmt: list = None,
            data_min_lmt: float = None,
            pkt_list: list[Packet] = None,
            last_end_time: EDecimal = None,
        ):
        r"""参数设置函数
        默认所有数值为 None，为 None 的数值不会修改目前参数

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
        if max_cft_pkt is not None:
            self.max_cft_pkt = max_cft_pkt
        if max_cft_pkt_prob is not None:
            self.max_cft_pkt_prob = max_cft_pkt_prob
        if max_time_extend is not None:
            self.max_time_extend = max_time_extend
        if min_time_extend is not None:
            self.min_time_extend = min_time_extend

        if proto_min_lmt is not None:
            self.proto_min_lmt = proto_min_lmt
        if data_max_lmt is not None:
            self.data_max_lmt = data_max_lmt
        if data_min_lmt is not None:
            self.data_min_lmt = data_min_lmt

        # 用于计算原始包之间的最小时间间隔，D 代表最大允许时间间隔中存在多少个可用时间位置
        if fence_time_divider is not None:
            self.fence_time_divider = fence_time_divider
        # 用于计算构建包与前个包之间的最小时间间隔，DD 代表在构建包与前个包时间间隔中存在多少个可用时间位置
        if cft_time_divider is not None:
            self.cft_time_divider   = cft_time_divider

        if pkt_list is not None:
            self.set_pkt_list(pkt_list, last_end_time)

    def __init__(self):
        """向量设置类，负责完成 nev_vec 相关基础数据结构的设置（主要是完成对于 流量-向量 可逆映射的设置）

        """
        self.pkt_list: list[Packet] | None  = None
        """ 被处理的恶意包列表，用于构建向量与重构流量   \n 默认值：None """
        self.last_end_time: EDecimal | None = None
        """ 上一条流结束的时间   \n 默认值：None"""
        self.max_cft_pkt: int          = 1
        """ 每个原始包对应构建包的最大数量(l_c)   \n 默认值：1 """
        self.max_cft_pkt_prob: float   = 0.01
        """ 在 0-1 之间的概率,限制一个slot填入构造包的最大概率,相当于 max_cft_pkt 的最大乘数   \n 默认值：0.01 """
        self.max_time_extend: float    = 6.
        """ 新流量相较于原始的时间倍数(l_t)   \n 默认值 6.0 """
        self.min_time_extend: float    = 3.
        """ 新流量相较于原始的时间倍数(l_t)   \n 默认值 3.0 """
        self.fence_time_divider: int   = 10000
        """ 用于计算原始包之间的最小时间间隔,代表最大允许时间间隔中存在多少个可用时间位置   \n 默认值：10000 """
        self.cft_time_divider: int     = 1000
        """ 用于计算构建包与前个包之间的最小时间间隔,代表在构建包与前个包时间间隔中存在多少个可用时间位置   \n 默认值 1000 """
        self.proto_min_lmt: float      = 1.0
        """ 用于限制构建包最小使用的协议层数   \n 默认值：1.0"""
        self.data_max_lmt: list[float] = [np.nan, 1500., 1480., 1460.]
        """ 用于限制构建包的 mtu, list 的序号对应协议层数, 如序号 2 限制 2 层包的 mtu    \n 默认值：[np.nan, 1500., 1480., 1460.]"""
        self.data_min_lmt: float       = 0.
        """ 用于限制构建包最小的 mtu, 限制构建包, 无论协议层数   \n 默认值 0.0"""

        self._pkt_num: int | None               = None
        """ [运行时参数] 记录恶意流量的包数量 """
        self._proto_max_lmt: list[float] | None = None
        """ [运行时参数] 用于限制构建包最大使用的协议层数 """

cfg: Conf = Conf()
""" 设置指针，保证设置实例的单例在算法多个模块之间共享的参数设置 """
