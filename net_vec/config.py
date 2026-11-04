from scapy.utils import EDecimal
from scapy.packet import Packet, Raw
import numpy as np

class Conf:
    def _cal_normalizer(self):
        minimum = []
        maximum = []

        for i in range(self._pkt_num):
            for _ in range(cfg.max_cft_pkt):
                minimum += [self.itv_min_lmt, self.proto_min_lmt, self.data_min_lmt]
                maximum += [self.itv_max_lmt, self._proto_max_lmt[i], self.data_max_lmt]

            minimum += [self.itv_min_lmt, 0]
            maximum += [self.itv_max_lmt, self.max_cft_pkt]


        self._max_vec = np.array(maximum)
        self._min_vec = np.array(minimum)

    def set_pkt_list(
            self,
            pkt_list: list[Packet],
            last_end_time: EDecimal = None,):
        """
        设置原始包列表和最后一个包的结束时间, 以便分组处理
        属于 Manipulater API

        :param pkt_list: 使用的原始包列表
        :param last_end_time: 上一条流结束的时间。可以为 None, 此时将使用包列表的首个包的时间,
            代表这是流捕获的的首个原始包列表
        """
        self._pkt_list = pkt_list
        if last_end_time is None:
            self._last_end_time = pkt_list[0].time
        else:
            self._last_end_time = last_end_time

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

        self._cal_normalizer()

    def set_config(
            self,
            itv_max_lmt: float = None,
            itv_min_lmt: float = None,
            max_cft_pkt: int = None,
            max_cft_pkt_prob: float = None,
            max_time_extend: float = None,
            min_time_extend: float = None,
            proto_min_lmt: float = None,
            data_max_lmt: list = None,
            data_min_lmt: float = None,
            pkt_list: list[Packet] = None,
            last_end_time: EDecimal = None,):

        r"""参数设置函数：默认所有数值为 None，为 None 的数值不会修改目前参数

        :param itv_max_lmt: 流量中最大包间隔
        :param itv_min_lmt: 流量中最小包间隔
        :param max_cft_pkt: 每个原始包对应构建包的最大数量(l_c)
        :param max_cft_pkt_prob: 在 0-1 之间的概率,限制一个slot填入构造包的最大概率,相当于 max_cft_pkt 的最大乘数
        :param max_time_extend: 新流量相较于原始的时间倍数(l_t)
        :param min_time_extend: 新流量相较于原始的时间倍数(l_t)
        :param proto_min_lmt: 用于限制构建包最小使用的协议层数
        :param data_max_lmt: 用于限制构建包最大包长度，一般填写目标链路 mtu
        :param data_min_lmt: 用于限制构建包最小包长度, 限制构建包, 无论协议层数
        """
        normalizer_modified = False

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
            normalizer_modified = True
        if data_max_lmt is not None:
            self.data_max_lmt = data_max_lmt
            normalizer_modified = True
        if data_min_lmt is not None:
            self.data_min_lmt = data_min_lmt
            normalizer_modified = True
        if itv_max_lmt is not None:
            self.itv_max_lmt = itv_max_lmt
            normalizer_modified = True
        if itv_min_lmt is not None:
            self.itv_min_lmt = itv_min_lmt
            normalizer_modified = True

        if pkt_list is not None:
            self.set_pkt_list(pkt_list, last_end_time)

        if normalizer_modified:
            self._max_vec, self._min_vec = self._cal_normalizer()

    def __init__(self):
        """向量设置类，负责完成 nev_vec 相关基础数据结构的设置（主要是完成对于 流量-向量 可逆映射的设置）

        类中包含两类变量：
        * 开头带下划线的变量：这类变量是运行时变量，用于存储模块在运行过程中的动态配置
        * 一般变量：这类变量是正常的设置变量

        严格来讲，带有单个下划线开头的变量应当属于 protected, 但实际上这些变量在项目中的访问相当普遍
        """

        self.max_cft_pkt: int           = 1
        """ 每个原始包对应构建包的最大数量(l_c)   \n 默认值 1 """
        self.max_cft_pkt_prob: float    = 0.01
        """ 概率值, 限制一个 slot 填入构造包的最大概率, 相当于 max_cft_pkt 的最大乘数   \n 默认值 0.01 """
        self.max_time_extend: float     = 6.
        """ 新流量相较于原始的时间倍数(l_t)   \n 默认值 6.0 """
        self.min_time_extend: float     = 3.
        """ 新流量相较于原始的时间倍数(l_t)   \n 默认值 3.0 """
        self.itv_min_lmt: float         = 0.
        """ 流量包时间间隔最小限制   \n 默认值 0 """
        self.itv_max_lmt: float         = 3.
        """ 流量包时间间隔最大限制，填写允许超时的时间   \n 默认值 60. """
        self.proto_min_lmt: float       = 1.0
        """ 用于限制构建包最小使用的协议层数   \n 默认值 1.0"""
        self.data_max_lmt: list[float]  = 1500.
        """ 用于限制构建包的最大包长度, 一般对应链路 mtu, 常见值 1500    \n 默认值 1500."""
        self.data_min_lmt: float        = 0.
        """ 用于限制构建包的最小包长度, 限制构建包, 无论协议层数   \n 默认值 0.0"""

        self._pkt_list: list[Packet] | None  = None
        """ 被处理的恶意包列表，用于构建向量与重构流量 """
        self._last_end_time: EDecimal | None = None
        """ 上一条流结束的时间 """
        self._pkt_num: int | None               = None
        """ 记录恶意流量的包数量 """
        self._prqoto_max_lmt: list[float] | None = None
        """ 用于限制构建包最大使用的协议层数 """

        self._max_vec: np.ndarray = None
        """ 最大-最小正则化的最大值 """
        self._min_vec: np.ndarray = None
        """ 最大-最小正则化的最小值 """

    def get_paramters(self) -> dict:
        """ 返回当前的向量设置，不包含运行时参数 """
        res = self.__dict__
        for key in list(res.keys()):
            if key[0] == '_':
                res.pop(key)

        return res

cfg: Conf = Conf()
""" 设置指针，保证设置实例的单例在算法多个模块之间共享的参数设置 """
