from copy import deepcopy
import numpy as np
from scapy.utils import EDecimal
from scapy.packet import Packet, Raw

from .config import cfg
from .vector import Unit
from .evaluator import Evaluator

class NetAlg:
    def __init__(
            self,
            max_cft_pkt: int = 1,
            max_cft_pkt_prob: float = 0.01,
            max_time_extend: float = 6.,
            min_time_extend: float = 3.,
            fence_time_divider: int = 10000,
            cft_time_divider: int = 1000,
            proto_min_lmt: float = 1.,
            data_max_lmt: list = [np.nan, 1500., 1480., 1460.],
            data_min_lmt: float = 0.,
            pkt_list: list[Packet] = None, 
            last_end_time: EDecimal = None,
        ):
        r"""
        netAlg 网络算法基类，将自动进行一些有关 Unit 类的设置

        在具体的算法实现中，此处应该包含一些超参数的记录与设置，但不应该包含算法初始化步骤，
        算法的具体初始化步骤应当合并到算法执行函数中

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

        self.evaluator = None # type: Evaluator
        self.glob_best_x = None # type: Unit
        self.glob_best_x_index = -1 # used by logger to record feature
        self.glob_best_x_dis = np.inf

        if pkt_list is not None:
            self.set_pkt_list(pkt_list, last_end_time)

    def _update_glob_best_x(self, new_best_x: Unit, distance: float, index: int):
        self.glob_best_x = deepcopy(new_best_x)
        self.glob_best_x_dis = distance
        self.glob_best_x_index = index

    def set_pkt_list(
            self, 
            pkt_list: list[Packet], 
            last_end_time: EDecimal = None
            ):
        """
        设置原始包列表和最后一个包的结束时间, 以便算法使用
        """
        cfg.pkt_list = pkt_list
        if last_end_time is None:
            cfg.last_end_time = pkt_list[0].time
        else:
            cfg.last_end_time = last_end_time

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

    def _iteration(self):
        """
        优化算法单次迭代函数，本函数是算法内部函数，设计在这里方便logger记录
        迭代历史
        """
        pass

    def execute(self):
        """
        优化算法执行函数，应当包含数据结构初始化在内的算法一切步骤
        约定返回内容数组：
        1. 增加时间
        2. 优化后最后一个包的结束时间
        3. 最佳 Unit
        """
        return np.nan, np.nan, Unit()
