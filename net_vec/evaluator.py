from scapy.plist import PacketList
import numpy as np

from .vector import Unit
from .config import cfg

class Evaluator:
    def __init__(
            self,
            mimic_set_file: str
        ):
        """
        :param mimic_set: 被模仿特征的正常流量特征文件 mimic(模仿、拟态)，应当是numpy保存的ndarray
        """
        self.cfg = cfg
        with open(mimic_set_file, "rb") as f:
            self.cfg.mimic_set = np.load(f)
        # logger API, 分别为不包含和包含构建包的流量特征列表
        self.feature = None # type: list
        self.all_feature = None # type: list

    def forward(self, grp_best_pkt_list: PacketList):
        """
        推进全局特征提取器进度。完成一组流量的优化后，使用本函数在本组最优的方向上推进特征提取工作
        :param grp_best_pkt_list 本组优化得到的最佳流量组
        """
        pass

    def evaluate(self, x: Unit):
        """
        评估函数，接受一个 Unit，并在内部完成评价，返回一个 float 数值作为评价结果
        函数会创建一个局部特征提取器，不会影响全局特征提取器，并计算与模仿集合的l2距离作为评价结果

        实现时请注意将提取特征存储到 feature 和 all_feature 中

        :param x: 需要评估的 Unit
        :return: 评价结果
        :rtype: float
        """
        return -1.
