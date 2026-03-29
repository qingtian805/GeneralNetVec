import numpy as np
import pickle as pkl
from typing import Iterable
from scapy.utils import rdpcap
from scapy.all import PacketList

from .AfterImageExtractor.FEKitsune import Kitsune
from .AfterImageExtractor.KitsuneTools import *

from net_vec.evaluator import Evaluator
from net_vec.vector import Unit
from net_vec.logger import logger

def flatten(item:Iterable, ignore_types=(str, bytes)):
    res = []
    for x in item:
        if isinstance(x, Iterable) and not isinstance(x, ignore_types):
            res += flatten(x)
        else:
            res.append(x)

    return res

class KNnormalizer:
    def __init__(self, model_save_path: str):
        with open(model_save_path, 'rb') as f:
            # FM 是在 Kitsune 中的 Feature Mapper
            self.FM = pkl.load(f)

        self.norm_max = []
        self.norm_min = []
        for i in range(len(self.FM)):
            self.norm_max.append(np.full(len(self.FM[i]), -np.inf)) # type: list[np.ndarray]
            self.norm_min.append(np.full(len(self.FM[i]),  np.inf)) # type: list[np.ndarray]

    def fit_transform(self, X):
        """对X中的数据执行最大-最小正则化(0-1 Normalize), 同时初始化自身最大最小值

        :param X: 说明
        :type X:
        :return: 说明
        :rtype: NDArray
        """
        train_Feature = []
        X = np.array(X)
        for i in range(len(X)):
            train_feature = []
            for j in range(len(self.FM)):
                x = X[i][self.FM[j]]
                # update norms
                self.norm_max[j][x > self.norm_max[j]] = x[x > self.norm_max[j]]
                self.norm_min[j][x < self.norm_min[j]] = x[x < self.norm_min[j]]

                # 0-1 normalize
                x = (x - self.norm_min[j]) / (
                    self.norm_max[j] - self.norm_min[j] + 0.0000000000000001)

                train_feature = np.concatenate((train_feature, x))

            train_Feature.append(train_feature)

        for i in range(len(self.FM)):
            self.norm_max[i] = self.norm_max[i].tolist()
            self.norm_min[i] = self.norm_min[i].tolist()

        self.norm_max = np.array(flatten(self.norm_max))
        self.norm_min = np.array(flatten(self.norm_min))
        self.FM = np.array(flatten(self.FM), dtype=np.int8)

        return np.array(train_Feature)

    def transform(self, X):
        """transform 对X中的数据执行最大-最小正则化(0-1 Normalize)

        :param X: 说明
        :type X:
        :return: 说明
        :rtype: Any"""
        X = np.array(X)
        # 0-1 normalize
        X[:, self.FM] = (X[:, self.FM] - self.norm_min) / (
            self.norm_max - self.norm_min + 0.0000000000000001)

        return X

class KitsuneEval(Evaluator):
    def __init__(
            self,
            model_save_path: str,
            feature_path: str,
            fm_grace: int,
            ad_grace: int,
            mimic_set: np.ndarray,
            init_pcap_in: str = None
            ):

        """
        本类使用 AfterImage 特征提取器的特征作为评价指标。

        AfterImage 特征提取器是 Kitsune NIDS 的一部分，为了理解方便，命名为 Kitsune 评价器

        :param model_save_path: Kitsune 模型存储的路径，需要其中包含 Feature Mapper.(附加说明，这个文件一般包含四个内容)：
                                1. Feature Mapper 参数
                                2. 聚合层参数（多个小AE）
                                3. 输出层参数（大AE）
                                4. RMSE 最大值
        :param feature_path: 训练 Kitusne 的良性流量包，用于模拟在 Kitsune 运行过程中最大最小值的变化
        :param fm_grace: 训练特征提取器的包数量，用于模拟在 Kitsune 运行过程中最大最小值的变化
        :param ad_grace: 训练入侵检测其的包数量，用于模拟在 Kitsune 运行过程中最大最小值的变化
        :param mimic_set: 被模拟的良性流量特征
        :param init_pcap_in:
        """

        super().__init__(mimic_set)

        self.normalizer = KNnormalizer(model_save_path)
        train_feat = np.load(feature_path)
        self.normalizer.fit_transform(train_feat[fm_grace:ad_grace])

        if init_pcap_in is None:
            self.global_FE = Kitsune(PacketList(), np.inf)
        else:
            self.global_FE = Kitsune(rdpcap(init_pcap_in), np.inf)
            RunFE(self.global_FE)

    @logger.evaluate_logger
    def evaluate(self, x: Unit):
        """
        距离估计函数，计算当前特征与良性流量特征（全部）的 L2 距离(最大最小正则化后)

        :param mimic_set: 模仿集合，根据代码来看是已经经过最大最小标准化的流量 Kitsune feature
        :type mimic_set: np.array
        :return: 说明
        :rtype: Any
        """

        pkt_list = x.rebuild()

        mal_pos = []
        cft_num = 0

        for i in range(self.cfg.pkt_num):
            cft_num += int(round(x.mal[i][1]))
            mal_pos.append(i + cft_num)

        # Rollback flag is designed to restore status in low level(in order to be fast)
        # In detail: it will run rollback() when first time running proc_next_packet() in Kitsune
        # and backup() will be called, which will restore status stored in backup1 and backup2
        local_FE = Kitsune(pkt_list, np.inf, True)
        local_FE.FE.nstat = safelyCopyNstat(self.global_FE.FE.nstat, True)
        feature, all_feature = RunFE(local_FE, origin_pos=mal_pos)

        feature = np.asarray(feature)
        # 将皮尔森系数设为 0？
        feature[:, 33:50:4] = 0.
        feature[:, 83:100:4] = 0.

        norm_feature = self.normalizer.transform(feature)

        # 计算每个特征与对应目标特征的 l2 距离（范数），取最小值作为评价指标
        dis = 0
        for i in range(self.cfg.pkt_num):
            dis += min(np.linalg.norm(norm_feature[i] - self.cfg.mimic_set,
                                     axis=1))

        return dis

    def forward(self, best_pkt_list: PacketList):
        """
        令 Feature Extractor 在 best_pkt_list 上运行，过程不返回结果
        一般用于准备进行下一组评价
        """
        # Prepare for next evaluate
        nstat = self.global_FE.FE.nstat
        self.global_FE = Kitsune(best_pkt_list, np.inf, False)
        self.global_FE.FE.nstat = safelyCopyNstat(nstat, False)
        RunFE(self.global_FE)
