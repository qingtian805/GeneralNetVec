import numpy as np

from copy import deepcopy
from net_vec.config import cfg
from net_vec.algorithum import NetAlg
from net_vec.evaluator import Evaluator

class Logger:
    def __init__(self):
        """
        过程记录类，会在修饰器触发后从算法以及评价器的 API 中提取数据
        （具体API见修饰器，请在实现算法时实现对这些 API 的修改）

        初始化后，请使用 set_evaluator 和 set_algoritum 函数分别传入正在使用的
        算法实例和评价器实例。
        """
        self.best_x_feature: list | None = None
        """ 指向当前最佳样本的恶意包特征 """
        self.best_x_all_feature: list | None = None
        """ 指向当前最佳样本的所有包特征 """
        self.best_x_dis_hist = []
        """ 记录最佳样本距离模仿特征的 L2 距离历史 """
        self.avg_dis_hist = []
        """ 记录全部样本的平均 L2 距离历史 """

        self.feature_list = []
        self.all_feature_list = []
        self.dis_sum = 0.

        self.eval_instance = None
        self.algo_instance = None

    def set_evaluator(self, evaluator: Evaluator):
        """ 设置被记录的评价器 """
        self.eval_instance = evaluator

    def set_algorithum(self, algorithum: NetAlg):
        """ 设置被记录的算法 """
        self.algo_instance = algorithum

    def evaluate_logger(self, eval_func):
        """
        用于修饰样本评价函数，修饰器做以下事情：
        1. 记录评价函数输出的历史之和用于计算优化过程中的距离均值
        2. 记录来自评价器的 feature 和 all_feature 对象
        """
        def wapper(*args, **kwargs):
            dis = eval_func(*args, **kwargs)

            self.dis_sum += dis
            self.feature_list.append(self.eval_instance.feature)
            self.all_feature_list.append(self.eval_instance.all_feature)

            return dis
        return wapper


    def iteration_logger(self, iteration_func):
        """
        用于修饰算法的每轮更新函数，修饰器做以下事情：
        1. 记录当前最优解的评价结果（distance）历史
        2. 利用索引号(index)，与特征历史对应，记录当前最优解的特征
        """
        def wapper(*args, **kwargs):
            res = iteration_func(*args, **kwargs)

            best_x_index = self.algo_instance.glob_best_x_index
            self.best_x_dis_hist.append(self.algo_instance.glob_best_x_dis)
            self.avg_dis_hist.append(self.dis_sum / len(self.feature_list))
            self.best_x_feature = self.feature_list[best_x_index]
            self.best_x_all_feature = self.all_feature_list[best_x_index]

            self.dis_sum = 0.
            self.feature_list.clear()
            self.all_feature_list.clear()

            return res
        return wapper

    def get_log(self):
        """
        返回列表：
        1. 特征
        2. 全部特征
        3. 距离历史
        4. 平均距离历史
        """

        return (
            self.best_x_feature,
            self.best_x_all_feature,
            deepcopy(self.best_x_dis_hist),
            deepcopy(self.avg_dis_hist)
        )

    def clear(self):
        """ 清理日志类，由变异器在变异每轮结束后调用 """
        self.best_x_feature = None
        self.best_x_all_feature = None
        self.best_x_dis_hist.clear()
        self.avg_dis_hist.clear()


logger = Logger()
