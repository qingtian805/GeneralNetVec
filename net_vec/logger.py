import numpy as np

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
        self.best_x_feature = None
        self.best_x_all_feature = None
        self.best_x_dis_hist = []
        self.avg_dis_hist = []

        self.feature_list = []
        self.all_feature_list = []
        self.dis_sum = 0.

        self.eval_instance = None
        self.algo_instance = None

    def set_evaluator(self, evaluator: Evaluator):
        self.eval_instance = evaluator

    def set_algorithum(self, algorithum: NetAlg):
        self.algo_instance = algorithum

    def evaluate_logger(self, eval_func):
        """
        用于修饰评价函数，修饰器做以下事情：
        1. 记录评价函数输出的历史到
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
        
logger = Logger()
