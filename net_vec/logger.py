import numpy as np

from net_vec.algorithum import NetAlg
from net_vec.evaluator import Evaluator

class Logger:
    def __init__(self):
        self.best_x_feature = None
        self.best_x_all_feature = None
        self.best_x_dis_hist = []
        self.avg_dis_hist = []

        self.feature_list = []
        self.all_feature_list = []
        self.dis_list = []

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
            res = eval_func(*args, **kwargs)

            self.feature_list.append(self.eval_instance.feature)
            self.all_feature_list.append(self.eval_instance.all_feature)
            
            return res
        return wapper
        

    def update_logger(self, update_func):
        """
        用于修饰算法的每轮更新函数，修饰器做以下事情：
        1. 记录当前最优解的评价结果（distance）历史
        2. 利用索引号(index)，与特征历史对应，记录当前最优解的特征
        """
        def wapper(*args, **kwargs):
            res = update_func(*args, **kwargs)
            
            best_x_index = self.algo_instance.glob_best_x_index
            self.best_x_dis_hist.append(self.algo_instance.glob_best_x_dis)
            self.best_x_feature = self.feature_list[best_x_index]
            self.best_x_all_feature = self.all_feature_list[best_x_index]
            self.feature_list.clear()
            self.all_feature_list.clear()

            return res
        return wapper
        
logger = Logger()
