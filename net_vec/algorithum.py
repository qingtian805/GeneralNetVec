from copy import deepcopy
import numpy as np

from .vector import Unit
from .evaluator import Evaluator

class NetAlg:
    def __init__(
            self,
            evaluator: Evaluator | None = None,
        ):
        r"""
        netAlg 网络算法基类，请在使用前完成对基础数据结构的设置

        在具体的算法实现中，此处应该包含一些超参数的记录与设置，但不应该包含算法初始化步骤，
        算法的具体初始化步骤应当合并到算法执行函数 excute 中，并实现一个每轮迭代函数，
        """
        self.evaluator = evaluator

        self.glob_best_x: Unit = None
        self.glob_best_x_dis: float = np.inf

        # Logger API
        self.glob_best_x_index: int = -1

    def set_evaluator(self, evaluator: Evaluator):
        r""" 设置算法使用的评估器 """
        self.evaluator = evaluator

    def _update_glob_best_x(self, new_best_x: Unit, distance: float, index: int):
        """ [工具函数] 更新全局最优，深复制，保证全局最优结果不被后续更新 """
        self.glob_best_x = deepcopy(new_best_x)
        self.glob_best_x_dis = distance
        self.glob_best_x_index = index

    def _reset_glob_best_x(self):
        """ [工具函数] 重置全局最优为空，同时更新结果、距离、序号 """
        self.glob_best_x = None
        self.glob_best_x_dis = np.inf
        self.glob_best_x_index = -1

    def get_paramter(self) -> dict:
        """
        通过本函数返回算法的参数
        """
        pass

    def _iteration(self):
        """
        算法实现中应该实现一个轮函数，功能为算法单轮迭代的步骤实现
        这个函数应该使用 Logger.iteration_logger 修饰
        """
        pass

    def execute(self) -> tuple[float, float, Unit]:
        """
        优化算法执行函数，应当包含**数据结构初始化**在内的算法一切步骤.

        约定返回内容数组：
        1. 增加时间
        2. 优化后最后一个包的结束时间
        3. 最佳 Unit
        """
        pass
