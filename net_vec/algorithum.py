from copy import deepcopy
import numpy as np

from .vector import Unit
from .evaluator import Evaluator

class NetAlg:
    r"""
    netAlg 网络算法基类，提供一些通用的工具：

    * `evaluator` 为通用评估器，会返回一条

    实现需要以下内容：

    * 构造函数 `__init__` 完成算法参数的设置，调用基类 __init__ 完成评估器设置
    * 实现获取算法参数的函数 `get_paramters`
    * 实现一个 `_iteration` 内部迭代函数，使用 logger.iteration_logger 修饰
    * 实现一个获取当前最佳向量的函数 `get_best_x`，函数应该返回的距离、序号
    """
    def __init__(
            self,
            evaluator: Evaluator | None = None,
        ):
        self.evaluator = evaluator

    def set_evaluator(self, evaluator: Evaluator):
        r""" 设置算法使用的评估器 """
        self.evaluator = evaluator

    def get_paramters(self) -> dict:
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

    def get_best_x():
        """
        [Logger API]
        算法应该实现一个能够获取自身当前最好数据的有关内容，包含

        * 最好向量
        * 相关距离
        * 序号
        """
        pass

    def execute(self) -> Unit:
        """
        优化算法执行函数，应当包含**数据结构初始化**在内的算法一切步骤
        函数应返回最好的向量
        """
        pass
