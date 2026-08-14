"""
向量基础模块包

有以下功能：
1. 基础向量实现：从流量到向量，从向量到流量的双向映射及其设置（Unit + cfg）
2. 算法基础类：基于向量的优化算法，基础类实现了一些工具以及接口
3. 评估器类：评估器类是用于评价一条向量有效性的函数，封装一个特征提取器作为算法的有效性参考
"""

from .config import cfg
from .vector import Unit
from .algorithm import NetAlg
from .evaluator import Evaluator
from .examinator import Examinator, OLExaminator
from .logger import logger

__all__ = ["cfg",
           "Unit",
           "NetAlg",
           "Evaluator",
           "Examinator", "OLExaminator",
           "logger",
           ]
