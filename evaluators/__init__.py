"""
评估器模块包

该包包含了各种网络流量评估器，用于评估网络数据包的特征。
"""

# 导入 kitsune 评估器
from .kitsune import KitsuneEval

__all__ = ['KitsuneEval']
