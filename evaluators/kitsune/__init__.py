"""
Kitsune 评估器模块

该模块提供了基于 Kitsune 异常检测系统的网络流量评估器。
主要包含 KitsuneEval 类，用于评估网络数据包的特征与良性流量特征的相似度。
"""

import os, sys
sys.path.append(os.path.split(__file__)[0])
from .kitsune import KitsuneEval, KNnormalizer

__all__ = ['KitsuneEval', 'KNnormalizer']
