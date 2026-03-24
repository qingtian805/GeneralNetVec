"""
Kitsune 测试器
"""

import os, sys
sys.path.append(os.path.join(os.path.split(__file__)[0], "Kitsune"))
from .kitsune import KitsuneExam

__all__ = ["KitsuneExam"]
