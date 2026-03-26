"""
Kitsune 测试器
"""

import os, sys
sys.path.append(os.path.join(os.path.split(__file__)[0], "Kitsune"))
from .kitsune import KitsuneExam
from .kitsune_ol import OLKitsuneExam

__all__ = ["KitsuneExam", "OLKitsuneExam"]
