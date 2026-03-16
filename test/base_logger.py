import sys, os
sys.path.append(f"{os.path.abspath(".")}")
from net_vec.algorithum import NetAlg
from net_vec.evaluator import Evaluator
from net_vec.logger import logger

class TestAlg(NetAlg):
    def __init__(self):
        pass
    
    @logger.update_logger
    def update(self):
        self.glob_best_x = 1
        self.glob_best_x_dis = 0.5
        self.glob_best_x_index = 0

class TestEval(Evaluator):
    def __init__(self):
        pass

    @logger.evaluate_logger
    def evaluate(self, x):
        self.feature = [1,2]
        self.all_feature = [1,2,3]

test_eval = TestEval()
test_algo = TestAlg()

logger.set_algorithum(test_algo)
logger.set_evaluator(test_eval)

test_eval.evaluate(1)
for key, value in logger.__dict__.items():
    print(f"{key}:\t{value}")

test_algo.update()
for key, value in logger.__dict__.items():
    print(f"{key}:\t{value}")
