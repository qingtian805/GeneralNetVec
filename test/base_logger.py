import sys, os
sys.path.append(f"{os.path.abspath(".")}")
from net_vec import NetAlg, Evaluator, log

class TestAlg(NetAlg):
    def __init__(self):
        pass
    @log.iteration_logger
    def update(self):
        self.glob_best_x = 1
        self.glob_best_x_dis = 0.5
        self.glob_best_x_index = 0

class TestEval(Evaluator):
    def __init__(self):
        pass

    @log.evaluate_logger
    def evaluate(self, x):
        self.feature = [1,2]
        self.all_feature = [1,2,3]
        return 1

test_eval = TestEval()
test_algo = TestAlg()

log.set_algorithm(test_algo)
log.set_evaluator(test_eval)

test_eval.evaluate(1)
for key, value in log.__dict__.items():
    print(f"{key}:\t{value}")

test_algo.update()
for key, value in log.__dict__.items():
    print(f"{key}:\t{value}")
