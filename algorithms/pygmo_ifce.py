from copy import deepcopy
import numpy as np
import pygmo as pg
from net_vec import NetAlg, cfg, Unit, Evaluator, log

class generation_problem:
    def __init__(self, evaluator: Evaluator):
        """将流量优化问题定义转移到 Pygmo2 中
        """
        if cfg._pkt_num is None:
            print("ERROR: Please set pkt_list in config before calling PYGMO!")
            exit(1)

        self.dims = cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)
        self.evaluator = evaluator

        self.restrict = [
                [0.] * self.dims,
                [1.] * self.dims
            ]

    def fitness(self, x: np.ndarray):
        if x is None:
            return None

        u = Unit()
        u.data[:] = x
        return [self.evaluator.evaluate(u)]

    def get_bounds(self):
        return self.restrict

class PygmoPort(NetAlg):
    """
    本算法是 net_vec 与 Pygmo 之间的接口，负责将 Pygmo 库移植为可用的算法
    """
    def __init__(
            self,
            algo,
            algo_param: dict,
            pop_size: int,
            *args,
            **kwargs):

        """
        :param algo: 用于构建 pg.algorithm, 相当于 `pg.algorithm(algo)`, 请参考 `list of algorithms` 部分
        :param algo_param: 算法使用的参数
        :param pop_size: 算法使用的染色体个数
        """
        super().__init__(*args, **kwargs)
        self.param = deepcopy(algo_param)

        # Force algorithm run once
        if algo_param.get("gen"):
            self.gen = algo_param["gen"]
            algo_param["gen"] = 1
        else:
            self.gen = 1

        self.algo = pg.algorithm(algo(**algo_param))
        """Pygmo 算法"""
        self.pop_size = pop_size

        self.prob = None
        """Pygmo 问题"""
        self.pop = None
        """Pygmo 人口(染色体集合)"""


    def get_paramters(self):
        param = self.param
        param["gen"] = self.gen
        return param

    def get_best_x(self):
        idx = self.pop.best_idx()

        return (self.pop.get_x()[idx], self.pop.get_f()[idx], idx)

    @log.iteration_logger
    def _iteration(self):
        self.pop = self.algo.evolve(self.pop)

    def execute(self):
        # 初始化染色体
        if self.prob is None:
            self.prob = pg.problem(generation_problem(self.evaluator))
        self.pop = pg.population(self.prob, size=self.pop_size)

        # 迭代过程
        for _ in range(self.gen):
            self._iteration()

        best_x = self.pop.get_x()[self.pop.best_idx()]
        # Prepare evaluator for next group
        best_x_unit = Unit()
        best_x_unit.data[:] = best_x
        best_x_unit.restrict()

        return best_x_unit
