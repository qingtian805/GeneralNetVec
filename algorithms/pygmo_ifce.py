from copy import deepcopy
import numpy as np
import pygmo as pg
from net_vec import NetAlg, cfg, Unit, Evaluator, log

def flatten(x: Unit) -> np.ndarray:
    dims = 2 + cfg.max_cft_pkt * 3
    res = np.zeros((dims * cfg._pkt_num))

    last_time = cfg.last_end_time
    for i in range(cfg._pkt_num):
        p = i * dims
        for j in range(cfg.max_cft_pkt):
            res[p + 3 * j: p + 3 * j + 3] = x.craft[i][j]

        res[p + 3 * cfg.max_cft_pkt : p + 3 * cfg.max_cft_pkt + 2] = [x.mal[i][0] - last_time, x.mal[i][1]]
        last_time = x.mal[i][0]

    return res

def deflatten(x: np.ndarray) -> Unit:
    if len(np.shape(x)) > 1:
        return None

    dims = 2 + cfg.max_cft_pkt * 3
    res = Unit()

    itv = cfg.last_end_time
    for i in range(cfg._pkt_num):
        p = i * dims
        for j in range(cfg.max_cft_pkt):
            res.craft[i][j] = x[p + j * 3: p + j * 3 + 3]

        res.mal[i] = [x[p + 3 * cfg.max_cft_pkt] + itv, x[p + 3 * cfg.max_cft_pkt + 1]]
        itv += x[p + 3 * cfg.max_cft_pkt]

    return res

class generation_problem:
    restrict: list[list] = [[], []] # [[lower_bound], [upper_bound]]

    def _cal_restriction_vector(self):
        self.restrict = [[], []] # [[lower_bound], [upper_bound]]

        max_mal_itv = (cfg.pkt_list[-1].time - cfg.last_end_time) * (cfg.max_time_extend + 1)
        mal_itv_lmt = max_mal_itv / cfg.fence_time_divider
        cft_itv_lmt = mal_itv_lmt / cfg.cft_time_divider

        for i in range(cfg._pkt_num):
            for _ in range(cfg.max_cft_pkt):
                self.restrict[0] += [cft_itv_lmt, cfg.proto_min_lmt, cfg.data_min_lmt]
                self.restrict[1] += [max_mal_itv, cfg._proto_max_lmt[i], cfg.data_max_lmt[round(cfg._proto_max_lmt[i])]]

            self.restrict[0] += [mal_itv_lmt, 0]
            self.restrict[1] += [max_mal_itv, cfg.max_cft_pkt]

    def __init__(self, evaluator: Evaluator):
        """将流量优化问题定义转移到 Pygmo2 中
        """
        if cfg._pkt_num is None:
            print("ERROR: Please set pkt_list in config before calling PYGMO!")
            exit(1)

        self.dims = cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)
        self.evaluator = evaluator

        self._cal_restriction_vector()

    def fitness(self, x):
        if x is None:
            return None

        u = deflatten(x)
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
            **kwargs
            ):
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
        uls = [Unit().initialize() for _ in range(self.pop_size)]
        prob = pg.problem(generation_problem(self.evaluator))
        self.pop = pg.population(prob, 0)
        for x in uls:
            x = flatten(x)
            self.pop.push_back(x)

        # 迭代过程
        for _ in range(self.gen):
            self._iteration()

        best_x = self.pop.get_x()[self.pop.best_idx()]
        # Prepare evaluator for next group
        best_x_unit = deflatten(best_x)

        return best_x_unit
