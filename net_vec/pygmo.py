import numpy as np
import pygmo as pg
from .vector import Unit
from .config import cfg
from .evaluator import Evaluator
from scapy.utils import EDecimal
from scapy.packet import Packet

mal_restrict: list | None = None
cft_restrict: list | None = None

restrict: list[list] = [[], []] # [[lower_bound], [upper_bound]]

def set_pkt_list(pkt_list: list[Packet], last_end_time: EDecimal = None):
    """
    针对 Pygmo2 库的 set_pkt_list 封装，在调用 cfg.set_pkt_list 后还进行以下工作：

    1. 完成用于 Pygmo2 库的上下限计算
    """
    global mal_restrict, cft_restrict, restrict

    cfg.set_pkt_list(pkt_list, last_end_time)

    max_mal_itv = (cfg.pkt_list[-1].time - cfg.last_end_time) * (cfg.max_time_extend + 1)
    mal_itv_lmt = max_mal_itv / cfg.fence_time_divider
    cft_itv_lmt = mal_itv_lmt / cfg.cft_time_divider

    for i in range(cfg._pkt_num):
        for _ in range(cfg.max_cft_pkt):
            restrict[0] += [cft_itv_lmt, cfg.proto_min_lmt, cfg.data_min_lmt]
            restrict[1] += [max_mal_itv, cfg._proto_max_lmt[i], cfg.data_max_lmt[round(cfg._proto_max_lmt[i])]]

        restrict[0] += [mal_itv_lmt, 0]
        restrict[1] += [max_mal_itv, cfg.max_cft_pkt]

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

def vec_to_pop(uls: list[Unit], prob: pg.problem) -> pg.population:
    """
    将 Unit 数据结构转换为用于 Pygmo2 的数据结构
    """
    pop = pg.population(prob, 0)

    for i in uls:
        pop.push_back(flatten(i))

    return pop

def pop_to_vec(pop: pg.population) -> list[Unit]:
    """
    将 Pygmo population 转换为 Unit 数据结构
    """
    x = pop.get_x()

    res = []
    for i in range(np.shape(x)[0]):
        res.append(deflatten(x[i]))

    return res

class generation_problem:
    def __init__(self, evaluator: Evaluator):
        """将流量优化问题定义转移到 Pygmo2 中
        """
        if cfg._pkt_num is None:
            print("Use warning: Please set pkt_list in config!")

        self.dims = cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)
        self.evaluator = evaluator

    def fitness(self, x):
        if x is None:
            return None

        u = deflatten(x)
        return [self.evaluator.evaluate(u)]

    def get_bounds(self):
        global restrict
        return restrict
