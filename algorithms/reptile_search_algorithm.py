from copy import deepcopy
import numpy as np
from net_vec import NetAlg, Unit, log

EPSILON = 2.2204e-16

class RSA(NetAlg):
    def __init__(
            self,
            alpha: float = 0.1,
            beta: float = 0.1,
            iter: int = 4,
            swarm: int = 6,
            *args,
            seed = None,
            seed1 = None,
            seed2 = None,
            seed3 = None,
            **kwargs):

        """爬行动物搜索算法

        :param alpha: 参数
        :param beta: 参数
        :param iter: 迭代次数，最好是 4 的倍数
        :param swarm: 算法使用的最优解个数
        :param seed: 随机数生成器的种子
        :param seed1: 随机数生成器的种子
        :param seed2: 随机数生成器的种子
        :param seed3: 随机数生成器的种子
        """

        super().__init__(*args, **kwargs)

        """当前全局最优"""
        self.alpha = alpha
        self.beta = beta
        self.iter = iter
        self.swarm = swarm

        self.rng  = np.random.default_rng(seed)
        self.rng1 = np.random.default_rng(seed1)
        self.rng2 = np.random.default_rng(seed2)
        self.rng3 = np.random.default_rng(seed3)

    def _percentage_difference(self, x: Unit):
        # not timing (UB-LB) because it is 1 always
        return (self.alpha
               + (x - x.data.mean())
               / (self.bestx + EPSILON))

    def _eta(self, x: Unit):
        """ η """
        return (self.bestx
                * self._percentage_difference(x))

    def _reduce(self):
        return ((self.bestx
                - self.bestx_list[self.rng2.integers(self.swarm)])
                / (self.bestx + EPSILON))

    def _evolutionary_sense(self, current_iter: int):
        return (2 * self.rng3.uniform(-1, 1)
                * (1 - current_iter / self.iter))

    def _high_walking(self):
        for i in range(self.swarm):
            self.bestx_list[i] = (self.bestx
                                  - self._eta(self.bestx_list[i])
                                  * self.beta
                                  - self._reduce()
                                  * self.rng.random())
            self.bestx_list[i].restrict()

    def _belly_walking(self, t):
        for i in range(self.swarm):
            self.bestx_list[i] = (self.bestx
                                  * self.bestx_list[self.rng1.integers(self.swarm)]
                                  * self._evolutionary_sense(t)
                                  * self.rng.random())
            self.bestx_list[i].restrict()

    def _coordination(self):
        for i in range(self.swarm):
            self.bestx_list[i] = (self.bestx
                                  * self._percentage_difference(self.bestx_list[i])
                                  * self.rng.random())
            self.bestx_list[i].restrict()

    def _cooperation(self):
        for i in range(self.swarm):
            self.bestx_list[i] = (self.bestx
                                  - self._eta(self.bestx_list[i])
                                  * EPSILON
                                  - self._reduce()
                                  * self.rng.random())
            self.bestx_list[i].restrict()

    @log.iteration_logger
    def _iteration(self, t):
        # evaluation
        for i in range(self.swarm):
            dis = self.evaluator.evaluate(self.bestx_list[i])
            if dis < self.bestx_dis:
                self.bestx_dis = dis
                self.bestx_index = i
        self.bestx = deepcopy(self.bestx_list[self.bestx_index])

        # router
        if t < self.iter / 2:
            if t < self.iter / 4:
                self._high_walking()
            else:
                self._belly_walking(t)
        else:
            if t < self.iter * 3 / 4:
                self._coordination()
            else:
                self._cooperation()

    def execute(self):
        self.bestx: Unit = None
        self.bestx_dis = np.inf
        self.bestx_index = -1

        self.bestx_list: list[Unit] = [ Unit().initialize() for _ in range(self.swarm) ]

        for t in range(self.iter):
            self._iteration(t)

        return self.bestx

    def get_best_x(self):
        return self.bestx, self.bestx_dis, self.bestx_index
