
import numpy as np
from net_vec import NetAlg, Unit, log

EPSILON = 1e-8

class RSA(NetAlg):

    def __init__(
            self,
            alpha: float = 0.1,
            beta: float = 0.1,
            iter: int = 3,
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
        :param eta:
        :param iter: 迭代次数，最好是 4 的倍数
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
        return (self.alpha
               + (x - x.data.mean())
               / (self.bestx + EPSILON))

    def _eta(self, x: Unit):
        """ η """
        return (self.bestx
                * self._percentage_difference(x))

    def _reduce(self, x: Unit):
        return ((self.bestx
                - self.bestx_list[self.rng2.integers(self.swarm)])
                / (self.bestx) + EPSILON)

    def _evolutionary_sense(self, current_iter: int):
        return (2 * self.rng3.uniform(-1, 1)
                * (1 - current_iter / self.iter))

    def get_best_x(self):
        return self.bestx, self.bestx_dis, self.bestx_index

    @log.iteration_logger()
    def _iteration(self, t):
        for i in range(self.swarm):
            if t < self.iter / 2:
                if t < self.iter / 4:
                    self.bestx_list[i] = (self.bestx
                                          * -self._eta(self.bestx_list[i])
                                          * self.beta
                                          - self._reduce(self.bestx_list[i])
                                          * self.rng.random())
                else:
                    self.bestx_list[i] = (self.bestx
                                          * self.bestx_list[self.rng1.integers(self.swarm)]
                                          * self._evolutionary_sense(t)
                                          * self.rng.random())
            else:
                if t < self.iter * 3 / 4:
                    self.bestx_list[i] = (self.bestx
                                          * self._percentage_difference(self.bestx_list[i])
                                          * self.rng.random())
                else:
                    self.bestx_list[i] = (self.bestx
                                          - self._eta(self.bestx_list[i])
                                          * EPSILON
                                          - self._reduce(self.bestx_list[i])
                                          * self.rng.random())

        for i in range(len(self.bestx_list)):
            score = self.evaluator.evaluate(self.bestx_list[i])
            if score < self.bestx_dis:
                self.bestx_index = i

        self.bestx = self.bestx_list[self.bestx_index]

    def execute(self):
        self.bestx: Unit = None
        self.bestx_dis = np.inf
        self.bestx_index = -1

        self.bestx_list: list[Unit] = [ Unit().initialize() for _ in range(self.swarm) ]

        for t in range(self.iter):
            self._iteration(t)
