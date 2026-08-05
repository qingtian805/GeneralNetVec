import random
from copy import deepcopy
import numpy as np

from net_vec import NetAlg, Unit, cfg, logger

class Partical:
    def __init__(self):
        self.x = Unit() # 个体位置
        self.x.initialize()
        # 个体速度
        self.v = Unit()
        # 个体最佳位置
        self.indi_bestx = self.x # type: Unit
        # 最佳评价
        self.indi_bestx_dis = np.inf


class LBPSO(NetAlg):
    def __init__(
            self,
            w: float = 0.7298,
            c1: float = 1.49618,
            c2: float = 1.49618,
            iter: int = 3,
            swarm_size: int = 6,
            grp_size: int = 3,
            *args,
            **kwargs
            ):
        """
        本地拓扑PSO算法

        :param w: 惯性权重
        :param c1: 个体学习因子
        :param c2: 社会学习因子
        :param iter: 最大迭代次数
        :param swarm_size: 粒子群大小
        :param grp_size: 每组粒子数量
        """
        super().__init__(*args, **kwargs)

        self.w = w
        self.c1 = c1
        self.c2 = c2
        self.iter = iter
        self.swarm_size = swarm_size
        self.grp_size = grp_size

        self.grp_num = swarm_size // grp_size

    def get_paramters(self):
        return {
            "w": self.w,
            "c1": self.c1,
            "c2": self.c2,
            "iter": self.iter,
            "swarm_size": self.swarm_size,
            "grp_size": self.grp_size,
            }

    def get_best_x(self):
        return (self.glb_bestx,
                self.glb_bestx_dis,
                self.glb_bestx_index)

    def _generate_V(self, x: Unit, best_x: Unit):
        """生成指向最优解的方向 V, 即计算

        $$$ P_t - X_t $$$

        :param p: 目前个体位置
        :type p: Partival
        :param best_X: 最优位置
        :type best_X: Unit
        :return: 指向最优解的向量
        :rtype: Unit"""
        v = Unit()

        # 指向最优解的向量
        v = best_x - x
        # v.mal = best_x.mal - x.mal
        # v.craft = best_x.craft - x.craft

        return v

    def _update_V(self, p: Partical, grp_bestx: Unit):
        """

        """
        # social V
        soc_V = self._generate_V(p.x, grp_bestx)
        # congitive V
        cog_V = self._generate_V(p.x, p.indi_bestx)

        r1 = random.random()
        r2 = random.random()

        p.v = self.w * p.v + self.c1 * r1 * cog_V + self.c2 * r2 * soc_V

        # p.v.mal = self.w * p.v.mal + self.c1 * r1 * cog_V.mal + self.c2 * r2 * soc_V.mal
        # p.v.craft = self.w * p.v.craft + self.c1 * r1 * cog_V.craft + self.c2 * r2 * soc_V.craft

    def _update_X(self, p: Partical):
        """根据V更新X,并加入诸多限制,即算法第二步

        $$ X_{t+1} = X_t + V_{t+1} $$

        :param p: 个体位置
        :type p: Partical
        :param V: 速度
        :type V: Unit
        :return: 更新后的 p
        :rtype: Partical"""

        p.x = p.x + p.v
        p.x.restrict()

        return p

    def _update_group(self, partical_list: list[Partical], grp_index):
        """
        优化一个本地拓扑
        """
        # Evaluate for group best
        for i in range(self.grp_size):
            p = partical_list[i]
            new_dis = self.evaluator.evaluate(p.x)

            if new_dis < p.indi_bestx_dis:
                p.indi_bestx = p.x
                p.indi_bestx_dis = new_dis

            if new_dis < self.grp_bestx_dis[grp_index]:
                self.grp_bestx[grp_index] = deepcopy(p.x)
                self.grp_bestx_dis[grp_index] = new_dis
                self.grp_bestx_index[grp_index] = i
        # Update partical velocity and position
        for p in partical_list:
            self._update_V(p, self.grp_bestx[grp_index])
            self._update_X(p)

    @logger.iteration_logger
    def _iteration(self):
        for i in range(self.grp_num):
            st = i * self.grp_size
            ed = (i + 1) * self.grp_size
            self._update_group(self.swarm[st:ed], i)

            # 如果组内找到的最好要好于全局，则更新全局最好信息
            if self.grp_bestx_dis[i] < self.glb_bestx_dis:
                self.glb_bestx = self.grp_bestx[i]
                self.glb_bestx_dis = self.grp_bestx_dis[i]
                self.glb_bestx_index = self.grp_bestx_index[i] + st

    def execute(self):
        # initialize
        self.glb_bestx: Unit = None
        self.glb_bestx_dis: float = np.inf
        self.glb_bestx_index: int = -1
        self.grp_bestx: list[Unit | None] = [None] * self.grp_num
        self.grp_bestx_dis: list[float] = [np.inf] * self.grp_num
        self.grp_bestx_index: list[int] = [-1] * self.grp_num

        self.swarm = []
        for _ in range(self.swarm_size):
            self.swarm.append(Partical())

        # start iteration

        for _ in range(self.iter):
            self._iteration()

        return self.glb_bestx
