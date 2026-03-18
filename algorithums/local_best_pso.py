import random
import math
import numpy as np

from net_vec.algorithum import NetAlg
from net_vec.vector import Unit
from net_vec.logger import logger

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

    def get_paramter(self):
        return {
            "w": self.w,
            "c1": self.c1,
            "c2": self.c2,
            "iter": self.iter,
            "swarm_size": self.swarm_size,
            "grp_size": self.grp_size,
            }

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
                self.grp_bestx[grp_index] = p.x
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
            if self.grp_bestx_dis[i] < self.glob_best_x_dis:
                index = self.grp_bestx_index[i] + st
                self._update_glob_best_x(
                    self.grp_bestx[i],
                    self.grp_bestx_dis[i],
                    index
                    )


    def execute(self):
        # initialize
        self.grp_bestx = [None] * self.grp_num # type: list[Unit]
        self.grp_bestx_dis = [np.inf] * self.grp_num
        self.grp_bestx_index = [-1] * self.grp_num

        self.swarm = []
        for _ in range(self.swarm_size):
            self.swarm.append(Partical())

        # start iteration
        iter = 0
        while True:
            self._iteration()

            iter += 1
            if iter >= self.iter:
                break
        # 算法迭代结束，提取最好的结果
        cur_end_time = self.glob_best_x.mal[-1][0]
        ics_time = cur_end_time - float(self.cfg.pkt_list[-1].time)

        return ics_time, cur_end_time, self.glob_best_x
