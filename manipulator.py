import time
from pickle import dump
from scapy.utils import rdpcap, wrpcap

from net_vec import NetAlg, Evaluator, logger, cfg

vec_cfg = cfg
""" 底层向量数据结构设置，影响流量与向量的双向映射 """

class Manipulator:

    def __init__(
            self,
            mal_pcap_file: str,
            algorithm: NetAlg,
            evaluator: Evaluator,
            grp_pkt_num: int,
            ):
        """网络异常流量变异器，使用指定的算法与评价器完成异常流量对抗样本生成

        :param mal_pcap_file: 恶意流量存储路径
        :param algorithm: 一个基于 net_vec.algorithm.NetAlg 实现的优化算法
        :param evaluator: 一个基于 net_vec.evaluator.Evaluator 实现的评价器
        :param grp_pkt_num: 超参数，同时进行变异的恶意流量包数
        """

        with open(mal_pcap_file, "rb") as f:
            self.pkt_list = rdpcap(f)

        self.alg = algorithm
        self.eval = evaluator

        # init logger
        logger.algo_instance = algorithm
        logger.eval_instance = evaluator

        self.alg.evaluator = evaluator

        self.grp_pkt_num = grp_pkt_num

        # log
        self.sta_best_x = []
        self.sta_feature_list = []
        self.sta_all_feature_list = []
        self.sta_glob_dis_list = []
        self.sta_avg_dis_list = []
        self.best_pkt_list = []

    def save_config(self, save_path):
        """保存当前变异参数到 save_path
        记录
        """
        f = open(save_path, "a")

        f.write(f"Time Spent: {self.time_spend}")
        f.write(f"Algorithm:\t{type(self.alg)}")
        f.write(f"Evaluator:\t{type(self.eval)}")
        f.write("AlgParamters:")
        for key, value in self.alg.get_paramters().items():
            f.write(f"    {key}:\t {value}")
        f.write("VecParameters:")
        for key, value in cfg.__dict__.items():
            f.write(f"    {key}:\t {value}")

        f.close()

    def dump_sta(self, sta_path):
        """ 保存日志文件，包含：
        1. 历史最优样本
        2. 历史最优样本的特征在评价器中的恶意包特征
        3. 历史最优样本的特征在评价器中的所有包特征
        4. 历史最优样本的距离历史
        5. 所有样本的距离历史

        以上内容通过 pickle 库逐个存储在 sta_path 文件中
        """
        with open(sta_path, "wb") as f:
            dump(self.sta_best_x, f)
            dump(self.sta_feature_list, f)
            dump(self.sta_all_feature_list, f)
            dump(self.sta_glob_dis_list, f)
            dump(self.sta_avg_dis_list, f)

    def dump_pkt_list(self, pcap_path):
        """ 将最优样本的流量写入 pcap_path 中 """
        with open(pcap_path, "wb") as f:
            wrpcap(f, self.best_pkt_list)

    def manipulate(
            self,
            start: int = 0,
            end: int = None
            ):
        r"""
        manipulate 执行优化算法，并返回优化结果
        :param start: 变异开始的包序号，首个为 0
        :param end: 变异结束的包序号，首个为 0
        """
        timestamp_start = time.process_time()

        last_end_time = self.pkt_list[0].time
        acc_ics_time = 0.

        if end is None:
            end = len(self.pkt_list)

        for st in range(start, end, self.grp_pkt_num):
            ed = st + self.grp_pkt_num
            print(f"Processing packet num {st + 1}-{ed}, total: {end}...", end="\r")
            grp_pkt_list = self.pkt_list[st:ed]

            for p in grp_pkt_list:
                p.time = p.time + acc_ics_time
            cfg.set_pkt_list(grp_pkt_list, last_end_time)

            best_x = self.alg.execute()
            # 算法迭代结束，根据结果获取时间修正参数
            last_end_time = best_x.mal[-1][0]
            ics_time = last_end_time - float(cfg.pkt_list[-1].time)

            acc_ics_time += ics_time

            # Prepare evaluator for next group
            new_pkt_list = best_x.rebuild()
            self.eval.forward(new_pkt_list)

            # log status
            self.best_pkt_list += new_pkt_list
            self.sta_best_x.append(best_x)
            feature, all_feature, dis_list, avg_dis_list = logger.get_log()
            logger.clear()
            self.sta_feature_list.append(feature)
            self.sta_all_feature_list.append(all_feature)
            self.sta_glob_dis_list.append(dis_list)
            self.sta_avg_dis_list.append(avg_dis_list)

        timestamp_stop = time.process_time()
        self.time_spend = timestamp_stop - timestamp_start
        print(f"Process finished, time: {self.time_spend}")