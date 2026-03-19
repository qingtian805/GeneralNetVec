import time
import numpy as np
from pickle import dump
from scapy.utils import rdpcap, wrpcap
from scapy.utils import EDecimal

from net_vec.algorithum import NetAlg
from net_vec.vector import Unit
from net_vec.evaluator import Evaluator
from net_vec.logger import logger

class Manipulator:
    def __init__(
            self, 
            mal_pcap_file: str,
            algorithum: NetAlg, 
            evaluator: Evaluator, 
            grp_pkt_num: int,
            ):
        
        with open(mal_pcap_file, "rb") as f:
            self.pkt_list = rdpcap(f)

        self.alg = algorithum
        self.eval = evaluator

        logger.algo_instance = algorithum
        logger.eval_instance = evaluator
        
        self.alg.evaluator = evaluator
        
        self.grp_pkt_num = grp_pkt_num

        self.sta_best_x = []
        self.sta_feature_list = []
        self.sta_all_feature_list = []
        self.sta_glob_dis_list = []
        self.sta_avg_dis_list = []

    def save_config(self, save_path):
        f = open(save_path, "a")

        f.write(f"Time Spent: {self.time_spend}")
        f.write(f"Algorithum:\t{type(self.alg)}")
        f.write(f"Evaluator:\t{type(self.eval)}")
        f.write("AlgParamters:")
        for key, value in self.alg.get_paramter().items():
            f.write(f"    {key}:\t {value}")
        f.write("VecParameters:")
        for key, value in self.alg.cfg.__dict__.items():
            f.write(f"    {key}:\t {value}")
        
        f.close()

    def dump_sta(self, sta_path):
        with open(sta_path, "wb") as f:
            dump(self.sta_best_x, f)
            dump(self.sta_feature_list, f)
            dump(self.sta_all_feature_list, f)
            dump(self.sta_glob_dis_list, f)
            dump(self.sta_avg_dis_list, f)
        
    def dump_pkt_list(self, pcap_path, start = 0, end = None):
        if end is None:
            end = len(self.pkt_list)

        pkt_list = []
        i = -1
        for st in range(start, end, self.grp_pkt_num):
            ed = st + self.grp_pkt_num
            i += 1
            self.alg.set_pkt_list(self.pkt_list[st: ed])
            pkt_list += self.sta_best_x[i].rebuild()

        with open(pcap_path, "wb") as f:
            wrpcap(f, pkt_list)


    def manipulate(
            self,
            start: int = 0,
            end: int = None
            ):
        r"""
        manipulate 执行优化算法，并返回优化结果
        """
        timestamp_start = time.process_time()

        last_end_time = self.pkt_list[0].time
        acc_ics_time = 0.

        if end is None:
            end = len(self.pkt_list)

        for st in range(start, end, self.grp_pkt_num):
            ed = st + self.grp_pkt_num
            print(f"Processing packet num {st}-{ed}...")
            grp_pkt_list = self.pkt_list[st:ed]

            for p in grp_pkt_list:
                p.time = p.time + acc_ics_time
            self.alg.set_pkt_list(grp_pkt_list, last_end_time)

            acc_time, last_end_time, best_x = self.alg.execute()

            acc_ics_time += acc_time

            # log status
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