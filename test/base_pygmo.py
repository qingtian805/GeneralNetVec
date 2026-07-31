import os, sys
sys.path.append(f"{os.path.abspath(".")}")

from random import seed
import numpy as np
import pygmo as pg
from scapy.utils import rdpcap
from net_vec import cfg
from net_vec.vector import Unit
from net_vec.logger import logger
from evaluators import KitsuneEval
from net_vec.pygmo import (
    flatten,
    deflatten,
    pop_to_vec,
    vec_to_pop,
    set_pkt_list,
    generation_problem)


set_pkt_list(rdpcap("test/test.pcap"))

evaluator = KitsuneEval(
    model_save_path="exp_file/models/Kitsune/TM_ben.pkl",
    feature_path="TrafficManipulator/example/train_ben.npy",
    fm_grace=5000,
    ad_grace=50000,
    mimic_set="TrafficManipulator/example/mimic_set.npy",
    init_pcap_in=None
)
# logger.set_evaluator(evaluator)

prob = pg.problem(generation_problem(evaluator))
# print(prob)

seed(100)

x = Unit()
x.initialize()
# print(x.craft)

# res = flatten(x)
# print(res)

uls = []
uls.append(x)
pop = vec_to_pop(uls, prob)

print(pop)
