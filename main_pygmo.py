import time
from scapy.utils import rdpcap, wrpcap
import pygmo as pg
from net_vec.pygmo import *
from evaluators import KitsuneEval

evaluator = KitsuneEval(
    model_save_path="exp_file/models/Kitsune/TM_ben.pkl",
    feature_path="TrafficManipulator/example/train_ben.npy",
    fm_grace=5000,
    ad_grace=50000,
    mimic_set="TrafficManipulator/example/mimic_set.npy",
    init_pcap_in=None
)

algo = pg.algorithm(pg.pso(gen=3, omega=0.7298, eta1=0.89618, eta2=0.89618))

pkt_list = rdpcap("exp_file/mal/mal.pcap")
save_path = "manipulated.pcap"
grp_pkt_num = 100
start = 0
end = len(pkt_list)

pop_size = 20

timestamp_start = time.process_time()
last_end_time = pkt_list[0].time
acc_ics_time = 0.

best_x = None
best_pkt_list = []

for st in range(start, end, grp_pkt_num):
    ed = st + grp_pkt_num
    print(f"Processing packet num {st}-{ed - 1}...")
    grp_pkt_list = pkt_list[st:ed]

    for p in grp_pkt_list:
        p.time += acc_ics_time
    set_pkt_list(grp_pkt_list, last_end_time)

    # acc_time, last_end_time, best_x = self.alg.execute()
    # 初始化染色体
    uls = [Unit().initialize() for _ in range(pop_size)]
    prob = pg.problem(generation_problem(evaluator))
    pop = pg.population(prob, 0)
    for i in range(pop_size):
        x = Unit()
        x.initialize()
        x = flatten(x)
        pop.push_back(x)

    pop = algo.evolve(pop)
    best_x = pop.get_x()[pop.best_idx()]
    # print(best_x)

    # Prepare evaluator for next group
    bext_x_unit = deflatten(best_x)
    new_pkt_list = bext_x_unit.rebuild()
    best_pkt_list += new_pkt_list
    evaluator.forward(new_pkt_list)

    last_end_time = best_pkt_list[-1].time
    acc_time = last_end_time - grp_pkt_list[-1].time
    acc_ics_time += acc_time

timestamp_stop = time.process_time()
time_spend = timestamp_stop - timestamp_start
print(f"Process finished, time: {time_spend}")
print(best_x)

with open(save_path, "wb") as f:
    wrpcap(f, best_pkt_list)
