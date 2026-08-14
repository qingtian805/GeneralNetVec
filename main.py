from random import seed
from algorithms import LBPSO
from evaluators import KitsuneEval
from manipulator import Manipulator, vec_cfg

"""网络异常流量生成总控台，在这里完成所有有关异常流量对抗样本生成的设置：
1. 选择与设置算法
    * 从 algorithms 中选择一个实现好的算法
    * 使用算法类初始化函数完成算法参数设置
2. 选择评价指标
    * 从 evaluators 中选择一个实现好的评价器
    * 设置好评价器有关参数
    * 变异器会自动将其与算法组装
3. 组装变异器
    * 使用 vec_cfg 成员完成框架算法有关超参数的设置
    * 将选择好的算法与评价器传入变异器
    * 设置变异的流量 pcap 文件
"""

seed(10)

# 底层数据结构设置
# vec_cfg.set_config()

evaluator = KitsuneEval(
    model_save_path="exp_file/models/Kitsune/TM_ben.pkl",
    feature_path="TrafficManipulator/example/train_ben.npy",
    fm_grace=5000,
    ad_grace=50000,
    mimic_set="TrafficManipulator/example/mimic_set.npy",
    init_pcap_in=None
)

# algorithm = LBPSO(
#     w=0.7298,
#     c1=0.89618,
#     c2=0.89618,
#     iter=3,
#     swarm_size=12,
#     grp_size=6
# )

from algorithms import PygmoPort
algorithm = PygmoPort()

m = Manipulator(
    mal_pcap_file="exp_file/mal/mal.pcap",
    algorithm=algorithm,
    evaluator=evaluator,
    grp_pkt_num=100,
)


m.manipulate()
m.dump_sta("statistics.pkl")
m.dump_pkt_list("manipulated.pcap")
