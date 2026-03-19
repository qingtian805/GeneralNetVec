from algorithums import LBPSO
from evaluators import KitsuneEval
from manipulator import Manipulator

algorithum = LBPSO(
    w=0.7298,
    c1=1.49618,
    c2=1.49618,
    iter=3,
    swarm_size=6,
    grp_size=3
)
# If you want to config paramters, use below
#algorithum.cfg

evaluator = KitsuneEval(
    model_save_path="TrafficManipulator/example/model.pkl",
    feature_path="TrafficManipulator/example/train_ben.npy",
    fm_grace=5000,
    ad_grace=50000,
    mimic_set="TrafficManipulator/example/mimic_set.npy",
    init_pcap_in=None
)

m = Manipulator(
    mal_pcap_file="TrafficManipulator/example/test.pcap",
    algorithum=algorithum,
    evaluator=evaluator,
    grp_pkt_num=100,
)

m.manipulate()
m.dump_sta("statistics.pkl")
m.dump_pkt_list("manipulated.pcap")
