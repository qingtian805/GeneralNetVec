import os.path as path
from exam import Exam
from examinators import KitsuneExam
from config import Config

"""测试总控台，在生成流量后可以在这里测试效果
"""

config = Config("config.json")

exam = KitsuneExam()
# exam.train_model("exp_file/models/Kitsune/mirai.pkl",
#                  "datasets/single_file/mirai.pcap",
#                  )

model_path = "exp_file/models"

exam.load_model(path.join(model_path, "Kitsune/TM_ben.pkl"))

mal_samp   = "exp_file/mal"
raw_res    = "exp_file/raw_res"
exp_name   = "new_represent_lbpso_g2"

e = Exam(exam)
e.exam_origin_pcap_file(
    path.join(mal_samp, "mal.pcap")
)
# e.set_manipu_pcap_file(
#     path.join(raw_res, exp_name, ".pcap"),
#     path.join(raw_res, exp_name, ".pkl")
# )

e.exam_manipu_pcap_file(
    "test1.pcap",
    "test1.pkl"
)
e.cal_metrics()
e.plt_rmse()
