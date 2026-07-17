from exam import Exam
from examinators import KitsuneExam

"""测试总控台，在生成流量后可以在这里测试效果
"""

exam = KitsuneExam()
# exam.train_model("exp_file/models/Kitsune/mirai.pkl",
#                  "datasets/single_file/mirai.pcap",
#                  )

exam.load_model("exp_file/models/Kitsune/TM_ben.pkl")
e = Exam(exam, "statistics.pkl")
e.exam("exp_file/mal/mal.pcap",
       "manipulated.pcap")
