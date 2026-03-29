from exam import Exam
from examinators import KitsuneExam

exam = KitsuneExam("./exam_res/kitsune/model.pkl")
# exam.train_model("./exam_res/kitsune/model.pkl",
#                  "TrafficManipulator/example/train_ben.pcap",
#                  )

e = Exam(exam, "statistics.pkl")
e.exam("TrafficManipulator/example/test.pcap",
       "manipulated.pcap")
