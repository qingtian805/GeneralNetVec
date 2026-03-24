from exam import Exam
from examinators import KitsuneExam

# exam = KitsuneExam()
# exam.train_model("./exam_res/kitsune",
#                  "TrafficManipulator/example/train_ben.pcap",
#                  )
exam = KitsuneExam.load_model("./exam_res/kitsune")

e = Exam(exam, "statistics.pkl")
e.exam("TrafficManipulator/example/test.pcap",
       "manipulated.pcap")
