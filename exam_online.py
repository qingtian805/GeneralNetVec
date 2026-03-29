from queue import Queue, Empty
from threading import Thread
import pickle as pkl
from scapy.sendrecv import sniff

from exam import Exam
from net_vec.examinator import OLExaminator

class OnlineExam(Exam):
    def __init__(
            self,
            ol_examinator: OLExaminator,
            batch_size: int = 100,
            buffer_size: int = 0
            ):
        
        getattr(ol_examinator, "exam_pkt")
        
        self.examinator = ol_examinator
        self.batch_size = batch_size

        self.buffer = Queue(buffer_size)
        self.rmse_list = []

    def dump_result(self, dump_file_prefix):
        with open(f"{dump_file_prefix}.pkt", "wb") as f:
            pkl.dump(self.origin_rmse, f)
            pkl.dump(self.manipu_rmse, f)

    def capture(self, packet):
        if not self.buffer.full():
            self.buffer.put_nowait(packet)
        else:
            print("Too much traffic!")
    
    def process(self):
        self.examinator.prepare_exam()
        batch = []
        while True:
            print("buff: {}".format(self.buffer.qsize()))
            
            batch.append(self.buffer.get())

            if len(batch) >= self.batch_size:
                rmse = self.examinator.exam_pkt(batch)
                batch.clear()
                self.rmse_list += rmse

    def exam(self, interface = None ,filter = ""):
        self.running = True
        p_thread = Thread(target=self.process)
        p_thread.daemon = True
        p_thread.start()
        
        sniff(prn=self.capture, store=False, filter=filter, iface=interface)

        print(self.rmse_list)

# class MetricCalulator(Exam):

