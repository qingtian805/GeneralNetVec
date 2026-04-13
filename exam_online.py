from queue import Queue
from threading import Thread
from struct import pack, unpack
import pickle as pkl
from socket import socket
from scapy.sendrecv import AsyncSniffer

from exam import Exam
from net_vec.examinator import OLExaminator

ABORT_HEAD = b"ABO"
ACK_HEAD   = b"ACK"
END_HEAD   = b"END"
START_HEAD = b"STA"

BUFFER_SIZE = 1500

def start_msg(exam_type: str = None, exam_paramter: dict = None):
    """
    Return a standard START MESSAGE

    b"STA" + message length + len(exam_type) + exam_type + exam_paramter
    """
    exam_paramter_dump = pkl.dumps(exam_paramter)
    message_len = 4 + len(exam_type) + len(exam_paramter_dump)

    return START_HEAD + pack(">I", message_len) + \
        pack(">I", len(exam_type)) + exam_type + exam_paramter_dump

def abort_msg():
    """
    Return a standard ABORT MESSAGE

    b"ABO" + message length(0)
    """
    return ABORT_HEAD + pack(">I", 0)

def ack_msg():
    """
    Return a standard ACK MESSAGE

    b"ACK" + message length(0)
    """
    return ACK_HEAD + pack(">I", 0)

def end_msg():
    """
    Return a standard END MESSAGE

    b"END" + message length(0)
    """
    return END_HEAD + pack(">I", 0)

def recv_msg(socket: socket):
    """
    Recive a standard msg from socket, returns
    
    1. msg_type(defined with headers)
    2. messages inside(b'' if nothing inside)
    """
    msg_type = socket.recv(3)
    length = unpack(">I", socket.recv(4))[0]
    msg = b''

    for i in range(10):
        if BUFFER_SIZE * i >= length:
            break
        msg += socket.recv(BUFFER_SIZE)
    
    return msg_type, msg

class OnlineExam(Exam):
    def __init__(
            self,
            ol_examinator: OLExaminator,
            batch_size: int = 100,
            buffer_size: int = 0
            ):
        """
        :param ol_examinator: 一个在线评估器，要求能够评价一个 scapy.plist.PacketList
        类型数据
        :param batch_size: 一次送入评估器的流量数量
        :param buffer_size: 缓冲区大小，如果 <= 0，则不限制缓冲区大小
        """
        
        getattr(ol_examinator, "exam_pkt")
        
        self.examinator = ol_examinator
        self.batch_size = batch_size

        self.buffer = Queue(buffer_size)
        self.rmse_list = []
        self.sniffer = None # type: AsyncSniffer

    def dump_result(self, dump_file_prefix):
        with open(f"{dump_file_prefix}.pkt", "wb") as f:
            pkl.dump(self.rmse_list, f)

    def capture(self, packet):
        if not self.buffer.full():
            self.buffer.put_nowait(packet)
        else:
            print("Too much traffic!")
    
    def process(self):
        self.examinator.prepare_exam()
        self.batch = []
        while True:          
            pkt = self.buffer.get()
            if pkt is None:
                break
            self.batch.append(pkt)

            if len(self.batch) >= self.batch_size:
                rmse = self.examinator.exam_pkt(self.batch)
                self.batch.clear()
                self.rmse_list += rmse
        
    def flush(self):
        """
        将最后的数据全部取出并完成评估，
        """
        if len(self.batch) != 0:
            self.rmse_list += self.examinator.exam_pkt(self.batch)

    def exam(self, interface = None ,filter = ""):
        """
        :param interface: sniff on which interface, defaults to scapy.conf.iface, specific with str interface name e.g."eth0"
        :param filter: Berkeley Packet Filter, see [This site](https://www.ibm.com/docs/en/qsip/7.5.0?topic=queries-berkeley-packet-filters)
        """
        self.p_thread = Thread(target=self.process)
        self.p_thread.start()
        
        self.sniffer = AsyncSniffer(prn=self.capture, store=False, filter=filter, iface=interface)
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop(join=True)
        self.buffer.put(None)
        self.p_thread.join()
        self.flush()
    
class ExamMetricCalculator(Exam):
    def __init__(self):
        pass

    @staticmethod
    def cal_metric(origin_rmse, manipu_rmse):
        """
        :param origin_rmse: 可以是路径(str)或数据(np.array)
        :param manipu_rmse: 可以是路径(str)或数据(np.array)
        """

        if isinstance(origin_rmse, str):
            with open(origin_rmse) as f:
                origin_rmse = pkl.load(f)

        if isinstance(manipu_rmse, str):
            with open(manipu_rmse) as f:
                manipu_rmse = pkl.load(f)

        calculator = ExamMetricCalculator()
        calculator.origin_rmse = origin_rmse
        calculator.manipu_rmse = manipu_rmse

        der = calculator._detection_evasion_rate()
        mer = calculator._malicious_evasion_rate()
        pdr = calculator._probability_decline_rate()

        return der,mer,pdr
    
if __name__ == "__main__":
    from examinators import OLKitsuneExam
    from time import sleep
    
    exam = OLKitsuneExam("./exam_res/kitsune/model.pkl")
    e = OnlineExam(exam, batch_size=20, buffer_size=0)

    # e.exam()
    # sleep(2)
    # e.stop()
    # print(len(e.rmse_list))
    t = Thread(target=e.exam)
    t.start()
    sleep(1)
    e.stop()
    if t.is_alive():
        print("Thread not stop!")

    print(len(e.rmse_list))

