from socketserver import TCPServer
from struct import unpack
from pickle import loads, dumps
from threading import Thread
from enum import Enum, auto
from typing import Callable

import examinators
from exam_online import OnlineExam
from exam_protocal import *

BUFFER_SIZE = 1500
STOP_TIMEOUT = 10
EXAM_THREAD = None # type: Thread | None
INTERFACE = "wlp0s20f3"
HOST, PORT = "localhost", 9999


class Status(Enum):
    IDLE      = auto()
    WAIT_RUN  = auto()
    RUNNING   = auto()
    FIN_EXAM  = auto()
    WAIT_STOP = auto()
    WAIT_SAVE = auto()
    SAVING    = auto()
    FIN_SAVE  = auto()
    ABORTING  = auto()

class Event(Enum):
    NET_ACK   = auto()
    NET_START = auto()
    NET_END   = auto()
    NET_ABORT = auto()
    LOC_FIN   = auto()

class ExamHandler(FSMBase):
    def _nop(self, msg: bytes):
        pass

    def _start(self, msg: bytes):
        """
        START subhandler
        """
        global EXAM_THREAD
        # Phase msg: exam_length:4 byte + exam_name + paramters
        exam_length = unpack(">I", msg[:4])[0]
        self.exam_type = msg[4:exam_length + 4].decode("UTF-8")
        exam_class = getattr(examinators, self.exam_type)
        self.exam_paramters = loads(msg[exam_length + 4:])
        
        examinator = exam_class(self.exam_paramters)
        self.exam = OnlineExam(examinator)

        # use bpf to filter traffic of controler itself
        EXAM_THREAD = Thread(self.exam.exam(
                        interface=INTERFACE,
                        filter=f"host not {self.server.server_address[0]} or tcp port not {self.server.server_address[1]}")
                        )

        # Start Protocal
        self.request.sendall(ack_msg())
        return 0

    def _exam_end(self, msg: bytes):
        """
        END subhandler
        """  
        # Stop exam process
        self.exam.stop()
        
        # END protocl
        self.request.sendall(ack_msg())
        return 0
    
    def _prep_save(self):
        global EXAM_THREAD
        EXAM_THREAD.join(STOP_TIMEOUT)

        if EXAM_THREAD.is_alive():
            return -1
        
        self.transit(Event.LOC_FIN)
    
    def _start_save(self):
        self.request.sendall(start_msg(self.exam_type, self.exam_paramters))

    def _save(self):
        """
        SAVING subhandler
        This handler sends rmse_list to remote client. When finished,
        it triggers LOC_FIN event
        """
        self.request.sendall(ack_msg())
        # Dumping result
        self.request.sendall(dumps(self.exam.rmse_list))

        self.transit(Event.LOC_FIN)

    def _save_end(self):
        """
        What to do when all data sent? It triggers END protocal to client
        """
        self.request.sendall(end_msg())

    def _save_final(self, msg: bytes):
        """
        DO NOT call this to send ack.
        """
        self.request.sendall(ack_msg())
        self._close()

    def _abort(self, msg: bytes):
        """
        ABORT subhandler
        """
        global EXAM_THREAD
        if self.status == Status.IDLE:
            return 0
        
        self.exam.stop()
        EXAM_THREAD.join(timeout=STOP_TIMEOUT)

        if EXAM_THREAD.is_alive():
            return -1

        self.request.sendall(ack_msg())
        self.server.close_request()

    def _close(self):
        self.keep_alive = False

    status = Status.IDLE
    transitions = {
        # Start transations
        (Status.IDLE,      Event.NET_START): (Status.WAIT_RUN,  _start),
        (Status.WAIT_RUN,  Event.NET_ACK)  : (Status.RUNNING,   _nop),
        # End trasations
        (Status.RUNNING,   Event.NET_END)  : (Status.FIN_EXAM,  _exam_end),
        (Status.FIN_EXAM,  Event.NET_ACK)  : (Status.WAIT_STOP, _prep_save),
        # Start saving
        (Status.WAIT_STOP, Event.LOC_FIN)  : (Status.WAIT_SAVE, _start_save),
        (Status.WAIT_SAVE, Event.NET_ACK)  : (Status.SAVING,    _save),
        # Finish saving
        (Status.SAVING,    Event.LOC_FIN)  : (Status.FIN_SAVE,  _save_end),
        (Status.FIN_SAVE,  Event.NET_ACK)  : (Status.IDLE,      _save_final),
        # Aborting
        (Status.RUNNING,   Event.NET_ABORT): (Status.ABORTING,  _abort),
        (Status.ABORTING,  Event.NET_ACK)  : (Status.IDLE,      _close),
    } # type: dict[tuple[Status, Event], tuple[Status, Callable]]

if __name__ == "__main__":
    # 创建服务器，绑定到 localhost 的 9999 端口
    with TCPServer((HOST, PORT), ExamHandler) as server:
        # 激活服务器；它将持续运行直到你
        # 使用 Ctrl-C 中断程序
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
