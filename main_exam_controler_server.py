from socketserver import TCPServer, BaseRequestHandler
from socket import socket
from struct import pack, unpack
from pickle import loads, dumps
from threading import Thread
from enum import Enum
from typing import Callable

import examinators
from net_vec.examinator import OLExaminator
from exam_online import (
    OnlineExam,
    ABORT_HEAD, abort_msg,
    ACK_HEAD, ack_msg,
    END_HEAD, end_msg,
    START_HEAD, start_msg,
    recv_msg
    )

BUFFER_SIZE = 1500
STOP_TIMEOUT = 5
EXAM_THREAD = None # type: Thread | None
INTERFACE = "wlp0s20f3"

class Status(Enum):
    IDLE = 0
    RUNNING = 1
    SAVING = 2

class ExamHandler(BaseRequestHandler):
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

        msg, _ = recv_msg(self.request)
        if not msg == ACK_HEAD:
            return -1
        return 0
    
    def _save(self):
        """
        SAVING subhandler
        """
        # START Protocal
        self.request.sendall(start_msg(self.exam_type, self.exam_paramters))
        
        msg_type, _ = recv_msg(self.request)
        if msg_type != ACK_HEAD:
            return -1
        
        self.request.sendall(ack_msg())

        # Dumping result
        self.request.sendall(dumps(self.exam.rmse_list))

        # END Protocal
        self.request.sendall(end_msg())
        msg_type, _ = recv_msg(self.request)
        if msg_type != ACK_HEAD:
            return -1
        
        self.request.sendall(ack_msg())
        self.status = Status.IDLE

    def _end(self, msg: bytes):
        """
        END subhandler
        """
        if self.status != Status.RUNNING:
            return -1
        
        # Stop exam process
        self.exam.stop()
        EXAM_THREAD.join(timeout=STOP_TIMEOUT)
        if EXAM_THREAD.is_alive():
            return -1
        
        # END protocl
        self.request.sendall(ack_msg())

        msg, _ = recv_msg(self.request)
        if msg != ACK_HEAD:
            return -1

        self._save()

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

        self.status = Status.IDLE
        self.request.sendall(ack_msg())

        msg, _ = recv_msg(self.request)
        if msg != ACK_HEAD:
            return -1

        
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

        self.status = Status.IDLE
        self.transations = {
            (Status.IDLE   , START_HEAD): (Status.RUNNING, self._start),
            (Status.RUNNING, END_HEAD  ): (Status.SAVING , self._end  ),
            (Status.RUNNING, ABORT_HEAD): (Status.IDLE   , self._abort),
        } # type: dict[tuple[Status, bytes], tuple[Status, Callable]]

    def handle(self):
        msg_type, msg = recv_msg(self.request)

        try:
            self.status, action = self.transations[(self.status, msg_type)]
            action(msg)
        except KeyError:
            pass
        
if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    # 创建服务器，绑定到 localhost 的 9999 端口
    with TCPServer((HOST, PORT), ExamHandler) as server:
        # 激活服务器；它将持续运行直到你
        # 使用 Ctrl-C 中断程序
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
