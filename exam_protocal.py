import pickle as pkl
from struct import pack, unpack
from socket import socket
from socketserver import BaseRequestHandler
from enum import Enum, auto
from typing import Callable

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

    i = 0
    while True:
        msg += socket.recv(BUFFER_SIZE)
        i += 1
        if BUFFER_SIZE * i >= length:
            break

    return msg_type, msg

class Event(Enum):
    pass

class NetEvent(Event):
    NET_ACK   = auto()
    NET_START = auto()
    NET_END   = auto()
    NET_ABORT = auto()

class Status(Enum):
    pass

class FSMBase(BaseRequestHandler):
    """
    网络有限状态机基础，可以给予本类快速构建网络有限状态机。需要：

    1. 本地事件请扩展 `Event` 类，网络事件有已经定义的 `NetEvent` 类
    2. 状态类扩展 `Status` 类
    3. 在类变量 `self.transitions` 中按照{(当前状态, 事件):(目标状态, 执行函数)}的顺序定义有限状态机的状态转换图
    4. 请调用 `__init__()` 设置初始状态和会话保活
    5. 网络事件的处理需要函数能够接受一个名称为 `msg` 的参数，这个参数传入去除头部的**原始**消息内容
    6. 如果要关闭服务器，请调用 `self._close()` 方法，或设置 `self.keep_alive = false`
    """

    # Transitions 记录 有限状态机 状态转换表
    transitions = {} # type: dict[tuple[Status, Event], tuple[Status, Callable]]

    def __init__(self, init_status = None, keep_alive = True):
        """
        :param init_status: 有限状态机初始状态
        :type init_status: Any
        :param keep_alive: 会话是否保活，若保活，则退出会话需要设置此变量为 False
        :type keep_alive: bool
        """
        self.status = init_status
        self.keep_alive = keep_alive

    def _close(self):
        self.keep_alive = False

    def transit(self, event: Event, **kwargs):
        """
        Event trigger, start an event use this function.
        This will get trasitions base on current status and event

        `(Status, Event) -> (NStatus, Callable)`

        Then set FSM status to NStatus and call the function like:

        `Callable(**kwargs)`
        """
        try:
            target_status, action = self.transitions[(self.status, event)]
            action(**kwargs)
            self.status = target_status
        except KeyError:
            pass

    def handle(self):
        """
        NET triger, require every net subhandler has a msg kwarg
        """
        while self.keep_alive:
            msg_type, msg = recv_msg(self.request)
            event = None

            if   msg_type == START_HEAD:
                event = NetEvent.NET_START
            elif msg_type == END_HEAD:
                event = NetEvent.NET_END
            elif msg_type == ACK_HEAD:
                event = NetEvent.NET_ACK
            elif msg_type == ABORT_HEAD:
                event = NetEvent.NET_ABORT

            self.transit(event, msg=msg)

__all__ = ["ABORT_HEAD", "ACK_HEAD", "END_HEAD", "START_HEAD",
           "abort_msg",  "ack_msg",  "end_msg",  "start_msg",
           "Event", "Status", "NetEvent", "FSMBase"]
