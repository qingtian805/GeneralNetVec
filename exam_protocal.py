import pickle as pkl
from struct import pack, unpack
from socket import socket
from socketserver import BaseRequestHandler
from enum import Enum
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

    for i in range(10):
        if BUFFER_SIZE * i >= length:
            break
        msg += socket.recv(BUFFER_SIZE)
    
    return msg_type, msg

class Event(Enum):
    pass

class Status(Enum):
    pass

class FSMBase(BaseRequestHandler):
    status = None
    transitions = {} # type: dict[tuple[Status, Event], tuple[Status, Callable]]

    def _close(self):
        self.keep_alive = False

    def transit(self, event: Event, **kwargs):
        """
        Event trigger, start an event use this function.
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
        self.keep_alive = True
        while self.keep_alive:
            msg_type, msg = recv_msg(self.request)
            event = None

            if   msg_type == START_HEAD:
                event = Event.NET_START
            elif msg_type == END_HEAD:
                event = Event.NET_END
            elif msg_type == ACK_HEAD:
                event = Event.NET_ACK
            elif msg_type == ABORT_HEAD:
                event = Event.NET_ABORT

            self.transit(event, msg=msg)
