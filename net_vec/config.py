from scapy.utils import EDecimal
from scapy.packet import Packet
import numpy as np

class Conf:
    def __init__(self):
        # Algorithm related config
        self.pkt_list         = None # type: list[Packet]
        self.last_end_time    = None # type: EDecimal
        self.max_cft_pkt      = 1 # type: int
        self.max_cft_pkt_prob = 0.01 # type: float
        self.max_time_extend  = 6. # type: float
        self.min_time_extend  = 3. # type: float
        self.fence_time_divider = 10000 # type: int
        self.cft_time_divider = 1000 # type: int
        self.proto_min_lmt    = 1. # type: float
        self.data_max_lmt     = [np.nan, 1500., 1480., 1460.] # type: list
        self.data_min_lmt     = 0. # type: float

        self.pkt_num      = None # type: int
        self.proto_max_lmt = None # type: list[float]
        
        # Evaluator related config
        self.mimic_set        = None # type: str

cfg = Conf()