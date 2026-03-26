import numpy as np
from scapy.utils import rdpcap
from scapy.plist import PacketList

from .Kitsune.netStat import netStat
from .Kitsune.FeatureExtractor import FE
from .Kitsune.KitNET.KitNET import KitNET
from .kitsune import KitsuneExam


class FEOL(FE):
    def set_pkt_list(self, pkt_list):
        self.scapyin = pkt_list
        self.limit = len(pkt_list)
        self.curPacketIndx = 0

    def __init__(self, pkt_list):
        self.nstat = netStat(np.nan, 16777216, 65536)
        self.parse_type = "scapy"

        self.set_pkt_list(pkt_list)

class OLKitsuneExam(KitsuneExam):
    def __init__(self):
        super().__init__()
    
    def train_model(
            self,
            model_save_path: str,
            train_pcap: str,
            limit = np.inf,
            max_autoencoder_size: int = 10,
            FM_grace: int = 5000,
            AD_grace: int = 50000):
        
        with open(train_pcap, "rb") as f:
            train_pkt = rdpcap(f)

        self.FE = FEOL(train_pkt, limit) # type: FEOL
        self.KitNET = KitNET(self.FE.get_num_features(), max_autoencoder_size, FM_grace, AD_grace)

        loop = 0
        self.abnormal_thresh = -np.inf
        while True:
            rmse = self._run_model()
            if rmse == -1:
                break

            if rmse > self.abnormal_thresh:
                self.abnormal_thresh = rmse

            loop += 1

        # Save and store status
        self.save_model(model_save_path)
        self.model_save_path = model_save_path
        self.n_trained = self.KitNET.n_trained

    def exam(self, pkt_list: PacketList, limit = np.inf):
        # Set kitsune status, no restore
        self.FE.set_pkt_list(pkt_list)

        rmse_list = []
        while True:
            rmse = self._run_model()

            if rmse == -1:
                break
            rmse_list.append(rmse)

        return rmse_list
