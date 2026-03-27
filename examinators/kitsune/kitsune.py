import pickle as pkl
import numpy as np
from scapy.plist import PacketList

from .Kitsune.KitNET.KitNET import KitNET
from .Kitsune.FeatureExtractor import FE
from .Kitsune.netStat import netStat
from net_vec.examinator import Examinator, OLExaminator

class KitsuneExam(Examinator):
    def __init__(self):
        self.KitNET = None # type: KitNET
        self.FE = None     # type: FE
        self.abnormal_thresh = -np.inf
        self.model_save_path = None # type: str
        self.n_trained = -1

    def save_model(self, model_save_path: str):
        with open(model_save_path, "wb") as f:
            pkl.dump(self.abnormal_thresh, f)
            pkl.dump(self.FE.get_num_features(), f)

            pkl.dump(self.KitNET.v, f)
            pkl.dump(self.KitNET.ensembleLayer, f)
            pkl.dump(self.KitNET.outputLayer, f)
            pkl.dump(self.KitNET.FM_grace_period, f)
            pkl.dump(self.KitNET.AD_grace_period, f)
            pkl.dump(self.KitNET.n_trained, f)

    @staticmethod
    def load_model(model_save_path):
        exam = __class__()
        exam.model_save_path = model_save_path

        with open(model_save_path, "rb") as f:
            exam.abnormal_thresh = pkl.load(f)

            exam.KitNET = KitNET(pkl.load(f), feature_map=pkl.load(f))
            exam.KitNET.ensembleLayer = pkl.load(f)
            exam.KitNET.outputLayer = pkl.load(f)
            exam.KitNET.FM_grace_period = pkl.load(f)
            exam.KitNET.AD_grace_period = pkl.load(f)
            exam.n_trained = exam.KitNET.n_trained = pkl.load(f)

        return exam

    def _run_model(self):
        # create feature vector
        x = self.FE.get_next_vector()
        if len(x) == 0:
            return -1 #Error or no packets left

        # process KitNET
        return self.KitNET.process(x)  # will train during the grace periods, then execute on all the rest.
    
    def train_model(
            self,
            model_save_path: str,
            train_pcap: str,
            limit = np.inf,
            max_autoencoder_size: int = 10,
            FM_grace: int = 5000,
            AD_grace: int = 50000):
        """
        :param max_autoencoder_size: 定义 Kitsune 使用最多多少个
        """

        self.FE = FE(train_pcap, limit)
        self.KitNET = KitNET(self.FE.get_num_features(), max_autoencoder_size, FM_grace, AD_grace)

        self.abnormal_thresh = -np.inf
        while True:
            rmse = self._run_model()
            if rmse == -1:
                break

            if rmse > self.abnormal_thresh:
                self.abnormal_thresh = rmse

        # Save and store status
        self.save_model(model_save_path)
        self.model_save_path = model_save_path
        self.n_trained = self.KitNET.n_trained

    def exam_pcap(self, pcap_file: str, limit = np.inf):
        # Restore Kitsune status
        self.FE = FE(pcap_file, limit)
        self.KitNET.n_trained = self.n_trained

        rmse_list = []
        while True:
            rmse = self._run_model()
            if rmse == -1:
                break

            rmse_list.append(rmse)

        return rmse_list

    def get_feature(self, pcap_file, limit = np.inf):
        pass

class FEOL(FE):
    def set_pkt_list(self, pkt_list):
        self.scapyin = pkt_list
        self.limit = len(pkt_list)
        self.curPacketIndx = 0

    def __init__(self, pkt_list):
        self.nstat = netStat(np.nan, 16777216, 65536)
        self.parse_type = "scapy"

        self.set_pkt_list(pkt_list)

class OLKitsuneExam(KitsuneExam, OLExaminator):
    def __init__(self):
        super().__init__()
        del self.exam_pcap

    def exam_pkt(self, pkt_list: PacketList):
        """
        本类是在线评估器, 不会在每次运行时重新初始化 Feture Extractor
        """
        if self.FE is None:
            self.FE = FEOL()
        # Set kitsune status, no restore
        self.FE.set_pkt_list(pkt_list)

        rmse_list = []
        while True:
            rmse = self._run_model()

            if rmse == -1:
                break
            rmse_list.append(rmse)

        return rmse_list
