import pickle as pkl
from scapy.utils import rdpcap
import numpy as np

from .Kitsune.Kitsune import Kitsune
from .Kitsune.FeatureExtractor import FE
from net_vec.examinator import Examinator

class KitsuneExam(Examinator):
    def __init__(self):
        self.kitsune = None
        self.abnormal_thresh = -np.inf
        self.model_save_path = None

    def save_model(self, model_save_path: str):
        with open(model_save_path, "wb") as f:
            pkl.dump(self.abnormal_thresh, f)

            pkl.dump(self.kitsune.AnomDetector.ensembleLayer, f)
            pkl.dump(self.kitsune.AnomDetector.outputLayer, f)
            pkl.dump(self.kitsune.AnomDetector.v, f)
            pkl.dump(self.kitsune.AnomDetector.FM_grace_period, f)
            pkl.dump(self.kitsune.AnomDetector.AD_grace_period, f)
            pkl.dump(self.kitsune.AnomDetector.n_trained, f)

    @staticmethod
    def load_model(model_save_path):
        exam = KitsuneExam()

        with open(model_save_path, "rb") as f:
            exam.abnormal_thresh = pkl.load(f)
        exam.model_save_path = model_save_path
        return exam

    def train_model(
            self,
            model_save_path: str,
            train_pcap: str,
            limit = np.inf,
            max_autoencoder_size: int = 10,
            FM_grace: int = 5000,
            AD_grace: int = 50000):

        self.kitsune = Kitsune(train_pcap, limit, max_autoencoder_size, FM_grace, AD_grace)

        loop = 0
        self.abnormal_thresh = -np.inf
        while True:
            rmse = self.kitsune.proc_next_packet()
            if rmse == -1:
                break

            if rmse > self.abnormal_thresh:
                self.abnormal_thresh = rmse

            loop += 1

        self.save_model(model_save_path)
        self.model_save_path = model_save_path

    def exam_pcap(self, pcap_file, limit = np.inf):
        self.kitsune = Kitsune(pcap_file, limit)
        with open(self.model_save_path, "rb") as f:
            self.abnormal_thresh = pkl.load(f)

            self.kitsune.AnomDetector.ensembleLayer = pkl.load(f)
            self.kitsune.AnomDetector.outputLayer = pkl.load(f)
            self.kitsune.AnomDetector.v = pkl.load(f)
            self.kitsune.AnomDetector.FM_grace_period = pkl.load(f)
            self.kitsune.AnomDetector.AD_grace_period = pkl.load(f)
            self.kitsune.AnomDetector.n_trained = pkl.load(f)

        loop = 0
        rmse_list = []
        while loop < limit:
            rmse = self.kitsune.proc_next_packet()
            if rmse == -1:
                break

            rmse_list.append(rmse)

        return rmse_list

    def get_feature(self, pcap_file, limit = np.inf):
        self.load_model(self.model_save_path)
