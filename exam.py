import numpy as np
import pickle as pkl
from net_vec.examinator import Examinator

class Exam:
    def __init__(
            self,
            examinator: Examinator,
            sta_file: str
            ):
        self.examinator = examinator
        self.ad_threshold = self.examinator.abnormal_thresh
        self.sta_file = sta_file

    def _detection_evasion_rate(self):
        origin_detectable = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        manipu_undetected = len(self.manipu_rmse[self.manipu_rmse < self.ad_threshold])

        return 1 - manipu_undetected / origin_detectable

    def _malicious_evasion_rate(self):
        with open(self.sta_file, "rb") as f:
            x_list = pkl.load(f)

        mal_pos = []
        for x in x_list:
            for i in range(len(x.mal)):
                mal_pos += [False] * round(x.mal[i][1])
                mal_pos += [True]

        origin_detectable = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        mal_rmse = self.manipu_rmse[mal_pos]
        mal_mani_undetected = len(mal_rmse[mal_rmse < self.ad_threshold])

        return 1 - mal_mani_undetected / origin_detectable

    def _probability_decline_rate(self):
        origin_mean = np.mean(self.origin_rmse)
        manipu_mean = np.mean(self.manipu_rmse)

        return 1 - manipu_mean / origin_mean

    def _malicious_mimicry_rate(self):
        pass

    def exam(
            self,
            origin_pcap_file: str,
            manipu_pcap_file: str,
            limit = np.inf
            ):
        self.origin_rmse = np.array(self.examinator.exam_pcap(origin_pcap_file, limit))
        self.manipu_rmse = np.array(self.examinator.exam_pcap(manipu_pcap_file, limit))

        der = self._detection_evasion_rate()
        mer = self._malicious_evasion_rate()
        pdr = self._probability_decline_rate()

        print(f"DER: {der}")
        print(f"MER: {mer}")
        print(f"PDR: {pdr}")
