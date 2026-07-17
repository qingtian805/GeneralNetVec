import numpy as np
import pickle as pkl
from net_vec.examinator import Examinator

class Exam:
    def __init__(
            self,
            examinator: Examinator,
            sta_file: str
            ):
        """测试流程控制器

        :param examinator: 一个使用 net_vec.examinator.Examinator 实现的测试器
        :param sta_file: 在变异过程中生成的状态记录文件，用于计算指标
        """
        self.examinator = examinator
        self.ad_threshold = self.examinator.abnormal_thresh
        self.sta_file = sta_file

    def _detection_evasion_rate(self):
        """ 计算对抗样本中（包含构建包）有多少逃脱了检测 """
        positive_origin = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        positive_manipu = len(self.manipu_rmse[self.manipu_rmse > self.ad_threshold])

        return 1 - positive_manipu / positive_origin

    def _malicious_evasion_rate(self):
        """ 计算对抗样本中（不包含构建包）有多少逃脱了检测 """
        with open(self.sta_file, "rb") as f:
            x_list = pkl.load(f)

        mal_pos = []
        for x in x_list:
            for i in range(len(x.mal)):
                mal_pos += [False] * round(x.mal[i][1])
                mal_pos += [True]

        positive_origin = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        mal_rmse = self.manipu_rmse[mal_pos]
        positive_mal_manipu = len(mal_rmse[mal_rmse > self.ad_threshold])

        return 1 - positive_mal_manipu / positive_origin

    def _probability_decline_rate(self):
        """ 计算对抗之后样本在目标检测器中恶意概率（异常置信度）降低了多少 """
        origin_mean = np.mean(self.origin_rmse)
        manipu_mean = np.mean(self.manipu_rmse)

        return 1 - manipu_mean / origin_mean

    def _malicious_mimicry_rate(self):
        return "pass"

    def dump_result(self, dump_file_prefix: str):
        with open(f"{dump_file_prefix}.txt", "w") as f:
            f.writelines((f"DER(gb): {self.der}",
                          f"MER(gb): {self.mer}",
                          f"PDR(gb): {self.pdr}",
                          f"MMR(gb): {self.mmr}",
                          f"rmse file saved at {dump_file_prefix}.pkl"))

        with open(f"{dump_file_prefix}.pkt", "wb") as f:
            pkl.dump(self.origin_rmse, f)
            pkl.dump(self.manipu_rmse, f)

    def cal_metrics(self):
        self.der = self._detection_evasion_rate()
        self.mer = self._malicious_evasion_rate()
        self.pdr = self._probability_decline_rate()
        self.mmr = self._malicious_mimicry_rate()

        print(f"DER: {self.der}")
        print(f"MER: {self.mer}")
        print(f"PDR: {self.pdr}")
        print(f"MMR: {self.mmr}")


    def exam(
            self,
            origin_pcap_file: str,
            manipu_pcap_file: str,
            limit = np.inf
            ):
        self.origin_rmse = np.array(self.examinator.exam_pcap(origin_pcap_file, limit))
        self.manipu_rmse = np.array(self.examinator.exam_pcap(manipu_pcap_file, limit))

        self.cal_metrics()
