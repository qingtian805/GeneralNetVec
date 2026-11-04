import numpy as np
import matplotlib.pyplot as plt
import pickle as pkl
from net_vec import Examinator, cfg

class Exam:
    def __init__(
            self,
            examinator: Examinator,):

        """测试流程控制器，初始化过程完成测试模型加载

        :param examinator: 一个使用 net_vec.examinator.Examinator 实现的测试器
        """
        self.examinator = examinator
        self.ad_threshold = self.examinator.abnormal_thresh
        self.limit = np.inf

    def exam_origin_pcap_file(
            self,
            origin_pcap_file: str,
            mimic_file: str | None = None,
            limit: float = np.inf,):

        """
        设置即将被测评的流量，会计算变异流量的异常置信度

        :prarm origin_pcap_file: 变异使用的原始流量文件
        :param mimic_file: 在变异过程中使用的模仿特征，用于计算白盒 MMR 指标
        :param limit: 在测试中要使用的包数量
        """
        if self.limit != np.inf:
            self.limit = min(limit, self.limit)

        self.mimic_file = mimic_file

        self.origin_rmse = np.array(self.examinator.exam_pcap(origin_pcap_file, self.limit))

    def exam_manipu_pcap_file(
            self,
            manipu_pcap_file: str,
            sta_file: str,
            limit: float = np.inf):

        """
        设置即将被测评的变异流量

        :param manipu_pcap_file: 变异流量文件路径
        :param sta_file: 变异过程中生成的状态记录文件
        :param limit: 在测试中要使用的包数量
        """
        if limit != np.inf:
            self.limit = min(limit, self.limit)

        self.manipu_rmse = np.array(self.examinator.exam_pcap(manipu_pcap_file, self.limit))

        with open(sta_file, "rb") as f:
            x_list = pkl.load(f)

        self.mal_pos = []
        for x in x_list:
            for i in range(int(len(x.mal))):
                self.mal_pos += [False] * int(round(x.mal[i][1]))
                self.mal_pos += [True]

        with open(sta_file, "rb") as f:
            self.manipu_feature = pkl.load(f)


    def _detection_evasion_rate(self):
        """ 计算对抗样本中（包含构建包）有多少逃脱了检测 """
        positive_origin = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        positive_manipu = len(self.manipu_rmse[self.manipu_rmse > self.ad_threshold])

        return 1 - positive_manipu / positive_origin

    def _malicious_evasion_rate(self):
        """ 计算对抗样本中（不包含构建包）有多少逃脱了检测 """

        positive_origin = len(self.origin_rmse[self.origin_rmse > self.ad_threshold])
        mal_rmse = self.manipu_rmse[self.mal_pos]
        positive_mal_manipu = len(mal_rmse[mal_rmse > self.ad_threshold])

        return 1 - positive_mal_manipu / positive_origin

    def _probability_decline_rate(self):
        """ 计算对抗之后样本在目标检测器中恶意概率（异常置信度）降低了多少 """
        origin_mean = np.mean(self.origin_rmse)
        manipu_mean = np.mean(self.manipu_rmse)

        return 1 - manipu_mean / origin_mean

    def _malicious_mimicry_rate(self):
        if self.mimic_file is None:
            return "pass"

        mimic_feat = np.load(self.mimic_file)

        mal_feat = np.load(orgi_feat_file)[:self.len]
        mut_feat = self.feature_list

        with open(knormer_file, 'rb') as f:
            knormer = pkl.load(f)

        mal_feat = knormer.transform(mal_feat)
        mut_feat = knormer.transform(mut_feat)
        org_dis = 0.
        mut_dis = 0.

        for i in range(mal_feat.shape[0]):
            org_dis += max(np.linalg.norm(mal_feat[i] - mimic_feat,
                                            axis=1))
            mut_dis += min(np.linalg.norm(mut_feat[i] - mimic_feat,
                                            axis=1))
        mmr = 1. - mut_dis / org_dis
        print("Feature Changed:")
        print("  Before:", org_dis, "After:", mut_dis)
        print("  MMR:", mmr)
        return mmr

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

    def plt_rmse(self):

        mal_rmse = self.manipu_rmse[self.mal_pos]

        length = len(self.origin_rmse)

        x = np.arange(0, length, 1)
        plt.figure()
        # plt.scatter(x, np.log(self.org_rmse_list), s=16,  c='#8A977B',alpha=0.5,label="Before")
        # plt.scatter(x, np.log(self.rmse_list), s=16, c='#FE4365',alpha=0.5,label="After")
        # plt.plot(x,[np.mean(np.log(self.org_rmse_list))]*self.len,c='#8A977B',alpha=0.5)
        # plt.plot(x,[np.mean(np.log(self.rmse_list))]*self.len, c='#FE4365',alpha=0.5)

        plt.scatter(x,
                    self.origin_rmse,
                    s=12,
                    c='#8A977B',
                    alpha=0.5,
                    label="Before")
        plt.scatter(x,
                    mal_rmse,
                    s=12,
                    c='#FE4365',
                    alpha=0.5,
                    label="After")
        plt.plot(x, [np.mean(self.origin_rmse)] * length,
                    c='#8A977B',
                    alpha=0.3,
                    linewidth=4)
        plt.plot(x, [np.mean(mal_rmse)] * length,
                    c='#FE4365',
                    alpha=0.3,
                    linewidth=4)
        plt.plot(x, [self.examinator.abnormal_thresh] * length,
                    c='black',
                    linewidth=2,
                    label="AD_threshold")
        plt.title("RMSE change and mean")
        plt.xlabel('pkt no.')
        plt.ylabel('RMSE in Kitsune')
        plt.legend(loc='upper right')

        # plt.savefig('./tmp.pdf')
        plt.show()

    def exam(
            self,
            origin_pcap_file: str,
            manipu_pcap_file: str,
            sta_file: str,
            mimic_file: str | None = None,
            limit: float = np.inf,
            ):
        self.exam_origin_pcap_file(origin_pcap_file, mimic_file, limit)
        self.exam_manipu_pcap_file(manipu_pcap_file, sta_file, limit)

        self.cal_metrics()
