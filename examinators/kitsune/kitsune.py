import pickle as pkl
import os.path as path
import numpy as np
from scapy.plist import PacketList

from .Kitsune.KitNET.KitNET import KitNET
from .Kitsune.FeatureExtractor import FE
from .Kitsune.netStat import netStat
from net_vec import Examinator, OLExaminator

class KitsuneExam(Examinator):
    def __init__(
            self,
            model_save_path: str = None):
        """Kitsune 模型测试器

        Kitsune 模型是一个用于物联网的轻量级 NIDS，基于多个小型自编码器集合。

        :param model_save_path: 模型保存路径，如果指定，测试器会尝试从路径中加载模型。
                                这与构造之后自行调用 load_model() 是一样的
        """
        self.model_save_path: str | None = model_save_path
        """ 当前内存中的模型对应的文件位置 """

        if model_save_path is not None and path.isfile(model_save_path):
            try:
                self.load_model()
                return
            except Exception:
                pass

        self.KitNET: KitNET  = None
        self.FE: FE          = None
        self.abnormal_thresh = -np.inf
        self.n_trained: int  = -1

    def save_model(self, model_save_path: str):
        """将模型另存为到 model_save_path 中

        文件包含：
        1. 异常门限参数
        2. 数据集特征数
        3. Feature Mapper 参数
        4. 聚合层参数（多个小AE）
        5. 输出层参数（大AE）
        6. 运行状态（三个参数FM_grace, AD_grace, n_trained）
        """
        with open(model_save_path, "wb") as f:
            pkl.dump(self.abnormal_thresh, f)
            pkl.dump(self.FE.get_num_features(), f)

            pkl.dump(self.KitNET.v, f)
            pkl.dump(self.KitNET.ensembleLayer, f)
            pkl.dump(self.KitNET.outputLayer, f)
            pkl.dump(self.KitNET.FM_grace_period, f)
            pkl.dump(self.KitNET.AD_grace_period, f)
            pkl.dump(self.KitNET.n_trained, f)

    def load_model(self, model_save_path: str = None):
        if model_save_path is not None:
            self.model_save_path = model_save_path

        with open(self.model_save_path, "rb") as f:
            self.abnormal_thresh = pkl.load(f)

            self.KitNET = KitNET(pkl.load(f), feature_map=pkl.load(f))
            self.KitNET.ensembleLayer = pkl.load(f)
            self.KitNET.outputLayer = pkl.load(f)
            self.KitNET.FM_grace_period = pkl.load(f)
            self.KitNET.AD_grace_period = pkl.load(f)
            self.n_trained = self.KitNET.n_trained = pkl.load(f)

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
            train_dataset: str,
            max_autoencoder_size: int = 10,
            FM_grace: int = 5000,
            AD_grace: int = 50000):
        """支持的数据集类型：pcap tsv

        Kitsune 的训练分为三个阶段（准确的说，两个）:
        1. 0 ~ FM_grace: 训练模型寻找特征之间的联系，将相关特征映射到相同 AE
        2. FM_grace + 1 ~ AD_grace + FM_grace: 用于训练模型的多个 AE 集合（KitNET）
        3. AD_grace ~ limit: 运行阶段

        :param model_save_path: 模型保存路径，使用 pickle 库保存，最好带 .pkl 后缀
        :param train_dataset: 用于训练的流量数据
        :param max_autoencoder_size: 定义 Kitsune 使用最多多少个
        :param FM_grace: 见函数描述
        :param AD_grace: 见函数描述
        """

        limit = float(FM_grace + AD_grace + 1)
        self.FE = FE(train_dataset, limit)
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

    def __init__(self, pkt_list = None):
        self.nstat = netStat(np.nan, 16777216, 131072)
        self.parse_type = "scapy"

        if pkt_list is not None:
            self.set_pkt_list(pkt_list)

class OLKitsuneExam(KitsuneExam, OLExaminator):
    def __init__(self, model_save_path: str = None):
        super().__init__(model_save_path)

    def prepare_exam(self):
        self.FE = FEOL() # type: FEOL

    def exam_pkt(self, pkt_list: PacketList):
        """
        本类是在线评估器, 为了提升速度, 不会检查使用 Feture Extractor 是否为在线版(即处理对象是 pkt_list)
        这些步骤在函数 prepare_exam 中完成, 请在首次执行 exam_pkt 之前执行
        """
        # Set kitsune status, no restore
        self.FE.set_pkt_list(pkt_list)

        rmse_list = []
        while True:
            rmse = self._run_model()

            if rmse == -1:
                break
            rmse_list.append(rmse)

        return rmse_list
