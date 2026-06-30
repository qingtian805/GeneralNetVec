import numpy as np
from scapy.plist import PacketList
from scapy.packet import Packet
from typing import Union

class Examinator:
    def __init__(self, model_save_path: str):
        """
        离线评估器类, 离线评估器可以完成模型全生命周期维护, 并使用该模型完成针对离线流量样本的评估工作

        在实现构造函数时, 结合后续的 load_model, 在构造函数内实现可选的模型载入操作
        """
        self.abnormal_thresh = -np.inf
        self.model_save_path = None

    def load_model(model_save_path: str):
        """
        负责实现从指定路径加载模型的操作
        """
        pass

    def save_model(self, model_save_path: str):
        """
        负责向指定路径保存模型, 暴露此 API 考虑另存为需求
        """
        pass

    def train_model(self, model_save_path: str, train_pcap: str, *args, **kwargs):
        """
        使用 train_pcap 训练模型，并将模型存入 model_save_path。
        在实现时后跟对应模型的超参数设置

        :param model_save_path: 模型保存路径
        :param train_pcap: 训练模型的 pcap 数据集
        """
        pass

    def exam_pcap(self, pcap_file: str, limit = np.inf):
        """
        评价目标 pcap 文件，返回 rmse 列表。可以使用 limit 评价部分内容

        :param pcap_file: 被评价的 pcap 文件
        :param limit: 如果需要评价部分内容,则设置本项目
        """
        pass

class OLExaminator(Examinator):
    def __init__(self):
        """
        在线评估器类, 内容与离线评估器类似, 完成模型全生命周期管理

        可以用这样区分两者: 在线评估器应该包含 exam_pkt 函数, 而非 exam_pcap 函数
        """
        super().__init__()
        del self.exam_pcap

    def prepare_exam(self):
        """
        完成一些在评估之前的初始化操作, 将这些操作从后续提取出来, 提高速度
        """
        pass

    def exam_pkt(self, pkt_list: Union[list[Packet], PacketList]):
        """
        评估一个 scapy.plist.PacketList 类
        """
        pass