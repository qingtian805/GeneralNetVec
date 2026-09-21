import random
import string
import copy
import numpy as np

from scapy.packet import Raw, Packet

from .config import cfg

def decide_has_pkt(crafted_pkt_prob: float):
    """decide_has_pkt 用于确定一个位置是否拥有包，概率为 crafted_pkt_prob

    :param crafted_pkt_prob: 函数返回 True 的概率
    :return: 在此位置是否构建包
    :rtype: bool
    """
    r = random.random()
    if r < crafted_pkt_prob:
        return True
    else:
        return False

def random_bytes(length):
    tmp_str = ''.join(random.choice(string.printable) for _ in range(length))
    return bytes(tmp_str, encoding='utf-8')

class Unit:
    def __init__(self):
        """Unit类 是用于存储包特征的类,包含两个成员
        Unit.mal 恶意包成员,数据结构:0 正向相对时间 1 包含的构建包
        Unit.craft 构建包成员,数据结构:0 正向相对时间 1 协议层数 2 mtu
        一个Unit向量实例表征一条完整的流
        """
        self.data: np.ndarray = np.zeros((cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)), dtype=np.float64)
        self.mal: np.ndarray = self.data.reshape((-1, 2 + cfg.max_cft_pkt * 3))[:, -2:]
        self.craft: np.ndarray = self.data.reshape((-1, 2 + cfg.max_cft_pkt * 3))[:, : cfg.max_cft_pkt * 3].reshape((-1, cfg.max_cft_pkt, 3))

    def initialize(self):
        """initialize 负责初始化一个 Unit 类中的 恶意包特征和构建包特征

        在运行前请至少先通过 config 模块设置 pkt_list

        构建包拥有随机MTU (包长度)、随机的槽位 (时间)、随机的协议层数(不会超过对应恶意包的层数)，
        每个构造包最大拥有max_cft_pkt个包,并将原始包的时间间隔拉长 max_time_extend 倍，方便插入构造包
        """

        last_mal_time = cfg.last_end_time

        # 计算整个流的最大时间长度，+1 的原因是增加原始流量的时间
        crafted_pkt_prob = random.uniform(0, cfg.max_cft_pkt_prob)

        # 初始化流量时间序列，
        for i in range(cfg._pkt_num):
            # 随机延长包间隔时间，引入随机性，插入构建包
            itv = cfg.pkt_list[i].time - last_mal_time
            self.mal[i][0] = itv + itv * random.uniform(cfg.min_time_extend, cfg.max_time_extend)
            last_mal_time = cfg.pkt_list[i].time

            # Build cft packets
            k = sum(1 for _ in range(cfg.max_cft_pkt) if decide_has_pkt(crafted_pkt_prob))

            self.mal[i][1] = k
            for j in range(k):
                self.craft[i][j][0] = random.uniform(cfg.itv_min_lmt, cfg.itv_max_lmt)
                self.craft[i][j][1] = random.choice(np.arange(cfg.proto_min_lmt, cfg._proto_max_lmt[i] + 1))
                self.craft[i][j][2] = random.uniform(cfg.data_min_lmt, cfg.data_max_lmt[round(cfg._proto_max_lmt[i])])

        return self

    def rebuild(self) -> list[Packet]:
        """rebuild 将Unit重建为网络流量,重构结果为 ...X.craft[i] + X.mal[i] + X.craft[i+1] X.mal[i+1]...

        :return: 重建后的流量列表
        :rtype: list[scapy.Packet]
        """

        new_list = []
        last_pkt_time = cfg.last_end_time
        # i+j：遍历所有包
        for i in range(cfg._pkt_num):
            for j in range(int(round(self.mal[i][1]))):
                # 构造包复制原始封包
                pkt = copy.deepcopy(cfg.pkt_list[i])
                pkt_layers = pkt.layers()

                if pkt.haslayer(Raw):
                    pkt_layers.remove(Raw)

                pkt_layer_num = len(pkt_layers)
                target_layer_num = round(self.craft[i][j][1])

                if target_layer_num not in (1,2,3):
                    raise RuntimeError("Error when rebuilding Unit!")

                if pkt_layer_num < target_layer_num:
                    raise RuntimeError("Error when rebuilding Unit!")

                # 清除原有负载，不清除头，保证构造包与原始包发送到同一主机
                pkt[pkt_layers[target_layer_num - 1]].remove_payload()

                # 添加随机内容，内容长度被 MTU 限制
                pkt.add_payload(random_bytes(int(round(self.craft[i][j][2]))))
                pkt.time = last_pkt_time + self.craft[i][j][0]
                last_pkt_time = pkt.time
                new_list.append(pkt)
            # 在构造包之后添加原始封包
            mal_pkt = copy.deepcopy(cfg.pkt_list[i])
            mal_pkt.time = last_pkt_time + self.mal[i][0]
            last_pkt_time = mal_pkt.time
            new_list.append(mal_pkt)

        return new_list

    def restrict(self):
        """约束函数，用于约束向量数据，具体完成以下工作：

        1. 时间约束：流量包之间需要满足一个最小时间间隔，根据是原始包还是构建包具体遵守对象有所不同
            next: 流量包之间需要满足的最小时间间隔直接通过设置获取，原始包和构建包遵循相同约束？
        2. 长度约束：构建包可以改变包长度，但必须满足 cfg.data_min_lmt < x < cfg.data_max_lmt\
        3. 协议层数约束：为了能够构建构建包，其层数必须小于其对应的原始包
        """
        # start checking process
        for i in range(cfg._pkt_num):
            # check mal pkt time
            if self.mal[i][0] < cfg.itv_min_lmt:
                self.mal[i][0] = cfg.itv_min_lmt
            elif self.mal[i][0] > cfg.itv_max_lmt:
                self.mal[i][0] = cfg.itv_max_lmt

            # check craft pkt num
            if self.mal[i][1] > cfg.max_cft_pkt:
                self.mal[i][1] = cfg.max_cft_pkt
            elif self.mal[i][1] < 0.:
                self.mal[i][1] = 0.

            # cft checking process
            for j in range(round(self.mal[i][1])):
                # time check
                """
                last_end_time                          X.mal[x][0]
                    |-------------|---------|---------------|
                    cft_itv_lmt   target_itv   cft_itv_lmt
                """
                if self.craft[i][j][0] < cfg.itv_min_lmt:
                    self.craft[i][j][0] = cfg.itv_min_lmt
                elif self.craft[i][j][0] > cfg.itv_max_lmt:
                    self.craft[i][j][0] = cfg.itv_max_lmt

                # proto check
                if self.craft[i][j][1] > cfg._proto_max_lmt[i]:
                    self.craft[i][j][1] = cfg._proto_max_lmt[i]
                elif self.craft[i][j][1] < cfg.proto_min_lmt:
                    self.craft[i][j][1] = cfg.proto_min_lmt

                # mtu check
                if self.craft[i][j][2] > cfg.data_max_lmt[round(self.craft[i][j][1])]:
                    self.craft[i][j][2] = cfg.data_max_lmt[round(self.craft[i][j][1])]
                elif self.craft[i][j][2] < cfg.data_min_lmt:
                    self.craft[i][j][2] = cfg.data_min_lmt

                # prepare for next cft check loop
                prio_cft_time = self.mal[i][0] - self.craft[i][j][0]

            # prepare for next mal check loop
            prio_mal_time = self.mal[i][0]

    def __add__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            ret.data = self.data + other.data
        else:
            ret.data = self.data + other
        return ret
    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            ret.data = self.data - other.data
        else:
            ret.data = self.data - other
        return ret
    def __rsub__(self, other):
        return self.__sub__(other)

    def __mul__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            ret.data = self.data * other.data
        else:
            ret.data = self.data * other
        return ret
    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            ret.data = self.data / other.data
        else:
            ret.data = self.data / other
        return ret
    def __rtruediv__(self, other):
        return self.__truediv__(other)
