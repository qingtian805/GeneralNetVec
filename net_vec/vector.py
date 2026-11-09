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

def max_min_normalize(x):
    return (x - cfg._min_vec) / (cfg._max_vec - cfg._min_vec)

def max_min_denormalize(x):
    return x * (cfg._max_vec - cfg._min_vec) + cfg._min_vec

class Unit:
    rng = np.random.default_rng()

    def denomalize(self):
        self.data = max_min_denormalize(self.data)
        return self

    def initialize(self):
        """initialize 将 Unit 类中的数据进行原地 [0,1] 随机化

        """
        self.rng.random(size=(cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)),
                        dtype=np.float64,
                        out=self.data)
        return self

    def __init__(self):
        """Unit类 是用于存储包特征的类
        基础类型使用单条向量表示, 另外包含两个可读性视图：
        Unit.mal 恶意包成员,数据结构:0 正向相对时间 1 包含的构建包
        Unit.craft 构建包成员,数据结构:0 正向相对时间 1 协议层数 2 mtu

        一个Unit向量实例表征一条完整的流

        :param initialize: 初始化符号，如果设置为 True，则进行随机初始化，否则向量为全0
        """
        self.data: np.ndarray = np.zeros((cfg._pkt_num * (2 + cfg.max_cft_pkt * 3)), dtype=np.float64)
        self.mal: np.ndarray = self.data.reshape((-1, 2 + cfg.max_cft_pkt * 3))[:, -2:]
        self.craft: np.ndarray = self.data.reshape((-1, 2 + cfg.max_cft_pkt * 3))[:, : cfg.max_cft_pkt * 3].reshape((-1, cfg.max_cft_pkt, 3))

    def rebuild(self) -> list[Packet]:
        """rebuild 将Unit重建为网络流量,重构结果为 ...X.craft[i] + X.mal[i] + X.craft[i+1] X.mal[i+1]...

        :return: 重建后的流量列表
        :rtype: list[scapy.Packet]
        """
        data = max_min_denormalize(self.data)

        new_list = []
        last_pkt_time = cfg._last_end_time
        # i+j：遍历所有包
        for i in range(cfg._pkt_num):
            p = (2 + cfg.max_cft_pkt * 3) * i
            for j in range(int(round(
                    data[p + cfg.max_cft_pkt * 3 + 1]))): # mal[i][1]

                # 构造包复制原始封包
                pkt = copy.deepcopy(cfg._pkt_list[i])
                pkt_layers = pkt.layers()

                if pkt.haslayer(Raw):
                    pkt_layers.remove(Raw)

                pkt_layer_num = len(pkt_layers)
                target_layer_num = round(
                    data[p + 3 * j + 1])  # craft[i][j][1]

                if target_layer_num not in (1,2,3):
                    raise RuntimeError("Error when rebuilding Unit!")

                if pkt_layer_num < target_layer_num:
                    raise RuntimeError("Error when rebuilding Unit!")

                # 清除原有负载，不清除头，保证构造包与原始包发送到同一主机
                pkt[pkt_layers[target_layer_num - 1]].remove_payload()

                # 添加随机内容，内容长度被 MTU 限制
                pkt.add_payload(random_bytes(int(round(
                    data[p + 3 * j + 2])))) # craft[i][j][2]
                pkt.time = (last_pkt_time + data[p + 3 * j])  # craft[i][j][0]
                last_pkt_time = pkt.time
                new_list.append(pkt)
            # 在构造包之后添加原始封包
            mal_pkt = copy.deepcopy(cfg._pkt_list[i])
            mal_pkt.time = last_pkt_time + data[p + cfg.max_cft_pkt * 3] # mal[i][0]
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
        self.data[self.data < 0.] = 0.
        self.data[self.data > 1.] = 1.

    def __add__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.add(self.data, other.data, out=ret.data)
        else:
            np.add(self.data, other, out=ret.data)
        return ret
    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.add(self.data, -other.data, out=ret.data)
        else:
            np.add(self.data, -other, out=ret.data)
        return ret
    def __rsub__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.add(-self.data, other.data, out=ret.data)
        else:
            np.add(-self.data, other, out=ret.data)

    def __mul__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.multiply(self.data, other.data, out=ret.data)
        else:
            np.multiply(self.data, other, out=ret.data)
        return ret
    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.divide(self.data, other.data, out=ret.data)
        else:
            np.divide(self.data, other, out=ret.data)
        return ret
    def __rtruediv__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.divide(other.data, self.data, out=ret.data)
        else:
            np.divide(other, self.data, out=ret.data)
        return ret

    def __pow__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.pow(self.data, other.data, out=ret.data)
        else:
            np.pow(self.data, other, out=ret.data)
        return ret
    def __rpow__(self, other):
        ret = Unit()
        if isinstance(other, Unit):
            np.pow(other.data, self.data, out=ret.data)
        else:
            np.pow(other, self.data, out=ret.data)
        return ret

    def __neg__(self):
        ret = Unit()
        np.negative(self.data, out=ret.data)
        return ret
