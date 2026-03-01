import random
import string
import copy
import numpy as np

from scapy.packet import Raw

from net_alg import cfg

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
        Unit.mal 恶意包成员,数据结构:0 时间 1 包含的构建包
        Unit.craft 构建包成员,数据结构:0 时间 1 协议层数 2 mtu 
        一个Unit向量实例表征一条完整的流
        """
        grp_size = len(cfg.grp_list)
        self.mal = np.zeros((grp_size, 2), dtype=np.float64)
        self.craft = np.zeros((grp_size, cfg.max_cft_pkt, 3), dtype=np.float64)

    def initialize(self):
        """initialize 负责初始化一个 Unit 类中的 恶意包特征和构建包特征
        构建包拥有随机MTU (包长度)、随机的槽位 (时间)、随机的协议层数(不会超过对应恶意包的层数)，
        每个构造包最大拥有max_cft_pkt个包,并将原始包的时间间隔拉长 max_time_extend 倍，方便插入构造包
        
        :return: 构建的 X 和包含每个包协议层数的列表
        :rtype: tuple[Unit, list]
        """

        ics_time = 0  # accumulated increased ITA 初始时间对齐时间累加器
        last_mal_time = cfg.last_end_time

        grp_size = len(cfg.grp_list)
        # 计算整个流的最大时间长度，+1 的原因是增加原始流量的时间
        max_mal_itv = (cfg.grp_list[-1].time - cfg.last_end_time) * (cfg.max_time_extend + 1)
        # 初始化流量时间序列，
        for i in range(grp_size):
            # 计算距离上个包的时间（itv）
            itv = cfg.grp_list[i].time - last_mal_time
            last_mal_time = cfg.grp_list[i].time

            # 随机延长包间隔时间，引入随机性，插入构建包
            ics_time += random.uniform(cfg.min_time_extend, cfg.max_time_extend) * itv
            self.mal[i][0] = cfg.grp_list[i].time + ics_time

        # building slot map，构建包的位置：每个包之间都可能插入新包，且数量为 max_cft_pkt 倍
        # Slot_itv 是每个槽位的时间间隔
        slot_num = grp_size * cfg.max_cft_pkt
        slot_itv = max_mal_itv / slot_num

        # initializing crafted pkts 构建协议层数列表：将每个包的协议层数对应构建的列表
        crafted_pkt_prob = random.uniform(0, cfg.max_cft_pkt_prob)
        nxt_mal_no = 0
        
        # 根据最大协议层数逐个槽位构建构造包
        # nxt_mal_no 是下一个恶意包的序号,表示当前构造的包属于哪一个恶意包
        for i in range(slot_num):
            # 按照固定的时间间隔构建包，如果构建包的时间超过了恶意包的时间，则进入下一个槽位组，在最后一个恶意包位置退出
            slot_time = i * slot_itv + cfg.last_end_time
            if slot_time >= self.mal[nxt_mal_no][0]:
                nxt_mal_no += 1
                if nxt_mal_no == grp_size:
                    break
            # 如果决定不构建包，或当前槽位组包数量达到最大限制（但还有槽位），则继续
            if (not decide_has_pkt(crafted_pkt_prob)
                ) or self.mal[nxt_mal_no][1] == cfg.max_cft_pkt:
                continue
            # 构建包
            # mal[n][1] 记录的是构建包的数量，也是一个指向下一个构建包位置的指针
            cft_no = int(round(self.mal[nxt_mal_no][1]))

            if cfg.proto_max_lmt[nxt_mal_no] == 0.:
                continue

            # 计算时间、协议层数、随机MTU并填充
            mtu = cfg.data_max_lmt[round(cfg.proto_max_lmt[nxt_mal_no])]
            self.craft[nxt_mal_no][cft_no][0] = self.mal[nxt_mal_no][0] - slot_time
            self.craft[nxt_mal_no][cft_no][1] = random.choice(np.arange(cfg.proto_min_lmt, cfg.proto_max_lmt[nxt_mal_no]))
            self.craft[nxt_mal_no][cft_no][2] = random.uniform(cfg.data_min_lmt, mtu)

            # 更新对应恶意流量包的构造包数量
            self.mal[nxt_mal_no][1] += 1.

    def rebuild(self):
        """rebuild 将Unit重建为网络流量,重构结果为 ...X.craft[i] + X.mal[i] + X.craft[i+1] X.mal[i+1]...

        :param grp_list: 原始流量列表
        :return: 重建后的流量列表
        :rtype: list[scapy.Packet]
        """
        
        new_list = []
        grp_size = len(cfg.grp_list)
        # i+j：遍历所有包
        for i in range(grp_size):
            for j in range(int(round(self.mal[i][1]))):
                # 构造包复制原始封包
                pkt = copy.deepcopy(cfg.grp_list[i])
                pkt_layers = pkt.layers().remove(Raw)
                pkt_layer_num = len(pkt_layers)
                target_layer_num = round(self.craft[i][j][1])

                if target_layer_num not in (1,2,3):
                    raise RuntimeError("Error when rebuilding Unit!")

                if pkt_layer_num < target_layer_num:
                    raise RuntimeError("Error when rebuilding Unit!")
                
                # 清除原有负载，不清除头，保证构造包与原始包发送到同一主机
                pkt[pkt_layers[target_layer_num]].remove_payload()

                # 添加随机内容，内容长度被 MTU 限制
                pkt.add_payload(random_bytes(int(round(self.craft[i][j][2]))))
                pkt.time = self.mal[i][0] - self.craft[i][j][0]
                new_list.append(pkt)
            # 在构造包之后添加原始封包
            mal_pkt = copy.deepcopy(cfg.grp_list[i])
            mal_pkt.time = self.mal[i][0]
            new_list.append(mal_pkt)

        return new_list
    
    def restrict(self):
        
        max_mal_itv = (float(cfg.grp_list[-1].time) - cfg.last_end_time) * (cfg.max_time_extend + 1)
        mal_itv_lmt = max_mal_itv / cfg.fence_time_divider

        # calculate max mal time map
        max_mal_time = [max_mal_itv + cfg.last_end_time - mal_itv_lmt]
        # 优化：i 始终指向的后一个包, 直接取后一个包的时间, 停止到 1
        for i in range(cfg.grp_size - 1, 0, -1):
            max_time = min(max_mal_time[0], self.mal[i][0]) - mal_itv_lmt
            max_mal_time.insert(0, max_time)
            
        # start checking process
        prio_mal_time = cfg.last_end_time
        for i in range(cfg.grp_size):
            # check mal pkt time
            if self.mal[i][0] - prio_mal_time < mal_itv_lmt:
                self.mal[i][0] = prio_mal_time + mal_itv_lmt
            elif self.mal[i][0] > max_mal_time[i]:
                self.mal[i][0] = max_mal_time[i]
            
            # check craft pkt num
            if self.mal[i][1] > cfg.max_cft_pkt:
                self.mal[i][1] = cfg.max_cft_pkt
            elif self.mal[i][1] < 0.:
                self.mal[i][1] = 0.

            # check craft pkt time
            # Warning: cft pkt time is how long it is before the mal pkt
            #          So the check logic is a revers to mal time check which is timestamp
            cft_itv_lmt = (self.mal[i][0] - prio_mal_time) / cfg.cft_time_divider

            # build max cft time map
            max_cft_time = [cft_itv_lmt]
            next_cft_time = 0
            for j in range(round(self.mal[i][1]) - 1, 0, -1):
                next_cft_time = self.craft[i][j][0]
                max_time = max(max_cft_time[0], next_cft_time) + cft_itv_lmt
                max_cft_time.insert(0, max_time)

            # cft checking process
            prio_cft_time = prio_mal_time
            for j in range(round(self.mal[i][1])):
                # time check
                """
                last_end_time                          X.mal[x][0]
                    |-------------|---------|---------------|
                    cft_itv_lmt   target_itv   cft_itv_lmt
                """
                if (self.mal[i][0] - self.craft[i][j][0]) - prio_cft_time < cft_itv_lmt:
                    self.craft[i][j][0] = self.mal[i][0] - (prio_cft_time + cft_itv_lmt)
                elif self.craft[i][j][0] < max_cft_time[j]:
                    self.craft[i][j][0] = max_cft_time[j]

                # proto check
                if self.craft[i][j][1] > cfg.proto_max_lmt[i]:
                    self.craft[i][j][1] = cfg.proto_max_lmt[i]
                elif self.craft[i][j][1] < cfg.proto_min_lmt:
                    self.craft[i][j][1] = cfg.proto_min_lmt

                # mtu check
                if self.craft[i][j][2] > cfg.data_max_lmt:
                    self.craft[i][j][2] = cfg.data_max_lmt[round(self.craft[i][j][1])]
                elif self.craft[i][j][2] < cfg.data_min_lmt:
                    self.craft[i][j][2] = cfg.data_min_lmt

                # prepare for next cft check loop
                prio_cft_time = self.mal[i][0] - self.craft[i][j][0]
            
            # prepare for next mal check loop
            prio_mal_time = self.mal[i][0]

    
if __name__ == "__main__":
    from scapy.all import *
    from net_alg import NetAlg
    with open("./test.pcap", "rb") as f:
        grp_list = rdpcap(f)

    alg = NetAlg(grp_list, grp_list[-1].time)
    
    t = Unit()

    print(t.mal)
    print(t.craft)

    t.restrict()

    print(t.mal)
    print(t.craft)

    r = t.rebuild()

    for i in r:
        i.show()

    # for name, value in cfg.__dict__.items():
    #     print(name, value)
    
    # print()

    # for name, value in alg.__dict__.items():
    #     print(name, value)
    
    # print(cfg == alg.cfg)

    # cfg.grp_size = 20

    # print(cfg == alg.cfg)
