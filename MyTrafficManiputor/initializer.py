"""
                                 ics_time                       
      |-----------------|+++++++++++++++++++++++|
last_end_time     groupList[-1].time      last_end_time(*) 
                                          cur_end_time
"""

from scapy.all import *
import random
import numpy as np
from utils import Unit


#生成crafted_pkt_prob比例的变异流量
def decide_has_pkt(crafted_pkt_prob):
    r = random.random()
    if r < crafted_pkt_prob:
        return True
    else:
        return False


def initialize(
    grp_size,  # Number of pkts in each group
    last_end_time,#上一次结束的时间
    groupList,  # Pcap info in current group
    max_time_extend,  # maximum time overhead (l_t)#不能超过
    max_cft_pkt,  # maximum crafted traffic overhead (l_c)#不能超过5
    min_time_extend, #不能少于
    max_crafted_pkt_prob,#流量变异率
):

    #X为X.mal(100*2)+X.craft(100*5*3)
    X = Unit(grp_size, max_cft_pkt)  # position vector

    ics_time = 0  # accumulated increased ITA

    #X.mal[i][0]为生成的随机时间（在l_t范围内）
    for i in range(grp_size):
        if i == 0:
            itv = groupList[i].time - last_end_time
        else:
            itv = groupList[i].time - groupList[i - 1].time
        # ics_time += random.uniform(0,max_time_extend)*itv
        ics_time += random.uniform(min_time_extend, max_time_extend) * itv
        #可以修改的时间
        X.mal[i][0] = groupList[i].time + ics_time

   #群时间最大能变异多少（+1是因为有原来的流量）
    max_mal_itv = (groupList[-1].time - last_end_time) * (max_time_extend + 1)

    # building slot map
    slot_num = grp_size * max_cft_pkt #1000*l_c(可以容纳变异流量的最大个数)*（每一组的size*最大变异量）
    slot_itv = max_mal_itv / slot_num #（平均间隔时间）（时间片）


    # initializing crafted pkts
    #变异率
    crafted_pkt_prob = random.uniform(0, max_crafted_pkt_prob)
    nxt_mal_no = 0

    proto_max_lmt = []  # maximum protocol layer number（最大协议层数）
    for i in range(grp_size):
        if groupList[i].haslayer(TCP) or groupList[i].haslayer(
                UDP) or groupList[i].haslayer(ICMP):
            proto_max_lmt.append(3.)
        elif groupList[i].haslayer(IP) or groupList[i].haslayer(
                IPv6) or groupList[i].haslayer(ARP):
            proto_max_lmt.append(2.)
        elif groupList[i].haslayer(Ether):
            proto_max_lmt.append(1.)
        else:
            proto_max_lmt.append(0.)


    for i in range(slot_num):
        #生成group中每个包的随机时间
        #如果时间片超过了X.mal[i][0]，nxt_mal_no就+1
        slot_time = i * slot_itv + last_end_time
        if slot_time >= X.mal[nxt_mal_no][0]:
            nxt_mal_no += 1
            if nxt_mal_no == grp_size:
                break
        #有crafted_pkt_prob百分比的mal（100*2）或者矩阵第二维会变成max_cft_pkt（l_c）==5跳过   
        if (not decide_has_pkt(crafted_pkt_prob)) or X.mal[nxt_mal_no][1] == max_cft_pkt:#不变异或者越界
            continue
        #这个包本身就会改变，且会新加变异包
        #变异的流量处理，初始cft_no=0，表明变异一次，cft_no越高越少
        cft_no = int(round(X.mal[nxt_mal_no][1]))

        if proto_max_lmt[nxt_mal_no] == 3.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1., 2., 3.])
            #mtu最大传输单元
            mtu = 1460
        elif proto_max_lmt[nxt_mal_no] == 2.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1., 2.])
            mtu = 1480
        elif proto_max_lmt[nxt_mal_no] == 1.:
            X.craft[nxt_mal_no][cft_no][1] = 1.
            mtu = 1500
        else:
            continue

        X.craft[nxt_mal_no][cft_no][0] = X.mal[nxt_mal_no][0] - slot_time#超过时间片的时间
        X.craft[nxt_mal_no][cft_no][2] = random.uniform(0, mtu)#最大传输单元
        #print(X.craft[nxt_mal_no][cft_no][2])
        X.mal[nxt_mal_no][1] += 1.#表明+新变异包数

    return X, proto_max_lmt
