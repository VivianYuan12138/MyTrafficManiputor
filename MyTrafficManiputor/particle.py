from numpy.core.fromnumeric import shape
from initializer import initialize
from rebuilder import rebuild
from BytesEncodingExtractor.BETools import *
import numpy as np
import copy
import random
from utils import *
from updater import generate_V, update_X
import time
from scapy.all import *
a=0

class Particle:
    def __init__(
            self,
            last_end_time,  # initializer
            groupList,  # initializer
            max_time_extend,  # initializer
            max_cft_pkt,  # initializer
            min_time_extend,
            max_crafted_pkt_prob,
            show_info=False):

        self.show_info = show_info

        self.grp_size = len(groupList)
        self.groupList = groupList
        self.max_cft_pkt = max_cft_pkt
        self.max_time_extend = max_time_extend
        self.last_end_time = last_end_time
        self.proto_max_lmt = []

        self.pktList = None
        self.feature = None
        self.all_feature = None
        self.local_FE = None

        if self.show_info:
            print("----@Particle: Initializing...")

        #PSO算法中X和V的初始值
        # initialize X and V
        #proto_max_lmt最大协议层
        #X.mal X.craft
        self.X, self.proto_max_lmt = initialize(self.grp_size, last_end_time,
                                                groupList, max_time_extend,
                                                max_cft_pkt, min_time_extend,
                                                max_crafted_pkt_prob)
        #初始化两个矩阵V.mal V.craft
        self.V = Unit(self.grp_size, self.max_cft_pkt)

        self.indi_best_X = None
        self.indi_best_dis = -1.
        self.dis = -1.



    def evaluate(self, mimic_set):#, nstat):#, knormer):
        global a
      # if self.show_info:
        print("----@Particle: Evaluate distance...")

        #把X里面的内容转换成pkt
        self.pktList = rebuild(self.grp_size, self.X, self.groupList)#,tmp_pcap_file='1.pcap')
        mal_pos = []
        #mal_ori=[]
        cft_num = 0#每个包变异的个数
        for i in range(self.grp_size):
            cft_num += int(round(self.X.mal[i][1]))
            #print("##Debug##", "X.mal[i][1]", i,self.X.mal[i][1])
            mal_pos.append(i + cft_num)#变成了第几个包、第几个包0  4  6这样的
            #mal_ori.append(self.pktList[i + cft_num])
        #if a==0:
            #wrpcap('00.pcap',mal_ori)
        #a+=1
        t1 = time.perf_counter()
        #print(len(mal_ori)) 100
        #self.pktList不等
        #self.local_FE = Kitsune(self.pktList, np.Inf, True)
        #self.local_FE.FE.nstat = safelyCopyNstat(nstat, True)
        self.feature, self.all_feature = RUNBE(self.pktList,origin_pos=mal_pos)
        self.feature = np.asarray(self.feature)
        #print("shape",shape(self.feature))

        #为什么设置这些地方为0
        # self.feature[:, 33:50:4] = 0.
        # self.feature[:, 83:100:4] = 0.

        #norm_feature = knormer.transform(self.feature)
        norm_feature=self.feature
        #相等了

        t2 = time.perf_counter()
        FE_time = t2 - t1

        self.dis = 0

        #print(mimic_set)
        print('self.grp_size ::',self.grp_size)
        for i in range(self.grp_size):
            # print("norm",norm_feature.shape)#100*64*256？？
            # print("mimic_set",mimic_set.shape)#1000*64*256
            #这里的问题在于对矩阵距离的处理，这里我以一个包为单位,表示这个包对距离1000个包里面最近的那个包，以他为距离优化
            list=[]
            tmp=norm_feature[i] - mimic_set #(1000, 64, 256)
            for j in range(len(tmp)):
                list.append(np.linalg.norm(tmp[j].flatten()))
            #print('list',len(list))
            #print('min(list)',min(list))
            self.dis+=min(list)
            
            #self.dis += min(np.linalg.norm(norm_feature[i] - mimic_set,
                                        #  axis=1))
            #print("dis:",self.dis)
        if self.show_info:
            print("----@Particle: distance is", self.dis)

        # Update individual best (check to see if the current position is an individual best)
        if self.dis < self.indi_best_dis or self.indi_best_dis == -1:
            self.indi_best_X = self.X
            self.indi_best_dis = self.dis

        return FE_time

    # update new particle velocity
    def update_v(self, glob_best_X, w, c1, c2):

        if self.show_info:
            print("----@Particle: Update social velocity...")
        soc_V = generate_V(self.X, glob_best_X, self.grp_size,
                           self.max_cft_pkt)

        if self.show_info:
            print("----@Particle: Update cognitive velocity...")
        # print("self.indi_best_X",self.indi_best_X)
        cog_V = generate_V(self.X, self.indi_best_X, self.grp_size,
                           self.max_cft_pkt)

        r1 = random.random()
        r2 = random.random()

        # compute V
        self.V.mal = w * self.V.mal + c1 * r1 * cog_V.mal + c2 * r2 * soc_V.mal
        self.V.craft = w * self.V.craft + c1 * r1 * cog_V.craft + c2 * r2 * soc_V.craft

    # update the particle position based off new velocity updates
    def update_x(self):
        if self.show_info:
            print("----@Particle: Update position...")

        update_X(self.X, self.V, self.grp_size, self.max_cft_pkt,
                 self.last_end_time, self.groupList, self.max_time_extend,
                 self.proto_max_lmt)
