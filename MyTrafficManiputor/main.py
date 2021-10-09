import numpy as np
import pickle as pkl
from scapy.all import *
import argparse
from manipulator import Manipulator

parse = argparse.ArgumentParser()

#寻求改变的恶性流量
parse.add_argument('-m',
                   '--mal_pcap',
                   type=str,
                   required=True,
                   help="input malicious traffic (.pcap)")

#需要模仿的流量
parse.add_argument('-b',
                   '--mimic_set',
                   type=str,
                   required=True,
                   help="benign features to mimic (.npy)")

#特征归一化的pkl
# parse.add_argument('-n',
#                    '--normalizer',
#                    type=str,
#                    required=True,
#                    help="compiled feature normalizer (.pkl)")


# parse.add_argument('-i',
#                    '--init_pcap',
#                    type=str,
#                    default='./dataPGA/empty.pcap',
#                    help="preparatory traffic (ignore this if you don't need)")

#存放把恶意流量变好的pkl
parse.add_argument('-o',
                   '--sta_file',
                   type=str,
                   default='./dataPGA/statistics.pkl',
                   help="file saving the final statistics (.pkl)")

arg = parse.parse_args()

#生成Maniputator对象
m = Manipulator(arg.mal_pcap, arg.mimic_set)#, arg.init_pcap)#, arg.normalizer

max_iter, particle_num, local_grp_size = 1,1,1#6,3
#max_iter,particle_num,local_grp_size = 4,8,4
# max_iter,particle_num,local_grp_size = 5,10,5
# max_iter,particle_num,local_grp_size = 3,10,5
#max_iter,particle_num,local_grp_size = 1,1,1

m.change_particle_params(w=0.7298, c1=1.49618, c2=1.49618)
m.change_pso_params(max_iter=max_iter,
                    particle_num=particle_num,
                    grp_size=local_grp_size)
m.change_manipulator_params(grp_size=100,
                            min_time_extend=3.,
                            max_time_extend=6.,
                            max_cft_pkt=2,
                            max_crafted_pkt_prob=0.02)#0.01

m.save_configurations('./configurations.txt')

#debug
#tmp_pcap_file = "_crafted.pcap"
#m.process(tmp_pcap_file, arg.sta_file, limit=20)
tmp_pcap_file='1.pcap'
m.process(tmp_pcap_file,arg.sta_file, limit=np.Inf, heuristic=False)