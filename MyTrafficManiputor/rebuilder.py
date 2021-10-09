from scapy.all import *
import random
import string
import numpy as np


def random_bytes(length):
    tmp_str = ''.join(random.choice(string.printable) for _ in range(length))
    return bytes(tmp_str, encoding='utf-8')


def rebuild(
    grp_size,
    X,
    groupList,
    #tmp_pcap_file #???离谱吧这个加不加应该不会有影响吧
):

    newList = []

    for i in range(grp_size):

        for j in range(int(round(X.mal[i][1]))):
            #对于新增的包，他是通过复制上一个的状态，然后进行改变的，本质上是要发生分裂的包改变了三个参数
            pkt = copy.deepcopy(groupList[i])
            #print('X.mal[i][1])',X.mal[i][1])
            #print(X.craft[i][j][1])
            if round(X.craft[i][j][1]) == 1:
                if groupList[i].haslayer(Ether):
                    pkt[Ether].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")

            elif round(X.craft[i][j][1]) == 2:
                if groupList[i].haslayer(IP):
                    pkt[IP].remove_payload()
                elif groupList[i].haslayer(IPv6):
                    pkt[IPv6].remove_payload()
                elif groupList[i].haslayer(ARP):
                    pkt[ARP].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")
            elif round(X.craft[i][j][1]) == 3:
                if groupList[i].haslayer(ICMP):
                    pkt[ICMP].remove_payload()
                elif groupList[i].haslayer(TCP):
                    pkt[TCP].remove_payload()
                elif groupList[i].haslayer(UDP):
                    pkt[UDP].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")
            else:
                raise RuntimeError("Error in rebuilder!")
            #print(int(round(X.craft[i][j][2])))
            pkt.add_payload(random_bytes(int(round(X.craft[i][j][2]))))
            pkt.time = X.mal[i][0] - X.craft[i][j][0]
            newList.append(pkt)

        mal_pkt = copy.deepcopy(groupList[i])
        mal_pkt.time = X.mal[i][0]
        newList.append(mal_pkt)

    #wrpcap(tmp_pcap_file, newList)
    return newList
