from sklearn.preprocessing import OneHotEncoder
from scapy.all import rdpcap
import numpy as np
from scapy.all import *


def BE(packets):
    nb = 64
    enc = OneHotEncoder()
    p = [[i] for i in range(256)]
    enc.fit(p)

    raw = list()
    for p in packets:
        x = np.zeros((nb))
        i = 0
        for m in bytes(p)[:nb]:
            x[i] = m
            i += 1
        raw.append(x)
        if len(raw) == 300000:
            break

    raw = np.array(raw)
    # print(raw.shape)
    # print(raw)

    data = np.zeros((raw.shape[0], nb, 256))
    for i in range(raw.shape[0]):
        ll = [[d] for d in raw[i]]
        data[i, :] = enc.transform(ll).toarray()

    #print("feature vectors shape :",data.shape)
    #print(data)
    # np.save(outfile, data.astype(np.float32))
    # print("save successfully")
    return data



a=0
al=[]
def RUNBE(packets,origin_pos=None):
    global a
    global al
    features=[]
    all_features=[]
    #print("@RunFE: Running Feature Extractor...")
    if origin_pos is None:
        features=BE(packets)
        print('流量长度为',len(packets))
    else:
        print('all_feature流量长度为',len(packets))
        tmp=[]
        for i in origin_pos:
            tmp.append(packets[i])
        if(a==2):
            wrpcap('2.pcap',tmp)
        print('feature流量长度为',len(tmp))
        
        #print(features)
        all_features=(RUNBE(packets)[0])
        for i in origin_pos:
            features.append(all_features[i])
        print(np.array(features).shape)
        if(a<5):
            print('?',len(all_features))
            al.append(features)
        a=a+1
        if(a==5):
            np.save('1.npy',al)
            print('okoko')
    return features,all_features












 

