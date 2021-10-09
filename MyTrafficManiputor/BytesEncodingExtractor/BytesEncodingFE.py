from sklearn.preprocessing import OneHotEncoder
from scapy.all import rdpcap
import numpy as np

# data_path = 'D:\\Dataset\\mawilab\\mawilab\\'
# data_file = data_path + ('mawilab_20_30w.pcap')
# outfile = 'mawilab.npy'

def BytesEncoding(pcap_file,outfile):
    nb = 64
    enc = OneHotEncoder()
    p = [[i] for i in range(256)]
    enc.fit(p)

    raw = list()
    packets = rdpcap(pcap_file)
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

    print("feature vectors shape :",data.shape)
    #print(data)
    np.save(outfile, data.astype(np.float32))
    print("save successfully")
    return data

