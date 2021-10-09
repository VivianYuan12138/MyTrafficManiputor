import numpy as np
import time
import argparse
import pickle as pkl
from config import Config
from model import TextCNN
import torch
from torch.autograd import Variable
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


#global
#属于是自己可以定义的，训练集和测试集的大小（因为没8/2分我先不写）
train_size = 90000
test_size = 10000

#config file
config = Config(sentence_max_size=50, word_embedding_dimension=256,
                batch_size=8,
                word_num=100,
                label_num=2,
                learning_rate=0.01,
                epoch=4,
                out_channel=1)


def MyMeature(prediction, label_test):
    craft_benign=0
    craft_malicious=0
    origin_benign=0
    origin_malicious=0
    for j in range(len(prediction)):
        if prediction[j] == 0:
            craft_benign = craft_benign + 1
        else:
            craft_malicious=craft_malicious+1

    for i in range(len(label_test)):
        if label_test[i] == 0:
            origin_benign = origin_benign + 1
        else:
            origin_malicious=origin_malicious+1
    print("origin_benign :",origin_benign)  
    print("origin_malicious:",origin_malicious)     
    print("craft_benign :",craft_benign)  
    print("craft_malicious:",craft_malicious)       
    print("PDR",(1-(craft_malicious/origin_malicious)))

def measure(res, label_test):
    TN = 0
    FN = 0
    TP = 0
    FP = 0
    for j in range(len(res)):
        if res[j] == 0:
            if label_test[j] == 0:
                TN = TN + 1
            else:
                FN += 1
        else:
            if label_test[j] == 0:
                FP = FP + 1
            else:
                TP += 1
    accuracy = accuracy_score(label_test, res)
    precision = precision_score(label_test, res)
    recall = recall_score(label_test, res)
    f1 = f1_score(label_test, res)
    if TN + FP > 0:
        fpr = FP / (TN + FP)
    else:
        fpr = 0

    print("TN = ", TN, "TP= ", TP, "FN= ", FN, "FP=", FP)
    print("F1-score = ", f1, "Precision = ",
          precision, "Recall = ", recall, "FPR=", fpr)
    return f1



#main
if __name__ == "__main__":
    parse = argparse.ArgumentParser()
    parse.add_argument('-M', '--mode', type=str, default='test', help="{train,test}")
    parse.add_argument('-tf', '--feat_file_path', type=str, default='../dataPGA/mawilab_20_30w.npy', help="train or execute feature file path (.npy)")
    parse.add_argument('-l', '--label_file_path', type=str, default='../dataPGA/mawilab_20_30w_label.npy',help="train or execute label file path (.npy)")
    parse.add_argument('-mf', '--model_file_path', type=str, default='../dataPGA/model.pkl',
                       help="for train mode, model is saved into 'mf'; for execute mode, model is loaded from 'mf'")
    arg = parse.parse_args()

    #train
    if arg.mode == 'train':
        print("Warning: under TRAIN mode!")
        data = np.load(arg.feat_file_path)
        print("train feature shape :",data.shape)
        labels = np.load(arg.label_file_path)

        #data preparation
        data_train = data[0:train_size, :]
        label_train = labels[0:train_size]

  
        train_size = data_train.shape[0]
        data_train = torch.from_numpy(data_train)
        label_train = torch.from_numpy(label_train)
        print("the size is", train_size)
        train_batch = train_size // config.batch_size

        model = TextCNN(config)
        criterion = nn.CrossEntropyLoss()#交叉熵主要是用来判定实际的输出与期望的输出的接近程度
        optimizer = optim.SGD(model.parameters(), lr=config.lr)#优化函数
        
        #train model
        model.train()
        for epoch in range(config.epoch):
            loss_sum = 0
            running_correct = 0
            print("training Epoch{}/{}".format(epoch, config.epoch))
            train_begin = time.time()
            for i in range(train_batch):
                inputs = Variable(data_train[i * config.batch_size:min((i + 1) * config.batch_size, train_size),
                                :], requires_grad=False).view(-1, 1, data_train.shape[1], data_train.shape[2])
                targets = Variable(label_train[i * config.batch_size:min(
                    (i + 1) * config.batch_size, train_size)], requires_grad=False)
                num = min((i + 1) * config.batch_size, train_size) - \
                    i * config.batch_size
                if num < config.batch_size:
                    break
                outputs = model(inputs)
                _, pred = torch.max(outputs.data, 1)
                optimizer.zero_grad()
                loss = criterion(outputs, targets)
                loss.backward()
                optimizer.step()

                loss_sum += loss.data.cpu().numpy()
                running_correct += sum(pred == targets)

            stop = time.time()
            print(epoch, "epoch time is", stop - train_begin)
            print("Loss is : {:.4f},Train acc is :{:.4f}%".format(float(
                loss_sum) / float(train_size), 100.0 * float(running_correct) / float(train_size)))

        #save model
        with open(arg.model_file_path, "ab") as f:
            pkl.dump(model, f)


    #test
    elif arg.mode == 'test':
        print("Warning: under EXECUTE mode!")
        data = np.load(arg.feat_file_path)
        print("test feature shape :",data.shape)
        labels = np.load(arg.label_file_path)

        #data preparation
        #data_test = data[train_size:train_size + test_size, :]
        label_test = labels[90000:91000]#labels[train_size:train_size + test_size]
        data_test=np.load('../dataPGA/t1000.npy')
        #label_test=np.load('../dataPGA/test2labels.npy')

        # evaluate model:
        with open(arg.model_file_path, "rb") as f:
            model= pkl.load(f)
        model.eval()
        test_size = len(data_test)
        test_batch = test_size // config.batch_size
        data_test = torch.from_numpy(data_test)
        prediction = np.zeros(test_size, dtype=np.uint8)

        st = time.time()
        for i in range(test_batch):
            inputs = Variable(data_test[i * config.batch_size:min((i + 1) * config.batch_size, test_size),
                            :], requires_grad=False).view(-1, 1, data_test.shape[1], data_test.shape[2])
            num = min((i + 1) * config.batch_size, test_size) - i * config.batch_size
            if num < config.batch_size:
                break
            outputs = model(inputs)
            pred = np.argmax(outputs.data.cpu().numpy(), axis=1)
            prediction[i * config.batch_size:min((i + 1)
                                                * config.batch_size, test_size)] = pred

        print("test time = ", time.time() - st)
        MyMeature(prediction, label_test)
        #measure(prediction, label_test)
