# from numpy import array
# from keras.utils import plot_model
import sys

import numpy as np
import pandas as pd
from keras.models import load_model
from sklearn.preprocessing import OneHotEncoder

def csv2vec():
    '''
    读取数据，并采用LabelEncoder+OneHotEncoder编码等方式向量化
    :return: X-数据集
    '''
    x_len_time = testdf[["ip_pkt_len", "timestamp", "time_delta", "src_port", "dst_port", "ip_ttl", "stream_index"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())
    # 使用LabelEncoder+OneHotEncoder
    X = np.concatenate([enc.transform(testdf[["proto", "ip_checksum_status", "ip_highest_layer", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]]),
                        x_len_time], axis=1)
    return X

def create_dataset(dataset_X, dataset_Y, look_back=1):
    dataX, dataY = [], []
    for i in range(len(dataset_X) - look_back + 1):
        a = dataset_X[i:(i + look_back), :]
        dataX.append(a)
        dataY.append(dataset_Y[i, :])
    return np.array(dataX, np.float16), np.array(dataY, np.float16)


if __name__ == '__main__':

    filename = sys.argv[1]
    seq_len = 30
    rootPath = "D:\\PythonDemo\\test\\"
    # rootPath = "D:\\PycharmProject\\LSTM\\data\\"
    # rootPath = "/root/Templates/LSTM/data/"
    labelList = ["label0", "label1", "label2", "label3", "label4", "label5", "label6"]
    # 加载训练数据生成enc
    df = pd.DataFrame(pd.read_csv(rootPath + "phase1-5-darpa2.0.2.csv")).fillna(0)
    enc = OneHotEncoder(sparse=False).fit(df[["proto", "ip_checksum_status", "ip_highest_layer", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]])

    # 加载测试数据
    # testFile = "D:\\PycharmProject\\LSTM\\data\\ral\\darpa2000LLDos1.0\\1.0-phase1-5样本拆分\\" + filename
    testFile = "D:\\PythonDemo\\test\\LLS_DOS_2.0.2\\2.0.2-阶段划分" + filename
    testdata = pd.read_table(testFile, header=0, sep=',')
    testdf = pd.DataFrame(testdata).fillna(0)
    testX = csv2vec()
    outMax = 0
    for i in range(len(labelList)):
        labelNum = labelList[i]
        encY = OneHotEncoder(sparse=False).fit(testdf[[labelNum]])
        # 加载模型
        model = load_model(rootPath + 'model\\' + str(i) + '.h5')
        testY = encY.transform(testdf[labelNum].values.reshape(-1, 1))
        test_X, test_Y = create_dataset(testX, testY, seq_len)
        y_pred = model.predict(test_X)
        out = np.mean(y_pred, 0)# 求每一列的均值
        print('The ' + str(i) + 'th y_pred:' + str(out))
        if out[0] > outMax:
            outMax = out[0]
            stage = i
    print('The stage of this dada is: ' + str(stage))
    print("ALL COMPLETED!")
    exit()
