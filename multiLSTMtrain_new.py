import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tensorflow as tf
from keras.layers import LSTM, Dense
from keras.models import Sequential
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder

def csv2vec():
    '''
    读取训练数据，并采用one_hot编码等方式向量化
    :param filename: 用于训练数据获取的文件名
    :return: X-数据集
    '''
    x_len_time = df[["ip_pkt_len", "timestamp", "time_delta", "src_port", "dst_port",
                     "ip_ttl", "stream_index"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())

    # 可用pandas.get_dummies或sklearn进行one-hot
    enc = OneHotEncoder(sparse=False).fit(df[["proto", "ip_checksum_status", "ip_highest_layer", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]])
    X = np.concatenate([enc.transform(df[["proto", "ip_checksum_status", "ip_highest_layer", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]]),
                        x_len_time], axis=1)
    # print(X, X.shape)
    return X
    
def create_dataset(dataset_X, dataset_Y, look_back=1):
    dataX, dataY = [], []
    for i in range(len(dataset_X) - look_back + 1):
        a = dataset_X[i:(i + look_back), :]
        dataX.append(a)
        dataY.append(dataset_Y[i, :])
        # print(np.array(dataX, np.float16))
    return np.array(dataX, np.float16), np.array(dataY, np.float16)