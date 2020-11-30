# from numpy import array
# from keras.utils import plot_model
import sys
import warnings
import os
import numpy as np
import pandas as pd
from keras.models import load_model
from sklearn.preprocessing import OneHotEncoder
warnings.filterwarnings("ignore")

# TODO:
# 输入形式：每条标定数据=>单个阶段文件csv
# 每个小文件一个标签，在模型结构中完成

def csv2df(file):
    '''
    将单个整体csv样本文件转化为单行信息
    :return: 新转化的一个表示样本文件的dataframe，单行
    '''
    df_original = pd.DataFrame(pd.read_csv(file)).fillna(0)
    df_original['stream_index_avr'] = df_original['stream_index'].mean()
    df_original['packet_num'] = df_original.shape[0]
    df_original['timestamp_avr'] = df_original['timestamp'].mean()
    df_original['timedelta_avr'] = df_original['time_delta'].mean()
    df_original['timestamp_max'] = df_original['timestamp'].max()
    df_original['timedelta_max'] = df_original['time_delta'].max()
    df_original['tcp_num'] = df_original[df_original['proto'] == 6].shape[0]
    df_original['udp_num'] = df_original[df_original['proto'] == 17].shape[0]
    df_original['icmp_num'] = df_original[df_original['proto'] == 1].shape[0]
    df_original['src_ip_num'] = df_original['src_ip'].value_counts().shape[0]
    df_original['dst_ip_num'] = df_original['dst_ip'].value_counts().shape[0]
    df_original['ip_ttl_avr'] = df_original['ip_ttl'].mean()
    df_new = df_original[["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
                        "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label",
                        "label0", "label1", "label2", "label3", "label4", "label5", "label6"]]
    df = df_new[0:1]
    return df

def df2vec(dataframe):
    x_len_time = dataframe[["stream_index_avr", "packet_num", "timestamp_avr", 
                    "timedelta_avr", "timestamp_max", "timedelta_max"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())

    # 可用pandas.get_dummies或sklearn进行one-hot
    # enc = OneHotEncoder(sparse=False).fit(dataframe[["tcp_num", "udp_num", "icmp_num", 
    #                                  "src_ip_num", "dst_ip_num", "ip_ttl_avr"]])
    X = np.concatenate([enc.transform(dataframe[["tcp_num", "udp_num", "icmp_num", 
                                    "src_ip_num", "dst_ip_num", "ip_ttl_avr"]]),
                        x_len_time], axis=1)
    return X

def csv2vec():
    '''
    读取数据，并采用LabelEncoder+OneHotEncoder编码等方式向量化
    :return: X-数据集
    '''
    x_len_time = testdf[["stream_index_avr", "packet_num", "timestamp_avr", 
                    "timedelta_avr", "timestamp_max", "timedelta_max"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())
    # 使用LabelEncoder+OneHotEncoder
    X = np.concatenate([enc.transform(testdf[["tcp_num", "udp_num", "icmp_num", 
                                    "src_ip_num", "dst_ip_num", "ip_ttl_avr"]]),
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
    filename = "phase-1-1.csv"
    seq_len = 1
    rootPath = "D:\\PythonDemo\\LSTMdemo\\"

    labelList = ["label0", "label1", "label2", "label3", "label4", "label5", "label6"]
    # 加载训练数据生成enc
    # df = pd.DataFrame(pd.read_csv(rootPath + "darpa-trainset.csv")).fillna(0)
    # trainFile = rootPath + "darpa-trainset.csv"
    # df = csv2df(trainFile)
    df = pd.DataFrame(columns=["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
                            "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label",
                            "label0", "label1", "label2", "label3", "label4", "label5", "label6"])
    for root,dirs,files in os.walk(r"D:\\PythonDemo\\LSTMdemo\\traindir\\"):
        for file in files:
            trainfile = os.path.join(root,file)
            traindf = csv2df(trainfile)
            df = df.append(traindf, ignore_index = True)

    enc = OneHotEncoder(sparse=False).fit(df[["tcp_num", "udp_num", "icmp_num", 
                                    "src_ip_num", "dst_ip_num", "ip_ttl_avr"]])

    # 加载测试数据
    testFile = "D:\\PythonDemo\\LSTMdemo\\testdir\\" + filename 
    testdf = csv2df(testFile)
    testX = df2vec(testdf)
    outMax = 0
    # 一个文件进模型通过每个模型进行预测分类，选出最接近准确的一个阶段
    for i in range(len(labelList)):
        labelNum = labelList[i]
        encY = OneHotEncoder(sparse=False).fit(testdf[[labelNum]])
        # 加载模型
        model = load_model(rootPath + 'model_new\\' + str(i) + '.h5')
        testY = encY.transform(testdf[labelNum].values.reshape(-1, 1))
        test_X, test_Y = create_dataset(testX, testY, seq_len)
        y_pred = model.predict(test_X) # 使用predict()方法进行预测时，返回值是数值，表示样本属于每一个类别的概率
        out = np.mean(y_pred, 0) # 求每一列的均值
        # out = out[~np.isnan(out)]
        print('The ' + str(i) + 'th y_pred:' + str(out))
        # 排序选最大预测值
        if out[0] > outMax:
            outMax = out[0]
            stage = i

    print('The stage of this data is: ' + str(stage))
    print("ALL COMPLETED!")
    exit()

    # 自定义该阶段样本csv的标签值
    # arr = filename.split(sep='-')
    # label = int(arr[1]) - 1
    # # 给dataframe加上标签附加列,某一个label为1，其余label全为0，两列概括
    # testdf['extra_label'] = 1
    # testdf['extra_label_0'] = 0
    # # 做OneHotEncoder
    # encY = OneHotEncoder(sparse=False).fit(testdf[['extra_label']])
    # # 加载模型
    # for i in range(7):
    #     model = load_model(rootPath + 'model\\' + str(i) + '.h5')
    #     testY = encY.transform(testdf['extra_label'].values.reshape(-1, 1))
    #     testY_0 = OneHotEncoder(sparse=False).fit(testdf[['extra_label_0']]).transform(testdf['extra_label_0'].values.reshape(-1, 1))
    #     test_X, test_Y = create_dataset(testX, testY, seq_len)
    #     y_pred = model.predict(test_X)
    #     out = np.mean(y_pred, 0)# 求每一列的均值
    #     print('The ' + str(i) + 'th y_pred:' + str(out))
    #     if out[0] > outMax:
    #         outMax = out[0]
    #         stage = i
