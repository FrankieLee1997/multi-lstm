import time
import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tensorflow as tf
import warnings
from keras.layers import LSTM, Dense, Dropout
from keras.models import Sequential
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler, MinMaxScaler

warnings.filterwarnings("ignore")
print(tf.version)

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
    df_original['highest_layer_num'] = df_original['ip_highest_layer'].value_counts().shape[0]
    # df_original['tcp_num'] = df_original[df_original['proto'] == 6].shape[0]
    # df_original['udp_num'] = df_original[df_original['proto'] == 17].shape[0]
    # df_original['icmp_num'] = df_original[df_original['proto'] == 1].shape[0]
    df_original['src_ip_num'] = df_original['src_ip'].value_counts().shape[0]
    df_original['dst_ip_num'] = df_original['dst_ip'].value_counts().shape[0]
    df_original['ip_ttl_avr'] = df_original['ip_ttl'].mean()
    df_original['port1'] = df_original['src_port'].values[0]
    df_original['port2'] = df_original['dst_port'].values[0]
    df_original['ip1'] = df_original['src_ip'].values[0]
    df_original['ip2'] = df_original['dst_ip'].values[0]
    df_new = df_original[["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
                        "highest_layer_num", "ip_ttl_avr", "port1", "port2", "src_ip_num", "dst_ip_num", "label", 
                        "label0", "label1", "label2", "label3", "label4", "label5", "label6"]]
    df = df_new[0:1]
    return df

# def csv2df(file):
#     '''
#     将单个整体csv样本文件转化为单行信息
#     :return: 新转化的一个表示样本文件的dataframe，单行
#     '''
#     df_original = pd.DataFrame(pd.read_csv(file)).fillna(0)
#     df_original['stream_index_avr'] = df_original['stream_index'].mean()
#     df_original['packet_num'] = df_original.shape[0]
#     df_original['timestamp_avr'] = df_original['timestamp'].mean()
#     df_original['timedelta_avr'] = df_original['time_delta'].mean()
#     df_original['timestamp_max'] = df_original['timestamp'].max()
#     df_original['timedelta_max'] = df_original['time_delta'].max()
#     df_original['tcp_num'] = df_original[df_original['proto'] == 6].shape[0]
#     df_original['udp_num'] = df_original[df_original['proto'] == 17].shape[0]
#     df_original['icmp_num'] = df_original[df_original['proto'] == 1].shape[0]
#     df_original['src_ip_num'] = df_original['src_ip'].value_counts().shape[0]
#     df_original['dst_ip_num'] = df_original['dst_ip'].value_counts().shape[0]
#     df_original['ip_ttl_avr'] = df_original['ip_ttl'].mean()
#     df_new = df_original[["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
#                         "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label",
#                         "label0", "label1", "label2", "label3", "label4", "label5", "label6"]]
#     df = df_new[0:1]
#     return df

def traincsv2df(file):
    '''
    将单个整体csv样本文件转化为单行信息
    return:新转化的一个表示样本文件的dataframe，单行
    '''
    df_original_0 = pd.DataFrame(pd.read_csv(file)).fillna(0)
    df_merge = pd.DataFrame(columns=["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
                            "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label"])
    # SettingWithCopyWarning的警告关闭，dataframe对程序的影响目前估计不大
    pd.set_option('mode.chained_assignment', None)
    for i in range(7):
        df_original = df_original_0[df_original_0['label'] == i]
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
                            "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label"]]
        df = df_new[0:1]
        df_merge = df_merge.append(df,ignore_index=True)
    return df_merge

def df2vec(dataframe):
    '''
    TODO:
    原处理字段，单个数据包角度：
    *时序部分："ip_pkt_len", "timestamp", "time_delta", "src_port", "dst_port","ip_ttl", "stream_index"
    *特征部分："proto", "ip_checksum_status", "ip_highest_layer"及tcp标志字段等
    新处理字段，单个阶段样本角度：
    *时序部分："stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max"
    *特征部分："tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", 
    读取训练数据，并采用one_hot编码等方式向量化
    :imput: 格式合法的dataframe数据
    :return: X-数据集
    '''
    x_len_time = dataframe[["stream_index_avr", "packet_num", "timestamp_avr", 
                    "timedelta_avr", "timestamp_max", "timedelta_max"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())

    # 可用pandas.get_dummies或sklearn进行one-hot
    enc = OneHotEncoder(sparse=False).fit(dataframe[["highest_layer_num", "ip_ttl_avr", "port1", "port2"]])
    X = np.concatenate([enc.transform(dataframe[["highest_layer_num", "ip_ttl_avr", "port1", "port2"]]),
                        x_len_time], axis=1)
    return X

def create_dataset(dataset_X, dataset_Y, look_back=1):
    dataX, dataY = [], []
    for i in range(len(dataset_X) - look_back + 1):
        a = dataset_X[i:(i + look_back), :]
        dataX.append(a)
        dataY.append(dataset_Y[i, :])
        # print(np.array(dataX, np.float16))
    return np.array(dataX, np.float16), np.array(dataY, np.float16)

def metric_visualize(history, num):
    # 绘制训练 & 验证的准确率值
    plt.plot(history.history['accuracy'], label='train')
    plt.plot(history.history['val_accuracy'], label='validation')
    plt.title('Model accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(rootPath + "Accuracy" + str(num) + ".png")
    plt.show()

    # 绘制训练 & 验证的损失值
    plt.plot(history.history['loss'], label='train')
    plt.plot(history.history['val_loss'], label='validation')
    plt.title('Model loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig(rootPath + "loss" + str(num) + ".png")
    plt.show()

def process_data(train, test, attr, lags):
    df1 = pd.read_csv(train, encoding='utf-8').fillna(0)
    df2 = pd.read_csv(test, encoding='utf-8').fillna(0)

    # scaler = StandardScaler().fit(df1[attr].values)
    scaler = MinMaxScaler(feature_range=(0, 1)).fit(df1[attr].values.reshape(-1, 1))
    flow1 = scaler.transform(df1[attr].values.reshape(-1, 1)).reshape(1, -1)[0]
    flow2 = scaler.transform(df2[attr].values.reshape(-1, 1)).reshape(1, -1)[0]

    train, test = [], []
    for i in range(lags, len(flow1)):
        train.append(flow1[i - lags: i + 1])
    for i in range(lags, len(flow2)):
        test.append(flow2[i - lags: i + 1])

    train = np.array(train)
    test = np.array(test)
    np.random.shuffle(train)

    X_train = train[:, :-1]
    y_train = train[:, -1]
    X_test = test[:, :-1]
    y_test = test[:, -1]

    return X_train, y_train, X_test, y_test

def build_model(layers, seq_len):
    '''
    构建LSTM模型
    :param layers: 特征维度，layers[0]表示初始输入特征数量
    :param seq_len: 时间步长（样本数量）
    :return: LSTM模型
    '''
    model = Sequential()
    # 添加层
    model.add(LSTM(layers[1], input_shape=(seq_len, layers[0]), return_sequences=True))
    model.add(LSTM(layers[2], input_shape=(seq_len, layers[1])))
    model.add(Dropout(0.2))
    model.add(Dense(units=layers[3], input_dim=(layers[2]), activation='softmax'))  # 激活函数可选'tanh'
    model.compile(loss='mse', optimizer='rmsprop', metrics=['accuracy']) #多分类损失函数为分类交想叉熵categorical_crossentropy
    return model


if __name__ == '__main__':
    # config
    starttime = time.time()
    lstmFirstLayer = 50 #LSTM层记忆单元
    lstmSecondLayer = 20
    outputLayer = 2 #输出层为包含2个分类的全连接层
    # seq_len = 30
    seq_len = 1
    batchSize = 32 #batch size
    nb_epoch = 4 # 训练周期

    # 加载训练数据
    rootPath = "D:\\PythonDemo\\LSTMdemo\\traindir_conversation\\"
    df = pd.DataFrame(columns=["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
                        "highest_layer_num", "ip_ttl_avr", "port1", "port2", "src_ip_num", "dst_ip_num" "label", 
                        "label0", "label1", "label2", "label3", "label4", "label5", "label6"])
    # df = pd.DataFrame(columns=["stream_index_avr", "packet_num", "timestamp_avr", "timedelta_avr", "timestamp_max", "timedelta_max",
    #                         "tcp_num", "udp_num", "icmp_num", "src_ip_num", "dst_ip_num", "ip_ttl_avr", "label",
    #                         "label0", "label1", "label2", "label3", "label4", "label5", "label6"])
    for root,dirs,files in os.walk(rootPath):
        for file in files:
            trainfile = os.path.join(root,file)
            traindf = csv2df(trainfile)
            df = df.append(traindf, ignore_index = True)
    # df = df.fillna(0)
    print(df)
    print('> Loading data from: ' + root)
    
    # 某一个数据,可以使用pd.concat拼接多个dataframe，使用ignore_index=True重构索引
    # df = csv2df(filename)
    X = df2vec(df)
    print('> Data Loaded. Completed!')

    # 多LSTM模型训练
    lossList = []
    accuracyList = []

    labelList = ["label0", "label1", "label2", "label3", "label4", "label5", "label6"]
    for i in range(1):
        labelNum = labelList[i]
        encY = OneHotEncoder(sparse=False).fit(df[[labelNum]])
        Y = encY.transform(df[labelNum].values.reshape(-1, 1))
        train_x, val_x, train_y, val_y = train_test_split(X, Y, test_size=0.25, shuffle=True)
        train_x, train_y = create_dataset(train_x, train_y, seq_len)
        val_x, val_y = create_dataset(val_x, val_y, seq_len)
        inputDim = train_x.shape[2]
        print(inputDim)
        # 建模
        model = build_model([inputDim, lstmFirstLayer, lstmSecondLayer, outputLayer],seq_len)
        # 模型训练
        model_fit = model.fit(train_x, train_y, batch_size=batchSize, epochs=nb_epoch,
                              validation_split=0.05, verbose=1, shuffle=False)
        # 评估模型
        loss, accuracy = model.evaluate(val_x, val_y)
        lossList.append(loss)
        accuracyList.append(accuracy)
        model.save('D:\\PythonDemo\\LSTMdemo\\model_conversation\\' + str(i) + '.h5')
        print('Model ' + str(i) + " completed.", lossList[i])

        # 模型概括
        print("-----------------------model " + str(i))
        print(model.summary())
        metric_visualize(model_fit, i)
        print("-----------------------")

    # 训练结果输出
    for i in range(len(labelList)):
        print('loss' + str(i) + ":", lossList[i])
        print('accuracy' + str(i) + ":", accuracyList[i])
    print("TRAINING COMPLETED!")
    exit()
