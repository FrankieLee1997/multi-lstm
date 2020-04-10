import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tensorflow as tf
from keras.layers import LSTM, Dense
from keras.models import Sequential
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder

print(tf.version)


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


def build_model(layers, seq_len):
    '''
    构建LSTM模型
    :param layers: 特征维度，layers[0]表示初始输入特征数量
    :param seq_len: 时间步长（样本数量）
    :return: LSTM模型
    '''
    model = Sequential()
    model.add(LSTM(layers[1], input_shape=(seq_len, layers[0]), return_sequences=True))
    model.add(LSTM(layers[2], input_shape=(seq_len, layers[1])))
    model.add(Dense(units=layers[3], input_dim=(layers[2]), activation='softmax'))  # 激活函数可选'tanh'
    model.compile(loss='mse', optimizer='rmsprop', metrics=['accuracy']) #多分类损失函数为分类交想叉熵categorical_crossentropy
    return model


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

if __name__ == '__main__':
    starttime = time.time()
    lstmFirstLayer = 50 #LSTM层记忆单元
    lstmSecondLayer = 20
    outputLayer = 2 #输出层为包含2个分类的全连接层
    seq_len = 30

    batchSize = 512 #batch size
    nb_epoch = 5 # 训练周期

    rootPath = "D:\\PythonDemo\\test\\"
    # rootPath = "D:\\PycharmProject\\LSTM\\data\\"
    # rootPath = "/root/Templates/LSTM/data/"
    # 加载训练数据
    labelList = ["label0", "label1", "label2", "label3", "label4", "label5", "label6"]
    # filename = rootPath + "ral\\darpa2000LLDos1.0\\test_darpa_inside-1.0.csv"
    filename = rootPath + "phase1-5-darpa2.0.2.csv"
    # filename = rootPath + "darpa/test_darpa_inside-1.0.csv"
    print('> Loading data from: ' + filename)
    data = pd.read_table(filename, header=0, sep=',')
    df = pd.DataFrame(data).fillna(0)

    # # 数据统计
    # d = {'label': df['label'].value_counts().index, 'count': df['label'].value_counts()}
    # df_label = pd.DataFrame(data=d).sort_index()
    #
    # df_label.plot(x='label', y='count', kind='bar', legend=False, figsize=(8, 5))
    # plt.title("数据包分布", fontproperties='SimHei', fontsize=18)
    # plt.ylabel('数据包数量', fontproperties='SimHei', fontsize=12)
    # plt.xlabel('攻击阶段', fontproperties='SimHei', fontsize=12)
    # # plt.xticks(["目标侦查", "武器化", "交付", "漏洞利用", "安装", "命令和控制", "行动"])
    # plt.savefig(rootPath + "data.png")
    # plt.show()

    X = csv2vec()
    print('> Data Loaded. Completed!')

    # 多LSTM模型训练
    lossList = []
    accuracyList = []

    for i in range(len(labelList)):
        labelNum = labelList[i]
        encY = OneHotEncoder(sparse=False).fit(df[[labelNum]])
        Y = encY.transform(df[labelNum].values.reshape(-1, 1))
        train_x, val_x, train_y, val_y = train_test_split(X, Y, test_size=0.3, shuffle=True)
        train_x, train_y = create_dataset(train_x, train_y, seq_len)
        val_x, val_y = create_dataset(val_x, val_y, seq_len)
        inputDim = train_x.shape[2]
        # 建模
        model = build_model([inputDim, lstmFirstLayer, lstmSecondLayer, outputLayer], seq_len)
        # 模型训练
        model_fit = model.fit(train_x, train_y, batch_size=batchSize, epochs=nb_epoch,
                              validation_split=0.05, verbose=1, shuffle=False)
        # 评估模型
        loss, accuracy = model.evaluate(val_x, val_y)
        lossList.append(loss)
        accuracyList.append(accuracy)
        model.save(rootPath + 'model\\' + str(i) + '.h5')
        print('Model ' + str(i) + " completed.", lossList[i])

        # 模型概括
        print("-----------------------model " + str(i))
        print(model.summary())
        # metric_visualize(model_fit, i)
        print("-----------------------")

    # 训练结果输出
    for i in range(len(labelList)):
        print('loss' + str(i) + ":", lossList[i])
        print('accuracy' + str(i) + ":", accuracyList[i])
    print("TRAINING COMPLETED!")
    exit()
