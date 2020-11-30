# from numpy import array
# from keras.utils import plot_model
import sys
import argparse
import pyshark
import numpy as np
import pandas as pd
from keras.models import load_model
from sklearn.preprocessing import OneHotEncoder

np.seterr(divide='ignore',invalid='ignore')

def analyse_ip(packet):
    # src_ip = str(packet.ip.src)
    number = str(packet.number) #frame no.
    src_ip_comm = str(packet.ip.src)
    src_ip_comm_split = src_ip_comm.split(".")
    # 点进制转化为十进制ip
    src_ip = str(int(src_ip_comm_split[0]) * 256 ** 3 +
                 int(src_ip_comm_split[1]) * 256 ** 2 +
                 int(src_ip_comm_split[2]) * 256 +
                 int(src_ip_comm_split[3]))
    # dst_ip = str(packet.ip.dst)
    dst_ip_comm = str(packet.ip.dst)
    dst_ip_comm_split = dst_ip_comm.split(".") #???
    dst_ip = str(int(dst_ip_comm_split[0]) * 256 ** 3 +
                 int(dst_ip_comm_split[1]) * 256 ** 2 +
                 int(dst_ip_comm_split[2]) * 256 +
                 int(dst_ip_comm_split[3]))
    proto = str(packet.ip.proto)
    ip_hdr_len = str(packet.ip.hdr_len)
    ip_pkt_len = str(packet.ip.len)
    ip_checksum_status = str(packet.ip.checksum_status)
    ip_ttl = str(packet.ip.ttl)
    ip_highest_layer = str(packet.highest_layer)
    return [number, src_ip, dst_ip, proto, ip_pkt_len, ip_checksum_status, ip_ttl]


def analyse_icmp(packet):
    '''
    only Layer ETH + IP + ICMP
    :param packet: packet in pcap
    :return: list of field
    '''
    icmp_type_code = str(packet.icmp.type) + str(packet.icmp.code)
    icmp_checksum_status = str(packet.icmp.checksum_status)
    icmp_data_len = str(packet.icmp.data_len)
    return ["", "", "", "", "", "", "", "", "", "", "",
            icmp_type_code, icmp_checksum_status]


def analyse_arp(packet):
    arp_src_proto_ipv4 = str(packet.arp.src_proto_ipv4)
    arp_dst_proto_ipv4 = str(packet.arp.dst_proto_ipv4)
    arp_opcode = str(packet.arp.opcode)


def analyse_tcp(packet):
    try:
        stream_index = str(packet.tcp.stream)
    except:
        stream_index = ""
    src_port = str(packet.tcp.srcport)
    dst_port = str(packet.tcp.dstport)
    tcp_hdr_len = str(packet.tcp.hdr_len)
    tcp_pkt_len = str(packet.tcp.len)
    tcp_timestamp = str(packet.tcp.time_relative)
    tcp_time_delta = str(packet.tcp.time_delta)
    tcp_flags = str(packet.tcp.flags)
    tcp_flags_ack = str(packet.tcp.flags_ack)
    tcp_flags_syn = str(packet.tcp.flags_syn)
    tcp_flags_fin = str(packet.tcp.flags_fin)
    tcp_flags_urg = str(packet.tcp.flags_urg)
    tcp_ack = str(packet.tcp.ack)
    tcp_checksum_status = str(packet.tcp.checksum_status)
    tcp_payload = codecs.decode(packet.tcp.payload.replace(":", ""), "hex").decode('utf-8')
    return [stream_index, src_port, dst_port, tcp_timestamp, tcp_time_delta,
            tcp_flags, tcp_flags_ack, tcp_flags_syn, tcp_flags_fin, tcp_flags_urg,
            tcp_checksum_status, "", ""]


def analyse_udp(packet):
    try:
        stream_index = str(packet.udp.stream)
    except:
        stream_index = ""
    src_port = str(packet.udp.srcport)
    dst_port = str(packet.udp.dstport)
    # udp_hdr_len = str(packet.udp.hdr_len)
    udp_pkt_len = str(packet.udp.length)
    udp_timestamp = str(packet.udp.time_relative)
    udp_time_delta = str(packet.udp.time_delta)
    udp_flags = ""
    udp_checksum_status = str(packet.udp.checksum_status)
    return [stream_index, src_port, dst_port, udp_timestamp, udp_time_delta,
            udp_flags, "", "", "", "", udp_checksum_status, "", ""]


def pcap2df(in_file):
    i = 0
    cap = pyshark.FileCapture(in_file)
    df = pd.DataFrame(columns=("","number", "src_ip", "dst_ip", "proto", "ip_pkt_len",
                             "ip_checksum_status", "ip_ttl", 
                             "stream_index", "src_port", "dst_port", "timestamp",
                             "time_delta", "flags", "tcp_flags_ack", "tcp_flags_syn",
                             "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status",
                             "icmp_type_code", "icmp_checksum_status"))
    for pkt in cap:
        try:
            if "TCP" in pkt.transport_layer:
                pkt_out_list = [i] + analyse_ip(pkt) + analyse_tcp(pkt)
                pkt_out_df = pd.Series(pkt_out_list).replace(r'', np.nan, regex=True)
                pkt_out_df.index = ["", "number", "src_ip", "dst_ip", "proto", "ip_pkt_len",
                             "ip_checksum_status", "ip_ttl",
                             "stream_index", "src_port", "dst_port", "timestamp",
                             "time_delta", "flags", "tcp_flags_ack", "tcp_flags_syn",
                             "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status",
                             "icmp_type_code", "icmp_checksum_status"]
                df = df.append(pkt_out_df, ignore_index=True)
            elif "UDP" in pkt.transport_layer:
                pkt_out_list = [i] + analyse_ip(pkt) + analyse_udp(pkt)
                pkt_out_df = pd.Series(pkt_out_list).replace(r'', np.nan, regex=True)
                pkt_out_df.index = ["", "number", "src_ip", "dst_ip", "proto", "ip_pkt_len",
                             "ip_checksum_status", "ip_ttl",
                             "stream_index", "src_port", "dst_port", "timestamp",
                             "time_delta", "flags", "tcp_flags_ack", "tcp_flags_syn",
                             "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status",
                             "icmp_type_code", "icmp_checksum_status"]
                df = df.append(pkt_out_df, ignore_index=True)
            elif "ICMP" in pkt.ip_highest_layer:
                pkt_out_list = [i] + analyse_ip(pkt) + analyse_icmp(pkt)
                pkt_out_df = pd.Series(pkt_out_list).replace(r'', np.nan, regex=True)
                pkt_out_df.index = ["", "number", "src_ip", "dst_ip", "proto", "ip_pkt_len",
                             "ip_checksum_status", "ip_ttl",
                             "stream_index", "src_port", "dst_port", "timestamp",
                             "time_delta", "flags", "tcp_flags_ack", "tcp_flags_syn",
                             "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status",
                             "icmp_type_code", "icmp_checksum_status"]
                df = df.append(pkt_out_df, ignore_index=True)
        except AttributeError as e:
            # ignore packets that aren't IPv4
            pass
        except Exception as e:
            print("No TCP or UDP or ICMP Found")
    return df

def csv2vec(df):
    '''
    读取数据，并采用LabelEncoder+OneHotEncoder编码等方式向量化
    :return: X-数据集
    '''
    x_len_time = df[["ip_pkt_len", "timestamp", "time_delta", "src_port", "dst_port", "ip_ttl", "stream_index"]]
    # 数据标准化
    x_len_time = (x_len_time - x_len_time.min()) / (x_len_time.max() - x_len_time.min())
    # 使用LabelEncoder+OneHotEncoder
    X = np.concatenate([enc.transform(df[["proto", "ip_checksum_status", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]]),
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
    parser = argparse.ArgumentParser(description="Attack Phase Judgement")
    parser.add_argument('-i', '--ip')
    parser.add_argument('-p', '--pcap')
    args = parser.parse_args()

    # 判定ip并转成同形式
    test_ip = str(args.ip)
    test_ip_split = test_ip.split(".")
    process_ip = float(int(test_ip_split[0]) * 256 ** 3 +
                 int(test_ip_split[1]) * 256 ** 2 +
                 int(test_ip_split[2]) * 256 +
                 int(test_ip_split[3]))
    seq_len = 30
    rootPath = ".\\"
    labelList = ["label0", "label1", "label2", "label3", "label4", "label5", "label6"]
    # 加载训练数据生成enc
    df = pd.DataFrame(pd.read_csv(rootPath + "darpa-trainset.csv")).fillna(0)
    enc = OneHotEncoder(sparse=False).fit(df[["proto", "ip_checksum_status", "tcp_flags_ack", "tcp_flags_syn", "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status", "icmp_type_code", "icmp_checksum_status"]])

    # 加载测试数据
    testFile = args.pcap
    # testdata = pd.read_table(testFile, header=0, sep=',')
    testdata = pcap2df(testFile)
    # 强转dataframe中的数据类型
    testdata = pd.DataFrame(testdata, dtype=np.float)
    # testdf = pd.DataFrame(testdata).fillna(0)
    testdf = testdata.fillna(0)
    testdf_ip = testdf[(testdf['src_ip'] == process_ip) | (testdf['dst_ip'] == process_ip)]
    testX = csv2vec(testdf_ip)
    outMax = 0
    # 一个文件进模型通过每个模型进行预测分类，选出最接近准确的一个阶段
    for i in range(len(labelList)):
        labelNum = labelList[i]
        # encY = OneHotEncoder(sparse=False).fit(testdf[[labelNum]])
        # 加载模型
        model = load_model(rootPath + 'model_1021\\' + str(i) + '.h5')
        # testY = encY.transform(testdf[labelNum].values.reshape(-1, 1))
        # test_X, test_Y = create_dataset(testX, testY, seq_len)
        test_X, test_Y = create_dataset(testX, testX, seq_len)
        y_pred = model.predict(test_X)#使用predict()方法进行预测时，返回值是数值，表示样本属于每一个类别的概率
        out = np.mean(y_pred, 0)# 求每一列的均值
        # out = out[~np.isnan(out)]
        print('The ' + str(i) + 'th y_pred:' + str(out))
        # 排序选最大预测值
        if out[0] > outMax:
            outMax = out[0]
            stage = i
    print('The stage of this data is: ' + str(stage))
