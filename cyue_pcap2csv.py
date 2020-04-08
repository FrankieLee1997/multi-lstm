import codecs
import csv

import os
import pyshark
from scapy.utils import rdpcap


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
    return [number, src_ip, dst_ip, proto, ip_pkt_len, ip_checksum_status, ip_ttl,
            ip_highest_layer]


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


def pcap2csv(in_file, out_file, write_or_add, labeled):
    cap = pyshark.FileCapture(in_file)
    f_out = open(out_file, write_or_add, encoding='utf-8', newline="")
    # f_out = io.open(out_file, write_or_add, newline='')
    csv_writer = csv.writer(f_out)
    if write_or_add == "w":
        csv_writer.writerow(["number", "src_ip", "dst_ip", "proto", "ip_pkt_len",
                             "ip_checksum_status", "ip_ttl", "ip_highest_layer",
                             "stream_index", "src_port", "dst_port", "timestamp",
                             "time_delta", "flags", "tcp_flags_ack", "tcp_flags_syn",
                             "tcp_flags_fin", "tcp_flags_urg", "tcp_checksum_status",
                             "icmp_type_code", "icmp_checksum_status", "label"])
    for pkt in cap:
        try:
            # print(pkt.transport_layer)
            if "TCP" in pkt.transport_layer:
                pkt_out_list = analyse_ip(pkt) + analyse_tcp(pkt)
                csv_writer.writerow(pkt_out_list + [labeled])
            elif "UDP" in pkt.transport_layer:
                pkt_out_list = analyse_ip(pkt) + analyse_udp(pkt)
                csv_writer.writerow(pkt_out_list + [labeled])
            elif pkt.highest_layer == "ICMP":
                pkt_out_list = analyse_ip(pkt) + analyse_icmp(pkt)
                csv_writer.writerow(pkt_out_list + [labeled])
        except AttributeError as e:
            # ignore packets that aren't IPv4
            pass
        except Exception as e:
            print("No TCP or UDP or ICMP Found")
    f_out.close()
    # cap.close()



def pcap2session(pcap_file_name):
    path = pcap_file_name
    sess_index = []
    cap = pyshark.FileCapture(path)

    # tcp
    for pkt in cap:
        try:
            sess_index.append(pkt.tcp.stream)
        except:
            pass
    print(sess_index)
    print(len(sess_index))
    max_index = 0
    if len(sess_index) > 0:
        max_index = int(max(sess_index)) + 1
    else:
        print("No TCP Found")
    for pkt in cap:
        try:
            if pkt.tcp.stream in sess_index:
                print("Stream", pkt.tcp.stream, pkt.tcp)
        except:
            pass

    # udp
    for pkt in cap:
        try:
            print(pkt.udp)
        except:
            pass



    # STREAM_NUMBER = 2
    # cap = pyshark.FileCapture(path, display_filter='tcp.stream eq %d' % STREAM_NUMBER)
    # while True:
    #     try:
    #         p = cap.next()
    #     except StopIteration:  # Reached end of capture file.
    #         break
    #     try:
    #         # print data from the selected stream
    #         print(p)
    #     except AttributeError:  # Skip the ACKs.
    #         pass


def pcap2txt():
    path = "../data/pcap/malware/"
    files = os.listdir(path)
    i = 1
    f = open("../data/text/train.txt", "w")
    for file in files:
        print(path + file)
        packets = rdpcap(path + file)
        for packet in packets:
            print(repr(packet))
            f.write(repr(packet), "    ", str(i))
        i += 1
    f.close()


if __name__ == '__main__':
    # pcap2session("../data/pcap/malware/vulappssambav1_20191113T075222.pcap")
    # pcap2csv("../data/pcap/benign/Skype.pcap", "../data/csv/train.csv", "w", "0")
    # pcap2csv("../data/pcap/malware/BitcoinMiner_F865C199024105A2FFDF5FA98F391D74.pcap",
    #          "../data/csv/train.csv", "a", "1")
    # pcap2csv("../data/pcap/malware/BIN_Lader-dlGameoverZeus_12cfe1caa12991102d79a366d3aa79e9.pcap",
    #          "../data/csv/train.csv", "a", "2")
    # pcap2csv("../data/pcap/malware/BIN_Nitedrem_508af8c499102ad2ebc1a83fdbcefecb.pcap",
    #          "../data/csv/train.csv", "a", "3")
    # pcap2csv("../data/pcap/malware/EK_MALWARE_2014-06-06-FlashPack-EK-traffic_mailware-traffic-analysis.net.pcap",
    #          "../data/csv/train.csv", "a", "4")
    # pcap2csv("../data/pcap/benign/weibo_00000_19700101125000.pcap",
    #          "../data/csv/train.csv", "a", "5")
    # pcap2csv("../data/pcap/benign/weibo_00001_19700101125000.pcap",
    #          "../data/csv/test.csv", "w", "5")
    # pcap2csv("../data/pcap/malware/vulappssambav1_20191113T075222.pcap", "../data/csv/train.csv", "a", "1")
    # pcap2csv("../data/pcap/malware/vulappsnginxv1_20191120T024750.pcap", "../data/csv/train.csv", "a", "2")
    # pcap2csv("../data/pcap/malware/vulappsjoomlav2_20191119T065503.pcap", "../data/csv/train.csv", "a", "3")
    # pcap2csv("../data/pcap/malware/vulappswordpressv3_20191113T074537.pcap", "../data/csv/train.csv", "a", "4")
    pcap2csv("LLS_DDOS_1.0-inside.pcap", "test_darpa_inside-1.csv", "w", "0")
