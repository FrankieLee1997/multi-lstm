from scapy.all import *
import os.path
import csv
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import pyshark

def pcap2csv(filename):
    packets = parse(filename)
    columns = [column[0] for _, column in enumerate(packets[0])]
    with open('.\LLS_DOS_2.0.2\phase-6-4.csv', 'w') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(columns)
        for _, packet in enumerate(packets):
            writer.writerow([v[1] for _, v in enumerate(packet)])


def parse(filename):
    # packets = rdpcap(filename)
    packets = pyshark.FileCapture(filename)
    data = []
    i = 1
    j = 0
    for _, packet in enumerate(packets):
        if i % 5 == 4:
            values = {}
            if 'TCP' in packet:
                if 'IP' in packet:
                    src_ip_comm = str(packet.ip.src)
                    src_ip_comm_split = src_ip_comm.split(".")
                    dst_ip_comm = str(packet.ip.dst)
                    dst_ip_comm_split = dst_ip_comm.split(".")
                    values.update({
                        '': j,
                        'anumber': packet.number,
                        # 'ip_id': packet['IP'].id,
                        # 'ip_time': packet['IP'].time,
                        'bsrc_ip': (int(src_ip_comm_split[0]) * 256 ** 3 +
                                   int(src_ip_comm_split[1]) * 256 ** 2 +
                                   int(src_ip_comm_split[2]) * 256 +
                                   int(src_ip_comm_split[3])),
                        'cdst_ip': (int(dst_ip_comm_split[0]) * 256 ** 3 +
                                   int(dst_ip_comm_split[1]) * 256 ** 2 +
                                   int(dst_ip_comm_split[2]) * 256 +
                                   int(dst_ip_comm_split[3])),
                        'eip_pkt_len': packet.ip.len,
                        'dip_proto': packet.ip.proto,
                        'gip_ttl': packet.ip.ttl,
                        'fip_checksum_status': packet.ip.checksum_status,
                        'hip_highest_layer': packet.highest_layer,
                    })
                if 'TCP' in packet:
                    values.update({
                        'jsrc_port': packet.tcp.srcport,
                        'kdst_port': packet.tcp.dstport,
                        'ltimestamp': packet.tcp.time_relative,
                        'mtime_delta': packet.tcp.time_delta,
                        'nflags': packet.tcp.flags,
                        'stcp_checksum_status': packet.tcp.checksum_status,
                        'istream_index': packet.tcp.stream,
                        'otcp_flags_ack': packet.tcp.flags_ack,
                        'ptcp_flags_syn': packet.tcp.flags_syn,
                        'qtcp_flags_fin': packet.tcp.flags_fin,
                        'rtcp_flags_urg': packet.tcp.flags_urg,
                        'ticmp_type_code': '',
                        'uicmp_checksum_status': '',
                    })
                if 'UDP' in packet:
                    values.update({
                        'jsrc_port': packet.udp.srcport,
                        'kdst_port': packet.udp.dstport,
                        'ltimestamp': packet.udp.time_relative,
                        'mtime_delta': packet.udp.time_delta,
                        # 'udp_len': packet['UDP'].len,
                        # 'udp-checksum': packet['UDP'].chksum,
                    })
                i = i + 1
                values = sorted(values.items())
                data.append(values)
            elif 'UDP' in packet:
                if 'IP' in packet:
                    src_ip_comm = str(packet.ip.src)
                    src_ip_comm_split = src_ip_comm.split(".")
                    dst_ip_comm = str(packet.ip.dst)
                    dst_ip_comm_split = dst_ip_comm.split(".")
                    values.update({
                        '': j,
                        'anumber': packet.number,
                        # 'ip_id': packet['IP'].id,
                        # 'ip_time': packet['IP'].time,
                        'bsrc_ip': (int(src_ip_comm_split[0]) * 256 ** 3 +
                                   int(src_ip_comm_split[1]) * 256 ** 2 +
                                   int(src_ip_comm_split[2]) * 256 +
                                   int(src_ip_comm_split[3])),
                        'cdst_ip': (int(dst_ip_comm_split[0]) * 256 ** 3 +
                                   int(dst_ip_comm_split[1]) * 256 ** 2 +
                                   int(dst_ip_comm_split[2]) * 256 +
                                   int(dst_ip_comm_split[3])),
                        'eip_pkt_len': packet.ip.len,
                        'dip_proto': packet.ip.proto,
                        'gip_ttl': packet.ip.ttl,
                        'fip_checksum_status': packet.ip.checksum_status,
                        'hip_highest_layer': packet.highest_layer,
                    })
                # if 'TCP' in packet:
                #     values.update({
                #         'tcp_src_port': packet['TCP'].sport,
                #         'tcp_dst_port': packet['TCP'].dport,
                #         'tcp_flag': packet.sprintf("%TCP.flags%"),
                #         'tcp_checksum': packet['TCP'].chksum,
                #     })
                if 'UDP' in packet:
                    values.update({
                        'jsrc_port': packet.udp.srcport,
                        'kdst_port': packet.udp.dstport,
                        'ltimestamp': packet.udp.time_relative,
                        'mtime_delta': packet.udp.time_delta,
                        'nflags': '',
                        'stcp_checksum_status': packet.udp.checksum_status,
                        'istream_index': packet.udp.stream,
                        'otcp_flags_ack': '',
                        'ptcp_flags_syn': '',
                        'qtcp_flags_fin': '',
                        'rtcp_flags_urg': '',
                        'ticmp_type_code': '',
                        'uicmp_checksum_status': '',
                    })
                i = i + 1
                values = sorted(values.items())
                data.append(values)
            elif "ICMP" in packet:
                if 'IP' in packet:
                    src_ip_comm = str(packet.ip.src)
                    src_ip_comm_split = src_ip_comm.split(".")
                    dst_ip_comm = str(packet.ip.dst)
                    dst_ip_comm_split = dst_ip_comm.split(".")
                    values.update({
                        '': j,
                        'anumber': packet.number,
                        # 'ip_id': packet['IP'].id,
                        # 'ip_time': packet['IP'].time,
                        'bsrc_ip': (int(src_ip_comm_split[0]) * 256 ** 3 +
                                   int(src_ip_comm_split[1]) * 256 ** 2 +
                                   int(src_ip_comm_split[2]) * 256 +
                                   int(src_ip_comm_split[3])),
                        'cdst_ip': (int(dst_ip_comm_split[0]) * 256 ** 3 +
                                   int(dst_ip_comm_split[1]) * 256 ** 2 +
                                   int(dst_ip_comm_split[2]) * 256 +
                                   int(dst_ip_comm_split[3])),
                        'eip_pkt_len': packet.ip.len,
                        'dip_proto': packet.ip.proto,
                        'gip_ttl': packet.ip.ttl,
                        'fip_checksum_status': packet.ip.checksum_status,
                        'hip_highest_layer': packet.highest_layer,
                    })
                    if 'ICMP' in packet:
                        values.update({
                            'jsrc_port': '',
                            'kdst_port': '',
                            'ltimestamp': '',
                            'mtime_delta': '',
                            'nflags': '',
                            'stcp_checksum_status': '',
                            'istream_index': '',
                            'otcp_flags_ack': '',
                            'ptcp_flags_syn': '',
                            'qtcp_flags_fin': '',
                            'rtcp_flags_urg': '',
                            # 'udp_src_port': '',
                            # 'udp_dst_port': '',
                            # 'udp_len': '',
                            # 'udp-checksum': '',
                            # 'icmp_type': packet['ICMP'].type,
                            'ticmp_type_code': packet['ICMP'].type + packet['ICMP'].code,
                            'uicmp_checksum_status': packet.icmp.checksum_status,
                        })
                    i = i + 1
                    values = sorted(values.items())
                    data.append(values)
            else:
                print 'frame:', i, ' is no use'
                i = i + 1
            j = j + 1
        else:
            print 'frame',packet.number,'has skipped'
            i = i + 1
    return data


# data_path = os.path.join('.', 'data', 'test1.pcap')
data_path = os.path.join('.\LLS_DOS_2.0.2\phase-4-part1.pcap')
pcap2csv(data_path)
