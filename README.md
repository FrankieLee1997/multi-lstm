# multi-lstm
2020年3到4月，nskeylab，与zhengn  
多LSTM模型进行攻击链划分，针对pcap流量文件  
multiLSTMtrain.py，训练程序  
multiLSTMtest.py，测试程序
LSTMdemo.py，以整个数据包为输入单位，重新选取以单个pcap数据考虑的字段
multiLSTMtest_new.py，测试程序，输入形式为无标签序列的阶段csv文件,调整主函数中获取dataframe的形式（有误）    
## 目前使用到需处理清洗的数据集有  
已完成：darpa2000-1.0，darpa2000-2.0.2，CICIDS2017-Thursday/Friday（dropbox、漏洞利用），ISCXIDS2012-June,13（内部渗透相关、mdns）
训练数据集：手动标定的部分darpa、CICIDS、ISCX组成的一个10000+数据包的训练集  
.\model：训练出的模型，version1  
## 2020.6 集成情况  
mongodb：219.245.185.225:27017/Log/flow_parse  
考虑输出etcd：219.245.185.226:2379  /mashcloud/decoysystem/phase/"IP":
数据样式：{ "_id" : ObjectId("5ee443e76752210181786d40"), "packet_id" : "3", "time_stamp" : "Jun 13, 2020 11:11:34", "src_ip" : "219.245.186.199", "dst_ip" : "203.208.50.95", "proto" : "6", "ip_pkt_len" : "41", "ip_checksum_status" : "2", "ip_ttl" : "64", "ip_highest_layer" : "TLS", "stream_index" : "0", "src_port" : "52131", "dst_port" : "443", "payload_len" : "1", "u_t_flags" : "0x00000010", "u_t_checksum_status" : "2", "tcp_ack" : "1", "tcp_flags_ack" : "1", "tcp_flags_syn" : "0", "tcp_flags_fin" : "0", "tcp_flags_urg" : "0", "tcp_flags_res" : "0", "tcp_flags_push" : "0", "icmp_type_code" : "", "icmp_checksum_status" : "" }  

我需要：  
提前训练较多标定完成的数据（需要模型中包括足够多类型的ip_highest_layer，不然会判定不出来，或者需要把这个字段替换掉，只留判断tcp/udp/icmp的proto字段即可）；  
从mongodb读入数据是否为批次，是否需要根据ip（五元组）判断分次攻击（在判定程序中）；  
