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
