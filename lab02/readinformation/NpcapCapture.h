#pragma once
#ifndef NPCAP_CAPTURE_H
#define NPCAP_CAPTURE_H

#include <pcap.h>
#include <iostream>
#include <string.h>

pcap_t* choosed_dev;//全局变量

typedef struct FrameHeader_t { //帧首部
    BYTE DesMAC[6];			   //目的地址
    BYTE SrcMAC[6];			   //源地址
    WORD TrameType;			   //帧类型

}FrameHeader_t;

typedef struct IPHeader_t {     // IP首部
    BYTE Ver_HLen;
    BYTE TOS;
    WORD TotalLen;
    WORD ID;
    WORD Flag_Segment;
    BYTE TTL;
    BYTE Protocol;
    WORD Checksum;
    ULONG SrcIP;
    ULONG DstIP;
}IPHeader_t;

typedef struct Data_t { //包含帧首部和IP首部的数据包
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;

// 数据包处理回调函数
void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);

// 启动数据包捕获
void startPacketCapture(const char* deviceName);

//获取设备列表
pcap_if_t* MYCAPTURELIST();

//监听选定的网络接口卡---打开网络接口
void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs);

//将地址由BYTE形式转换为16进制字符串类型
std::string* Byte2Hex(unsigned char bArray[], int bArray_len);

//再打开的网络接口卡上捕获网络数据包
void Capture();

#endif // NPCAP_CAPTURE_H
