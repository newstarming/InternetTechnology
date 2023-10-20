#pragma once
#ifndef NPCAP_CAPTURE_H
#define NPCAP_CAPTURE_H

#include <pcap.h>
#include <iostream>
#include <string.h>

pcap_t* choosed_dev;//ȫ�ֱ���

typedef struct FrameHeader_t { //֡�ײ�
    BYTE DesMAC[6];			   //Ŀ�ĵ�ַ
    BYTE SrcMAC[6];			   //Դ��ַ
    WORD TrameType;			   //֡����

}FrameHeader_t;

typedef struct IPHeader_t {     // IP�ײ�
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

typedef struct Data_t { //����֡�ײ���IP�ײ������ݰ�
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;

// ���ݰ�����ص�����
void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data);

// �������ݰ�����
void startPacketCapture(const char* deviceName);

//��ȡ�豸�б�
pcap_if_t* MYCAPTURELIST();

//����ѡ��������ӿڿ�---������ӿ�
void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs);

//����ַ��BYTE��ʽת��Ϊ16�����ַ�������
std::string* Byte2Hex(unsigned char bArray[], int bArray_len);

//�ٴ򿪵�����ӿڿ��ϲ����������ݰ�
void Capture();

#endif // NPCAP_CAPTURE_H
