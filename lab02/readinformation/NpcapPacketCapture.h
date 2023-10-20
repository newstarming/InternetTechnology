#pragma once
#ifndef NPCAPPACKETCAPTURE_H
#define NPCAPPACKETCAPTURE_H

#include <pcap.h>

// �������ڳ�ʼ�����ݰ�����
pcap_t* InitializePacketCapture(const char* device);

// �������ڲ������ݰ�
void CapturePackets(pcap_t* handle, int numPackets, pcap_handler callback);

// �������ڹر����ݰ�����
void ClosePacketCapture(pcap_t* handle);

#endif
