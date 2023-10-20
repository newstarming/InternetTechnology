#pragma once
#ifndef NPCAPPACKETCAPTURE_H
#define NPCAPPACKETCAPTURE_H

#include <pcap.h>

// 函数用于初始化数据包捕获
pcap_t* InitializePacketCapture(const char* device);

// 函数用于捕获数据包
void CapturePackets(pcap_t* handle, int numPackets, pcap_handler callback);

// 函数用于关闭数据包捕获
void ClosePacketCapture(pcap_t* handle);

#endif
