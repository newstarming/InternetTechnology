#include "NpcapPacketHandler.h"
#include <iostream>

void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
	// 在这里处理捕获到的数据包
	std::cout << "数据包已处理\n";
}