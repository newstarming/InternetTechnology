#include "NpcapPacketHandler.h"
#include <iostream>

void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
	// �����ﴦ���񵽵����ݰ�
	std::cout << "���ݰ��Ѵ���\n";
}