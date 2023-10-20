#include "NpcapPacketCapture.h"
#include <iostream>

pcap_t* InitializePacketCapture(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "���Ϊ��\n";
    }
    return handle;
}

void CapturePackets(pcap_t* handle, int numPackets, pcap_handler callback) {
    if (pcap_loop(handle, numPackets, callback, nullptr) == -1) {
        std::cerr << "�������ݰ�ʧ��\n";
    }
    //struct pcap_pkthdr header;
    //const u_char* packet;

    //while (int returnValue = pcap_next_ex(handle, &header, &packet) >= 0) {
    //    // �����̫��֡�Ƿ����㹻�ĳ���
    //    if (header.len < 14) {
    //        continue;
    //    }

    //    // ����̫��֡����ȡԴMAC��ַ��Ŀ��MAC��ַ
    //    unsigned char* sourceMac = (unsigned char*)(packet);
    //    unsigned char* destMac = (unsigned char*)(packet + 6);

    //    // ��ȡ����/�����ֶε�ֵ
    //    unsigned short etherType = ntohs(*(unsigned short*)(packet + 12));

    //    // ����Ļ����ʾ���ݰ���Ϣ
    //    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", sourceMac[0], sourceMac[1], sourceMac[2], sourceMac[3], sourceMac[4], sourceMac[5]);
    //    printf("Dest MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", destMac[0], destMac[1], destMac[2], destMac[3], destMac[4], destMac[5]);
    //    printf("Type/Length: 0x%04X\n", etherType);
    //    printf("\n");
    //}
}

void ClosePacketCapture(pcap_t* handle) {
    pcap_close(handle);
}
