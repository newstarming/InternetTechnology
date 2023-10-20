#include "NpcapDeviceList.h"
#include <pcap.h>
#include <iostream>

std::vector<NetworkDevice> GetNpcapDeviceList() {
    std::vector<NetworkDevice> deviceList;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // δ�ҵ������豸
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "û���ҵ������豸\n";
        return deviceList;
    }

    // ���������豸
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        NetworkDevice device;
        device.name = dev->name;
        device.description = (dev->description) ? dev->description : "N/A";
        deviceList.push_back(device);
    }

    // �ͷ������豸���ڴ�
    pcap_freealldevs(alldevs);
    return deviceList;
}
