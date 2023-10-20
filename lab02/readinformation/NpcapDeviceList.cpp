#include "NpcapDeviceList.h"
#include <pcap.h>
#include <iostream>

std::vector<NetworkDevice> GetNpcapDeviceList() {
    std::vector<NetworkDevice> deviceList;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 未找到网络设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "没有找到网络设备\n";
        return deviceList;
    }

    // 遍历网络设备
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        NetworkDevice device;
        device.name = dev->name;
        device.description = (dev->description) ? dev->description : "N/A";
        deviceList.push_back(device);
    }

    // 释放网络设备的内存
    pcap_freealldevs(alldevs);
    return deviceList;
}
