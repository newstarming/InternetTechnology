#include "NpcapDeviceControl.h"
#include <iostream>

pcap_t* OpenNpcapDevice(const char* deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open(deviceName, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);

    if (handle == nullptr) {
        std::cerr << "打开设备错误 " << deviceName << ": " << errbuf << std::endl;
    }

    return handle;
}
