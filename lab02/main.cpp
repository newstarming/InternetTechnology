#include <iostream>
#include <pcap.h>
#include <vector>

// 用于存储网络设备信息
struct NetworkDevice {
    std::string name;
    std::string description;
};
// 获取本机的所有网络设备并标号存储
std::vector<NetworkDevice> GetNpcapDeviceList();
// 打开选定的设备
pcap_t* OpenNpcapDevice(const char* deviceName);
// 捕获数据包并解析
void CaptureAndDisplayPackets(pcap_t* handle, int numPackets);

int main() {
    std::vector<NetworkDevice> devices = GetNpcapDeviceList();
    if (devices.empty()) {
        std::cerr << "No devices found. Exiting." << std::endl;
        return 1;
    }
    std::cout << "选择设备标号: ";
    int deviceIndex;
    std::cin >> deviceIndex;
    if (deviceIndex < 1 || deviceIndex > devices.size()) {
        std::cerr << "Invalid device selection. Exiting." << std::endl;
        return 1;
    }
    // 打开选定的设备
    pcap_t* handle = OpenNpcapDevice(devices[deviceIndex - 1].name.c_str());
    if (handle != nullptr) {
        std::cout << "要抓取数据包的数量：";
        int numPackets;
        std::cin >> numPackets;
        CaptureAndDisplayPackets(handle, numPackets);
        pcap_close(handle);
    }
    return 0;
}
// 获取本机的所有网络设备并标号存储
std::vector<NetworkDevice> GetNpcapDeviceList() {
    std::vector<NetworkDevice> deviceList;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return deviceList;
    }
    int deviceIndex = 1;
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        NetworkDevice device;
        device.name = dev->name;
        device.description = (dev->description) ? dev->description : "N/A";
        deviceList.push_back(device);
        std::cout << deviceIndex << ". " << device.name << " - " << device.description << std::endl;
        deviceIndex++;
    }

    pcap_freealldevs(alldevs);
    return deviceList;
}
// 打开选定的设备
pcap_t* OpenNpcapDevice(const char* deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
    }
    return handle;
}
// 捕获数据包并解析
void CaptureAndDisplayPackets(pcap_t* handle, int numPackets) {
    struct pcap_pkthdr header;
    const u_char* packet;
    for (int i = 0; i < numPackets; ++i) {
        packet = pcap_next(handle, &header);
        if (packet == nullptr) {
            std::cerr << "No more packets to capture." << std::endl;
            break;
        }
        // 解析以太网帧
        unsigned char* sourceMac = (unsigned char*)(packet);
        unsigned char* destMac = (unsigned char*)(packet + 6);
        unsigned short etherType = (packet[12] << 8) + packet[13];
        // 显示结果
        std::cout << "Packet " << i + 1 << ":\n";
        std::cout << "Source MAC: ";
        for (int j = 0; j < 6; ++j) {
            std::cout << std::hex << (int)sourceMac[j];
            if (j < 5) std::cout << ':';
        }
        std::cout << "\nDest MAC: ";
        for (int j = 0; j < 6; ++j) {
            std::cout << std::hex << (int)destMac[j];
            if (j < 5) std::cout << ':';
        }
        std::cout << "\nType/Length: 0x" << std::hex << etherType << "\n\n";
    }
}