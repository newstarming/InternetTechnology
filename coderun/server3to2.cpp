#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_PACKET_SIZE 1024
#define WINDOW_SIZE 10

struct Packet {
    int seq;
    char data[MAX_PACKET_SIZE];
};

int main() {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    // 创建套接字
    SOCKET serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    // 绑定套接字到端口
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(12345);
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    if (bind(serverSocket, (SOCKADDR*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Failed to bind socket" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // 接收窗口
    int expectedSeqNum = 0;
    Packet receiveWindow[WINDOW_SIZE];
    bool received[WINDOW_SIZE] = { false };

    // 接收数据包
    while (true) {
        Packet packet;
        int addrLength = sizeof(serverAddress);
        int recvResult = recvfrom(serverSocket, reinterpret_cast<char*>(&packet), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, &addrLength);
        if (recvResult != SOCKET_ERROR) {
            int seq = packet.seq;
            std::cout << "Received packet with sequence number: " << seq << std::endl;

            if (seq == expectedSeqNum) {
                receiveWindow[seq] = packet;
                received[seq] = true;

                // 滑动接收窗口
                while (received[expectedSeqNum]) {
                    std::cout << "Delivered packet with sequence number: " << expectedSeqNum << std::endl;

                    // 将数据写入文件
                    std::ofstream file("received_file.txt", std::ios::binary | std::ios::app);
                    file.write(receiveWindow[expectedSeqNum].data, MAX_PACKET_SIZE);
                    file.close();

                    expectedSeqNum++;
                }
            }

            // 发送ACK
            Packet ackPacket;
            ackPacket.seq = seq;
            sendto(serverSocket, reinterpret_cast<char*>(&ackPacket), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, sizeof(serverAddress));
            std::cout << "Sent ACK for sequence number: " << seq << std::endl;
        }
    }

    // 关闭套接字
    closesocket(serverSocket);

    // 清理Winsock
    WSACleanup();

    return 0;
}