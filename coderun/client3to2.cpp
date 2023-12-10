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
    SOCKET clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    // 设置服务器地址和端口
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(12345);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // 打开文件
    std::ifstream file("file.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // 发送窗口和接收窗口
    int sendBase = 0;
    int nextSeqNum = 0;
    Packet sendWindow[WINDOW_SIZE];
    bool acked[WINDOW_SIZE] = { false };

    // 发送数据包
    while (sendBase < nextSeqNum || nextSeqNum < WINDOW_SIZE) {
        if (nextSeqNum < WINDOW_SIZE) {
            Packet packet;
            packet.seq = nextSeqNum;
            file.read(packet.data, MAX_PACKET_SIZE);

            if (file.gcount() == 0) {
                break;  // 文件读取完毕
            }

            sendWindow[nextSeqNum] = packet;
            sendto(clientSocket, reinterpret_cast<char*>(&packet), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, sizeof(serverAddress));
            std::cout << "Sent packet with sequence number: " << nextSeqNum << std::endl;

            nextSeqNum++;
        }

        // 接收ACK
        Packet ackPacket;
        int addrLength = sizeof(serverAddress);
        int recvResult = recvfrom(clientSocket, reinterpret_cast<char*>(&ackPacket), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, &addrLength);
        if (recvResult != SOCKET_ERROR) {
            int ack = ackPacket.seq;
            std::cout << "Received ACK for sequence number: " << ack << std::endl;

            if (ack >= sendBase && ack < nextSeqNum) {
                acked[ack] = true;

                // 滑动发送窗口
                while (acked[sendBase]) {
                    sendBase++;
                }
            }
        }
    }

    // 关闭套接字和文件
    closesocket(clientSocket);
    file.close();

    // 清理Winsock
    WSACleanup();

    return 0;
}