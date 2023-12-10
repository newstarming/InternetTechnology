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
    // ��ʼ��Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    // �����׽���
    SOCKET clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        WSACleanup();
        return 1;
    }

    // ���÷�������ַ�Ͷ˿�
    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(12345);
    serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

    // ���ļ�
    std::ifstream file("file.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    // ���ʹ��ںͽ��մ���
    int sendBase = 0;
    int nextSeqNum = 0;
    Packet sendWindow[WINDOW_SIZE];
    bool acked[WINDOW_SIZE] = { false };

    // �������ݰ�
    while (sendBase < nextSeqNum || nextSeqNum < WINDOW_SIZE) {
        if (nextSeqNum < WINDOW_SIZE) {
            Packet packet;
            packet.seq = nextSeqNum;
            file.read(packet.data, MAX_PACKET_SIZE);

            if (file.gcount() == 0) {
                break;  // �ļ���ȡ���
            }

            sendWindow[nextSeqNum] = packet;
            sendto(clientSocket, reinterpret_cast<char*>(&packet), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, sizeof(serverAddress));
            std::cout << "Sent packet with sequence number: " << nextSeqNum << std::endl;

            nextSeqNum++;
        }

        // ����ACK
        Packet ackPacket;
        int addrLength = sizeof(serverAddress);
        int recvResult = recvfrom(clientSocket, reinterpret_cast<char*>(&ackPacket), sizeof(Packet), 0, (SOCKADDR*)&serverAddress, &addrLength);
        if (recvResult != SOCKET_ERROR) {
            int ack = ackPacket.seq;
            std::cout << "Received ACK for sequence number: " << ack << std::endl;

            if (ack >= sendBase && ack < nextSeqNum) {
                acked[ack] = true;

                // �������ʹ���
                while (acked[sendBase]) {
                    sendBase++;
                }
            }
        }
    }

    // �ر��׽��ֺ��ļ�
    closesocket(clientSocket);
    file.close();

    // ����Winsock
    WSACleanup();

    return 0;
}