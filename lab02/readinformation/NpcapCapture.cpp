#include "NpcapCapture.h"
#include<WinSock2.h>
#include<process.h>
#include<bitset>
#define WIN32
#define HAVE_REMOTE
#define BYTE unsigned char
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

// ���ݰ�����ص�����
void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkt_header, const unsigned char* pkt_data) {
    // ���ݰ������߼����������������ԴMAC��Ŀ��MAC�������ֶε���Ϣ
    // �ο�ԭ�д����е����ݰ�������
}

// �������ݰ�����
void startPacketCapture(const char* deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // ������ӿ�
    handle = pcap_open(deviceName, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

    if (handle == NULL) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    // ��ʼ�������ݰ������ݸ�packetHandler��������
    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
}

//��ȡ�豸�б�
pcap_if_t* MYCAPTURELIST() {
    pcap_if_t* alldevs;     //ָ���豸�����ײ���ָ��
    pcap_if_t* d;
    //pcap_addr_t* a;
    int          n = 1;         //ͨ��n��ѡ�������Ҫ�������豸
    char        errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������

    //��ȡ�������豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,//��ȡ�����Ľӿ��豸
        NULL,//������֤
        &alldevs,//ָ���豸�б��ײ�
        errbuf //������Ϣ���滺����
    ) != 0)
    {
        //������Ϣ����,��׼�������
        std::cout << stderr << "error in pcap_findalldevs_ex" << errbuf << std::endl;
    }
    //=1ʱ����ʾ�ӿ��б�

    for (d = alldevs; d != NULL; d = d->next) {
        std::cout << n << "." << d->name;
        if (d->description)
            std::cout << ":" << d->description << std::endl;
        else
            std::cout << "NO DESCRIPTION FOUND;" << std::endl;
        n++;
    }

    //pcap_freealldevs(alldevs);
    return alldevs;//pcap_findalldevs_ex�������óɹ���alldevs����ָ���ȡ������ӿ��б�ĵ�һ��Ԫ��
}

//����ѡ��������ӿڿ�---������ӿ�
void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs) {
    //ָ��ָ��Ҫ�������豸
    int i = 1;
    char        errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
    while (i < M)
    {
        D = D->next;
        i++;

    }
    //��ѡ�������ӿڣ�����һ��ָ��pcap_t��ָ��

    choosed_dev = pcap_open(D->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (choosed_dev == NULL) {
        std::cout << stderr << "error in pcap_open" << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return;
    }
    return;


}
//����ַ��BYTE��ʽת��Ϊ16�����ַ�������
std::string* Byte2Hex(unsigned char bArray[], int bArray_len)
{
    std::string* strHex = new std::string();
    int nIndex = 0;
    for (int i = 0; i < bArray_len; i++)
    {
        char hex1;
        char hex2;
        int value = bArray[i];
        int S = value / 16;
        int Y = value % 16;
        if (S >= 0 && S <= 9)
            hex1 = (char)(48 + S);
        else
            hex1 = (char)(55 + S);
        if (Y >= 0 && Y <= 9)
            hex2 = (char)(48 + Y);
        else
            hex2 = (char)(55 + Y);
        if (i != bArray_len - 1) {
            *strHex = *strHex + hex1 + hex2 + "-";
        }
        else
            *strHex = *strHex + hex1 + hex2;
    }

    return strHex;
}
//�ٴ򿪵�����ӿڿ��ϲ����������ݰ�
void Capture() {

    int i = 1;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    //ѭ������pcap_next_ex()�������ݱ�
    int m = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data);
    while (m != -1) {
        //cout << pcap_next_ex(choosed_dev, &pkt_header, &pkt_data) << endl;
        if (m == 0) //pkt_dataָ�򲶻񵽵��������ݰ�
            continue;
        else {
            //�����񵽵����ݱ���Ϣ���������
            Data_t* pack; //����֡�ײ���IP�ײ������ݰ�
            pack = (Data_t*)pkt_data;
            std::cout << "���񵽵ĵ�" << i << "�����ݰ���";
            std::cout << "ԴMAC��ַ��" << *(Byte2Hex(pack->FrameHeader.SrcMAC, 6)) << std::endl;
            std::cout << "Ŀ��MAC��ַ��" << *(Byte2Hex(pack->FrameHeader.DesMAC, 6)) << std::endl;
            std::cout << "���ͣ�" << pack->FrameHeader.TrameType << std::endl;
            i++;
        }
        if (i == 10)
            break;
    }
    if ((pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) == -1)
        std::cout << "error in pcap_next_ex" << std::endl;
}