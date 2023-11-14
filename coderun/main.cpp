#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)


//IP�����ʽ����
string CoutIp(unsigned long u) {
    in_addr addr;
    memcpy(&addr, &u, sizeof(u));
    return inet_ntoa(addr);
}

//����ַ��BYTE��ʽת��Ϊ16�����ַ�������
string* Byte2Hex(unsigned char bArray[], int bArray_len)
{
    string* strHex = new string();
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


//ָ��Ҫת��Ϊ�ַ����������ֽ��е� IP ��ַ��ָ��
void* get_in_addr(struct sockaddr* sa)
{
   //�ж�һ���Ƿ�ΪIP
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

#pragma pack(1)
#define BYTE unsigned char

//֡�ײ�
typedef struct FrameHeader_t {
    BYTE DesMAC[6]; //ԴMAC��ַ
    BYTE SrcMAC[6]; //Ŀ��MAC��ַ
    WORD FrameType; //֡����
}FrameHeader_t;

//ARP֡
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader; //֡�ײ�
    WORD HardwareType; //Ӳ������
    WORD ProtocolType; //Э������
    BYTE HLen;//Ӳ����ַ����
    BYTE PLen;//Э���ַ����
    WORD Operation;//��������
    BYTE SendHa[6];//ԴMAC��ַ
    DWORD SendIP;//ԴIP��ַ
    BYTE RecvHa[6];//Ŀ��MAC��ַ
    DWORD RecvIP;//Ŀ��IP��ַ
}ARPFrame_t;


#pragma pack()
ARPFrame_t ARPFrame;//Ҫ���͵�APR���ݰ�(����������
ARPFrame_t ARPF_Send;//Ҫ���͵�APR���ݰ���������
unsigned char mac[48], desmac[48];//Ŀ������������������mac
pcap_t* choosed_dev;//ѡ�������ӿ�

void ARP_show(struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct ARPFrame_t* arp_protocol;
    arp_protocol = (struct ARPFrame_t*)(pkt_data);

    cout << "ԴMAC��ַ��  " << *(Byte2Hex(arp_protocol->FrameHeader.SrcMAC, 6)) << endl;
    cout << "ԴIP��ַ��   " << CoutIp(arp_protocol->SendIP) << endl;
    cout << "Ŀ��MAC��ַ��" << *(Byte2Hex(arp_protocol->FrameHeader.DesMAC, 6)) << endl;
    cout << "Ŀ��IP��ַ  " << CoutIp(arp_protocol->RecvIP) << endl;
    cout << endl;
}

//��ȡ��������ӿڵ�MAC��ַ��IP��ַ
pcap_if_t* CAPLIST() {
    pcap_if_t* alldevs;     //ָ���豸�����ײ���ָ��
    pcap_if_t* d;
    pcap_addr_t* a;
    int          n = 1;         
    char        errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������

   //��ȡ�������豸�б�
   //����pcap_findalldevs����������alldevsָ���������������а�װ������ӿ��豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cout << stderr << "Error in pcap_findalldevs_ex:" << errbuf << endl;
        return 0;
    }


    //��ʾ�ӿ��б�

    for (d = alldevs; d != NULL; d = d->next)
    {
        cout << n++ << "." << d->name;
        if (d->description)
            cout << "(" << d->description << ")" << endl;
        else
            cout << "(No description )\n";
        //��ȡ������ӿڵ�IP��ַ��Ϣ
        for (a = d->addresses; a != NULL; a = a->next) {
            //�жϸõ�ַ�Ƿ�ΪIP��ַ
            if (a->addr->sa_family == AF_INET) {
                //�������ӿڿ��ϰ󶨵Ķ��IP��ַ�������Ϣ
                char str[INET_ADDRSTRLEN];
                // �ַ���תip��ַ
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), str, sizeof(str)); //��ȡIP��ַ
                cout << "IP��ַ��" << str << endl;
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->netmask), str, sizeof(str));//��ȡ��������
                cout << "�������룺" << str << endl;
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->broadaddr), str, sizeof(str));//��ȡ�㲥��ַ
                cout << "�㲥��ַ��" << str << endl;
               
            }
        }
    }
    if (n == 0)
    {
        cout << "\nERROR!\n";
       // return 0;
    }
    return alldevs;//pcap_findalldevs_ex�������óɹ���alldevs����ָ���ȡ������ӿ��б�ĵ�һ��Ԫ��
}


void SET_ARP_Frame_HOST(ARPFrame_t &ARPFrame1, char ip[INET_ADDRSTRLEN]) {
    for (int i = 0; i < 6; i++) {
        ARPFrame1.FrameHeader.DesMAC[i] = 0xff;
        ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;
        ARPFrame1.SendHa[i] = 0x0f;
        ARPFrame1.RecvHa[i] = 0x00;
    }

    ARPFrame1.FrameHeader.FrameType = htons(0x0806);
    ARPFrame1.HardwareType = htons(0x0001);
    ARPFrame1.ProtocolType = htons(0x0800);
    ARPFrame1.HLen = 6;
    ARPFrame1.PLen = 4;
    ARPFrame1.Operation = htons(0x0001);
    ARPFrame1.SendIP = inet_addr("10.10.10.10");
    ARPFrame1.RecvIP = inet_addr(ip);
}
void SET_ARP_Frame_DEST(ARPFrame_t& ARPFrame , char ip[INET_ADDRSTRLEN],unsigned char*mac, unsigned char*desmac) {
    for (int i = 0; i < 6; i++) {
        ARPFrame.FrameHeader.DesMAC[i] = 0xff;
        ARPFrame.RecvHa[i] = 0x00;
        ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//����Ϊ����������MAC��ַ
        ARPFrame.SendHa[i] = mac[i];//����Ϊ����������MAC��ַ
    }
    ARPFrame.FrameHeader.FrameType = htons(0x0806);
    ARPFrame.HardwareType = htons(0x0001);
    ARPFrame.ProtocolType = htons(0x0800);
    ARPFrame.HLen = 6;
    ARPFrame.PLen = 4;
    ARPFrame.Operation = htons(0x0001);
    ARPFrame.SendIP = inet_addr(ip);

}


int main() {

    pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
    pcap_if_t* d;
    pcap_addr_t* a;
   
    char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
    alldevs = CAPLIST();
    cout << "---------------------------------------------------------------------------------------------------------------------\n\n";
    
    //�豸�����ײ���ָ��
    d = alldevs;

    int j;
    cout << "��ѡ�������ݰ���������";
    cin >> j;
    int i = 0;
    //��ȡָ��ѡ�������ݰ�������ָ��
    
    while (i < j - 1) {
        i++;
        d = d->next;
    }
    

    //���û�ѡ���豸������
    choosed_dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    
    if (choosed_dev == NULL) {
        cout << "Error pcap_open!" << errbuf << endl;
        //ʧ�ܾ��ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return 0;
    }
    //����������ip��ַ��ָ�򻺳�����ָ�룬���ڴ洢 IP ��ַ�� NULL ��ֹ�ַ�����ʾ��ʽ����
    char ip[INET_ADDRSTRLEN];


    for (a = d->addresses; a != NULL; a = a->next) {
        //�жϸõ�ַ�Ƿ�ΪIP��ַ
        if (a->addr->sa_family == AF_INET) {
        //InetNtop ������ IPv4 �� IPv6 Internet �����ַת��Ϊ���� Internet ��׼��ʽ���ַ���->ip
            inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), ip, sizeof(ip));
        }
    }
    cout << ip;
    cout << endl << d->name << endl;

    //��ȡ������MAC��ַ
   
    //����ARP֡���
    SET_ARP_Frame_HOST(ARPF_Send, ip);

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    struct pcap_pkthdr* header = new pcap_pkthdr;
    int k;
    //���͹���õ����ݰ�
    //��pcap_next_ex()�������ݰ���pkt_dataָ�򲶻񵽵��������ݰ�
    while ((k = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) >= 0) {
        //�������ݰ�
       /* if (pcap_sendpacket(choosed_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t)) != 0) {
            cout << "Error in pcap_sendpacket";
            pcap_freealldevs(alldevs);
            return 0;
        }
        */
        pcap_sendpacket(choosed_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
           if (k == 0)continue;
           else
           {   //֡����ΪARP���Ҳ�������ΪARP��Ӧ��SendIpΪ���͵����ݰ��е�RecvIP
               /* if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002)
                   && *(unsigned long*)(pkt_data + 28) == ARPF_Send.RecvIP) {*/

               if(arp_message->FrameHeader.FrameType==htons(0x0806)&& arp_message->Operation == htons(0x0002)){
                   cout << "ARP���ݰ���\n";
                   ARP_show(header, pkt_data);//��ӡ��Ӧ����Ϣ
                   //��MAC��ַ��¼������MAC��ַ�����ں�������ARP���ݰ�
                   for (int i = 0; i < 6; i++) {
                       mac[i] = *(unsigned char*)(pkt_data + 22 + i);
                   }
                   cout << "��ȡ����MAC��ַΪ��" << *(Byte2Hex(mac, 6)) << endl;
                   break;
               }
           }
       }
    
    if (k < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    cout << "-------------------------------------------------------------------------------------------------------------------------------------------\n\n";
    
    //����ARP֡

    SET_ARP_Frame_DEST(ARPFrame,ip, mac, desmac);

    cout << "������Ŀ��������IP��ַ��";
    char desip[INET_ADDRSTRLEN];
    cin >> desip;
    ARPFrame.RecvIP = inet_addr(desip); //����Ϊ�����IP��ַ

    while ((k = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) >= 0) {
        //pcap_sendpacket�������͹���õ����ݰ�
        /*
        if (pcap_sendpacket(choosed_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) {
            cout << "Error in pcap_sendpacket";
            pcap_freealldevs(alldevs);
            return 0;
        }
        */
        pcap_sendpacket(choosed_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
        struct ARPFrame_t* arp_message;
        arp_message = (struct ARPFrame_t*)(pkt_data);
        if (k == 0)continue;
        else 
            //if (*(unsigned short*)(pkt_data + 12) == htons(0x0806)
        //    && *(unsigned short*)(pkt_data + 20) == htons(0x0002)
        //    //&& *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP
        //    ) {
         if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) {
            cout << "ARP���ݰ���\n";
            ARP_show(header, pkt_data);
            for (int i = 0; i < 6; i++) {
            //��¼�õ���Ŀ��������MAC��ַ
                desmac[i] = *(unsigned char*)(pkt_data + 22 + i);
            }
            cout << "��ȡĿ��������MAC��ַΪ��" << *(Byte2Hex(desmac, 6)) << endl;
            break;
        }
    }
    pcap_freealldevs(alldevs);
  //  system("pause");
}