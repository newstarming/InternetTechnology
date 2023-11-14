#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)


//IP输出格式更改
string CoutIp(unsigned long u) {
    in_addr addr;
    memcpy(&addr, &u, sizeof(u));
    return inet_ntoa(addr);
}

//将地址由BYTE形式转换为16进制字符串类型
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


//指向要转换为字符串的网络字节中的 IP 地址的指针
void* get_in_addr(struct sockaddr* sa)
{
   //判断一下是否为IP
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

#pragma pack(1)
#define BYTE unsigned char

//帧首部
typedef struct FrameHeader_t {
    BYTE DesMAC[6]; //源MAC地址
    BYTE SrcMAC[6]; //目的MAC地址
    WORD FrameType; //帧类型
}FrameHeader_t;

//ARP帧
typedef struct ARPFrame_t {
    FrameHeader_t FrameHeader; //帧首部
    WORD HardwareType; //硬件类型
    WORD ProtocolType; //协议类型
    BYTE HLen;//硬件地址长度
    BYTE PLen;//协议地址长度
    WORD Operation;//操作类型
    BYTE SendHa[6];//源MAC地址
    DWORD SendIP;//源IP地址
    BYTE RecvHa[6];//目的MAC地址
    DWORD RecvIP;//目的IP地址
}ARPFrame_t;


#pragma pack()
ARPFrame_t ARPFrame;//要发送的APR数据包(其他主机）
ARPFrame_t ARPF_Send;//要发送的APR数据包（本机）
unsigned char mac[48], desmac[48];//目的主机和其他主机的mac
pcap_t* choosed_dev;//选择的网络接口

void ARP_show(struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct ARPFrame_t* arp_protocol;
    arp_protocol = (struct ARPFrame_t*)(pkt_data);

    cout << "源MAC地址：  " << *(Byte2Hex(arp_protocol->FrameHeader.SrcMAC, 6)) << endl;
    cout << "源IP地址：   " << CoutIp(arp_protocol->SendIP) << endl;
    cout << "目的MAC地址：" << *(Byte2Hex(arp_protocol->FrameHeader.DesMAC, 6)) << endl;
    cout << "目的IP地址  " << CoutIp(arp_protocol->RecvIP) << endl;
    cout << endl;
}

//获取本机网络接口的MAC地址和IP地址
pcap_if_t* CAPLIST() {
    pcap_if_t* alldevs;     //指向设备链表首部的指针
    pcap_if_t* d;
    pcap_addr_t* a;
    int          n = 1;         
    char        errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

   //获取本机的设备列表
   //调用pcap_findalldevs（）函数，alldevs指向的链表包含主机中安装的网络接口设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cout << stderr << "Error in pcap_findalldevs_ex:" << errbuf << endl;
        return 0;
    }


    //显示接口列表

    for (d = alldevs; d != NULL; d = d->next)
    {
        cout << n++ << "." << d->name;
        if (d->description)
            cout << "(" << d->description << ")" << endl;
        else
            cout << "(No description )\n";
        //获取该网络接口的IP地址信息
        for (a = d->addresses; a != NULL; a = a->next) {
            //判断该地址是否为IP地址
            if (a->addr->sa_family == AF_INET) {
                //输出网络接口卡上绑定的多个IP地址的相关信息
                char str[INET_ADDRSTRLEN];
                // 字符串转ip地址
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), str, sizeof(str)); //获取IP地址
                cout << "IP地址：" << str << endl;
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->netmask), str, sizeof(str));//获取网络掩码
                cout << "网络掩码：" << str << endl;
                inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->broadaddr), str, sizeof(str));//获取广播地址
                cout << "广播地址：" << str << endl;
               
            }
        }
    }
    if (n == 0)
    {
        cout << "\nERROR!\n";
       // return 0;
    }
    return alldevs;//pcap_findalldevs_ex函数调用成功后，alldevs参数指向获取的网络接口列表的第一个元素
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
        ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//设置为本机网卡的MAC地址
        ARPFrame.SendHa[i] = mac[i];//设置为本机网卡的MAC地址
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

    pcap_if_t* alldevs;//指向设备链表首部的指针
    pcap_if_t* d;
    pcap_addr_t* a;
   
    char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
    alldevs = CAPLIST();
    cout << "---------------------------------------------------------------------------------------------------------------------\n\n";
    
    //设备链表首部的指针
    d = alldevs;

    int j;
    cout << "请选择发送数据包的网卡：";
    cin >> j;
    int i = 0;
    //获取指向选择发送数据包网卡的指针
    
    while (i < j - 1) {
        i++;
        d = d->next;
    }
    

    //打开用户选择设备的网卡
    choosed_dev = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    
    if (choosed_dev == NULL) {
        cout << "Error pcap_open!" << errbuf << endl;
        //失败就释放设备列表；
        pcap_freealldevs(alldevs);
        return 0;
    }
    //保存网卡的ip地址（指向缓冲区的指针，用于存储 IP 地址的 NULL 终止字符串表示形式。）
    char ip[INET_ADDRSTRLEN];


    for (a = d->addresses; a != NULL; a = a->next) {
        //判断该地址是否为IP地址
        if (a->addr->sa_family == AF_INET) {
        //InetNtop 函数将 IPv4 或 IPv6 Internet 网络地址转换为采用 Internet 标准格式的字符串->ip
            inet_ntop(AF_INET, get_in_addr((struct sockaddr*)a->addr), ip, sizeof(ip));
        }
    }
    cout << ip;
    cout << endl << d->name << endl;

    //获取本机的MAC地址
   
    //设置ARP帧相关
    SET_ARP_Frame_HOST(ARPF_Send, ip);

    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    struct pcap_pkthdr* header = new pcap_pkthdr;
    int k;
    //发送构造好的数据包
    //用pcap_next_ex()捕获数据包，pkt_data指向捕获到的网络数据包
    while ((k = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) >= 0) {
        //发送数据包
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
           {   //帧类型为ARP，且操作类型为ARP响应，SendIp为发送的数据包中的RecvIP
               /* if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002)
                   && *(unsigned long*)(pkt_data + 28) == ARPF_Send.RecvIP) {*/

               if(arp_message->FrameHeader.FrameType==htons(0x0806)&& arp_message->Operation == htons(0x0002)){
                   cout << "ARP数据包：\n";
                   ARP_show(header, pkt_data);//打印相应的信息
                   //用MAC地址记录本机的MAC地址，用于后续构造ARP数据包
                   for (int i = 0; i < 6; i++) {
                       mac[i] = *(unsigned char*)(pkt_data + 22 + i);
                   }
                   cout << "获取本机MAC地址为：" << *(Byte2Hex(mac, 6)) << endl;
                   break;
               }
           }
       }
    
    if (k < 0) {
        cout << "Error in pcap_next_ex." << endl;
    }
    cout << "-------------------------------------------------------------------------------------------------------------------------------------------\n\n";
    
    //设置ARP帧

    SET_ARP_Frame_DEST(ARPFrame,ip, mac, desmac);

    cout << "请输入目的主机的IP地址：";
    char desip[INET_ADDRSTRLEN];
    cin >> desip;
    ARPFrame.RecvIP = inet_addr(desip); //设置为请求的IP地址

    while ((k = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) >= 0) {
        //pcap_sendpacket（）发送构造好的数据包
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
            cout << "ARP数据包：\n";
            ARP_show(header, pkt_data);
            for (int i = 0; i < 6; i++) {
            //记录得到的目的主机的MAC地址
                desmac[i] = *(unsigned char*)(pkt_data + 22 + i);
            }
            cout << "获取目的主机的MAC地址为：" << *(Byte2Hex(desmac, 6)) << endl;
            break;
        }
    }
    pcap_freealldevs(alldevs);
  //  system("pause");
}