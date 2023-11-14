#include"pcap.h"
#include<iostream>
#include<WinSock2.h>
#include<process.h>
#include<bitset>
#ifndef WIN32
#define WIN32
#endif
#define HAVE_REMOTE
#define BYTE unsigned char
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

pcap_t* choosed_dev;//全局变量
//IP数据报的提取
#pragma pack(1)
typedef struct FrameHeader_t { //帧首部
	BYTE DesMAC[6];			   //目的地址
	BYTE SrcMAC[6];			   //源地址
	WORD TrameType;			   //帧类型

}FrameHeader_t;

typedef struct IPHeader_t {     // IP首部
    BYTE Ver_HLen;
    BYTE TOS;
    WORD TotalLen;
    WORD ID;
    WORD Flag_Segment;
    BYTE TTL;
    BYTE Protocol;
    WORD Checksum;
    ULONG SrcIP;
    ULONG DstIP;
}IPHeader_t;

typedef struct Data_t { //包含帧首部和IP首部的数据包
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
}Data_t;

#pragma pack()

//获取设备列表
pcap_if_t* CAPLIST() {
    pcap_if_t   *alldevs;     //指向设备链表首部的指针
    pcap_if_t   *d;
    pcap_addr_t *a;
    int          n=1;         //通过n来选择后续想要监听的设备
    char        errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区

    //获取本机的设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,//获取本机的接口设备
        NULL,//无需认证
        &alldevs,//指向设备列表首部
        errbuf //出错信息保存缓冲区
    ) !=0)
    {
        //出错信息处理,标准错误输出
        cout << stderr << "error in pcap_findalldevs_ex" << errbuf << endl;
    }
    //=1时，显示接口列表
    
        for (d = alldevs; d != NULL; d = d->next) {
            cout <<n<<"."<< d->name;
            if (d->description)
                cout << ":" << d->description << endl;
            else
                cout << "NO DESCRIPTION FOUND;" << endl;
            n++;
        }
       
        //pcap_freealldevs(alldevs);
        return alldevs;//pcap_findalldevs_ex函数调用成功后，alldevs参数指向获取的网络接口列表的第一个元素
}
//监听选定的网络接口卡---打开网络接口
void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs) {
    //指针指向要监听的设备
    int i = 1;
    char        errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
    while (i < M )
    {
        D = D->next;
        i++;

    }
    //打开选择的网络接口，返回一个指向pcap_t的指针
    
    choosed_dev = pcap_open(D->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (choosed_dev == NULL) {
        cout << stderr << "error in pcap_open" << errbuf << endl;
        pcap_freealldevs(alldevs);
        return ;
    }
    return;


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
        int value= bArray [i];
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
//再打开的网络接口卡上捕获网络数据包
void Capture() {
    
    int i = 1;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
//循环调用pcap_next_ex()捕获数据报
    int m = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data);
    while (m!= -1) {
        //cout << pcap_next_ex(choosed_dev, &pkt_header, &pkt_data) << endl;
        if (m == 0) //pkt_data指向捕获到的网络数据包
            continue;
        else {
    //将捕获到的数据报信息进行输出；
            Data_t* pack; //包含帧首部和IP首部的数据包
            pack = (Data_t*)pkt_data;
            cout <<"捕获到的第"<< i << "个数据包：";
            cout << "源MAC地址：" << *(Byte2Hex(pack->FrameHeader.SrcMAC,6)) << endl;
            cout << "目的MAC地址：" << *(Byte2Hex(pack->FrameHeader.DesMAC,6)) << endl;
            cout << "类型：" << pack->FrameHeader.TrameType << endl;
            i++;
        }
        
        if (i == 10)
            break;
    }
    if ((pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) == -1)
        cout << "error in pcap_next_ex" << endl;
}


int main() {
    pcap_if_t  *alldevs;//指向设备链表首部的指针
    alldevs= CAPLIST();
    //选择要监听的设备
    cout << "请选择要监听的设备：";
    pcap_if_t  *D;
    D = alldevs;
    int m;
    cin >> m;
    //监听选定的网络接口卡---打开网络接口
    CHOOSEDEV(m,  D,  alldevs);
    Capture();

    pcap_freealldevs(alldevs);
}