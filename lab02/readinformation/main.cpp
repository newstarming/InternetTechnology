#include "NpcapDeviceList.h"
#include "NpcapDeviceControl.h"
#include "NpcapPacketCapture.h"
#include "NpcapPacketHandler.h"
#include "NpcapCapture.h"
#include <iostream>

int main(){
	//pcap_if_t* alldevs;
	//pcap_if_t* d;
	//int i = 0;
	//char errbuf[PCAP_ERRBUF_SIZE];
	///* Retrieve the device list from the local machine */
	//if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1){
	//	fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
	//	exit(1);
	//}
	///* Print the list */
	//for (d = alldevs; d != NULL; d = d->next){
	//	printf("%d. %s", ++i, d->name);
	//	if (d->description)
	//		printf(" (%s)\n", d->description);
	//	else
	//		printf(" (No description available)\n");
	//}
	//if (i == 0){
	//	printf("\nNo interfaces found! Make sure Npcap is installed.\n");
	//	return 0;
	//}
	///* We don't need any more the device list. Free it */
	//pcap_freealldevs(alldevs);


	///*
	//* 设备列表获取
	//*/
	//std::vector<NetworkDevice> devices = GetNpcapDeviceList();

	//if (!devices.empty()) {
	//	std::cout << "NPcap Device List:\n";
	//	for (const NetworkDevice& device : devices) {
	//		std::cout << "Device Name: " << device.name << "\n";
	//		std::cout << "Description: " << device.description << "\n\n";
	//	}
	//}
	//else {
	//	std::cerr << "Failed to retrieve device list." << std::endl;
	//}

	///*
	//* 网卡设备打开
	//*/
	//const char* deviceName = "\\Device\\NPF_{F09ED677-039B-4645-8312-65F369FF4216}"; // 替换为实际设备名称,这里是本机的wifi

	//pcap_t* deviceHandle = OpenNpcapDevice(deviceName);

	//if (deviceHandle != nullptr) {
	//	// 打开设备成功，可以继续捕获数据包或其他操作
	//	// 例如：pcap_loop(deviceHandle, 0, packetHandler, nullptr);
	//	// 其中packetHandler是一个用户定义的数据包处理函数
	//	std::cout << "打开网卡设备成功！\n";

	//	/*
	//	* 捕获数据包
	//	*/
	//	int numPackets = 10;  // 捕获的数据包数量

	//	pcap_t* handle = InitializePacketCapture(deviceName);

	//	if (handle != nullptr) {
	//		CapturePackets(handle, numPackets, packetHandler);
	//		ClosePacketCapture(handle);
	//	}
	//	else {
	//		std::cerr << "Failed to initialize packet capture." << std::endl;
	//	}
	//	system("pause");
	//	pcap_close(deviceHandle); // 记得在不需要时关闭设备
	//}
	//else {
	//	std::cerr << "Failed to open the device." << std::endl;
	//}

	pcap_if_t* alldevs;//指向设备链表首部的指针
	alldevs = MYCAPTURELIST();
	//选择要监听的设备
	std::cout << "请选择要监听的设备：";
	pcap_if_t* D;
	D = alldevs;
	int m;
	std::cin >> m;
	//监听选定的网络接口卡---打开网络接口
	CHOOSEDEV(m, D, alldevs);

	Capture();

	pcap_freealldevs(alldevs);

	system("pause");
	return 0;
}


//#include"pcap.h"
//#include<iostream>
//#include<WinSock2.h>
//#include<process.h>
//#include<bitset>
//#define WIN32
//#define HAVE_REMOTE
//#define BYTE unsigned char
//using namespace std;
//#pragma comment(lib,"wpcap.lib")
//#pragma comment(lib,"ws2_32.lib")
//#pragma warning(disable:4996)
//
//pcap_t* choosed_dev;//全局变量
////IP数据报的提取
//#pragma pack(1)
//typedef struct FrameHeader_t { //帧首部
//    BYTE DesMAC[6];			   //目的地址
//    BYTE SrcMAC[6];			   //源地址
//    WORD TrameType;			   //帧类型
//
//}FrameHeader_t;
//
//typedef struct IPHeader_t {     // IP首部
//    BYTE Ver_HLen;
//    BYTE TOS;
//    WORD TotalLen;
//    WORD ID;
//    WORD Flag_Segment;
//    BYTE TTL;
//    BYTE Protocol;
//    WORD Checksum;
//    ULONG SrcIP;
//    ULONG DstIP;
//}IPHeader_t;
//
//typedef struct Data_t { //包含帧首部和IP首部的数据包
//    FrameHeader_t FrameHeader;
//    IPHeader_t IPHeader;
//}Data_t;
//
//#pragma pack()
//
////获取设备列表
//pcap_if_t* CAPLIST() {
//    pcap_if_t* alldevs;     //指向设备链表首部的指针
//    pcap_if_t* d;
//    pcap_addr_t* a;
//    int          n = 1;         //通过n来选择后续想要监听的设备
//    char        errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
//
//    //获取本机的设备列表
//    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,//获取本机的接口设备
//        NULL,//无需认证
//        &alldevs,//指向设备列表首部
//        errbuf //出错信息保存缓冲区
//    ) != 0)
//    {
//        //出错信息处理,标准错误输出
//        cout << stderr << "error in pcap_findalldevs_ex" << errbuf << endl;
//    }
//    //=1时，显示接口列表
//
//    for (d = alldevs; d != NULL; d = d->next) {
//        cout << n << "." << d->name;
//        if (d->description)
//            cout << ":" << d->description << endl;
//        else
//            cout << "NO DESCRIPTION FOUND;" << endl;
//        n++;
//    }
//
//    //pcap_freealldevs(alldevs);
//    return alldevs;//pcap_findalldevs_ex函数调用成功后，alldevs参数指向获取的网络接口列表的第一个元素
//}
////监听选定的网络接口卡---打开网络接口
//void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs) {
//    //指针指向要监听的设备
//    int i = 1;
//    char        errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
//    while (i < M)
//    {
//        D = D->next;
//        i++;
//
//    }
//    //打开选择的网络接口，返回一个指向pcap_t的指针
//
//    choosed_dev = pcap_open(D->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
//    if (choosed_dev == NULL) {
//        cout << stderr << "error in pcap_open" << errbuf << endl;
//        pcap_freealldevs(alldevs);
//        return;
//    }
//    return;
//
//
//}
////将地址由BYTE形式转换为16进制字符串类型
//string* Byte2Hex(unsigned char bArray[], int bArray_len)
//{
//    string* strHex = new string();
//    int nIndex = 0;
//    for (int i = 0; i < bArray_len; i++)
//    {
//        char hex1;
//        char hex2;
//        int value = bArray[i];
//        int S = value / 16;
//        int Y = value % 16;
//        if (S >= 0 && S <= 9)
//            hex1 = (char)(48 + S);
//        else
//            hex1 = (char)(55 + S);
//        if (Y >= 0 && Y <= 9)
//            hex2 = (char)(48 + Y);
//        else
//            hex2 = (char)(55 + Y);
//        if (i != bArray_len - 1) {
//            *strHex = *strHex + hex1 + hex2 + "-";
//        }
//        else
//            *strHex = *strHex + hex1 + hex2;
//    }
//
//    return strHex;
//}
////再打开的网络接口卡上捕获网络数据包
//void Capture() {
//
//    int i = 1;
//    struct pcap_pkthdr* pkt_header;
//    const u_char* pkt_data;
//    //循环调用pcap_next_ex()捕获数据报
//    int m = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data);
//    while (m != -1) {
//        //cout << pcap_next_ex(choosed_dev, &pkt_header, &pkt_data) << endl;
//        if (m == 0) //pkt_data指向捕获到的网络数据包
//            continue;
//        else {
//            //将捕获到的数据报信息进行输出；
//            Data_t* pack; //包含帧首部和IP首部的数据包
//            pack = (Data_t*)pkt_data;
//            cout << "捕获到的第" << i << "个数据包：";
//            cout << "源MAC地址：" << *(Byte2Hex(pack->FrameHeader.SrcMAC, 6)) << endl;
//            cout << "目的MAC地址：" << *(Byte2Hex(pack->FrameHeader.DesMAC, 6)) << endl;
//            cout << "类型：" << pack->FrameHeader.TrameType << endl;
//            i++;
//        }
//
//        if (i == 10)
//            break;
//    }
//    if ((pcap_next_ex(choosed_dev, &pkt_header, &pkt_data)) == -1)
//        cout << "error in pcap_next_ex" << endl;
//}
//
//
//int main() {
//
//    //CAPLIST();
//    pcap_if_t* alldevs;//指向设备链表首部的指针
//    alldevs = CAPLIST();
//    //选择要监听的设备
//    cout << "请选择要监听的设备：";
//    pcap_if_t* D;
//    D = alldevs;
//    int m;
//    cin >> m;
//    //监听选定的网络接口卡---打开网络接口
//    CHOOSEDEV(m, D, alldevs);
//    Capture();
//    pcap_freealldevs(alldevs);
//}




