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
	//* �豸�б��ȡ
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
	//* �����豸��
	//*/
	//const char* deviceName = "\\Device\\NPF_{F09ED677-039B-4645-8312-65F369FF4216}"; // �滻Ϊʵ���豸����,�����Ǳ�����wifi

	//pcap_t* deviceHandle = OpenNpcapDevice(deviceName);

	//if (deviceHandle != nullptr) {
	//	// ���豸�ɹ������Լ����������ݰ�����������
	//	// ���磺pcap_loop(deviceHandle, 0, packetHandler, nullptr);
	//	// ����packetHandler��һ���û���������ݰ�������
	//	std::cout << "�������豸�ɹ���\n";

	//	/*
	//	* �������ݰ�
	//	*/
	//	int numPackets = 10;  // ��������ݰ�����

	//	pcap_t* handle = InitializePacketCapture(deviceName);

	//	if (handle != nullptr) {
	//		CapturePackets(handle, numPackets, packetHandler);
	//		ClosePacketCapture(handle);
	//	}
	//	else {
	//		std::cerr << "Failed to initialize packet capture." << std::endl;
	//	}
	//	system("pause");
	//	pcap_close(deviceHandle); // �ǵ��ڲ���Ҫʱ�ر��豸
	//}
	//else {
	//	std::cerr << "Failed to open the device." << std::endl;
	//}

	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	alldevs = MYCAPTURELIST();
	//ѡ��Ҫ�������豸
	std::cout << "��ѡ��Ҫ�������豸��";
	pcap_if_t* D;
	D = alldevs;
	int m;
	std::cin >> m;
	//����ѡ��������ӿڿ�---������ӿ�
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
//pcap_t* choosed_dev;//ȫ�ֱ���
////IP���ݱ�����ȡ
//#pragma pack(1)
//typedef struct FrameHeader_t { //֡�ײ�
//    BYTE DesMAC[6];			   //Ŀ�ĵ�ַ
//    BYTE SrcMAC[6];			   //Դ��ַ
//    WORD TrameType;			   //֡����
//
//}FrameHeader_t;
//
//typedef struct IPHeader_t {     // IP�ײ�
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
//typedef struct Data_t { //����֡�ײ���IP�ײ������ݰ�
//    FrameHeader_t FrameHeader;
//    IPHeader_t IPHeader;
//}Data_t;
//
//#pragma pack()
//
////��ȡ�豸�б�
//pcap_if_t* CAPLIST() {
//    pcap_if_t* alldevs;     //ָ���豸�����ײ���ָ��
//    pcap_if_t* d;
//    pcap_addr_t* a;
//    int          n = 1;         //ͨ��n��ѡ�������Ҫ�������豸
//    char        errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
//
//    //��ȡ�������豸�б�
//    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,//��ȡ�����Ľӿ��豸
//        NULL,//������֤
//        &alldevs,//ָ���豸�б��ײ�
//        errbuf //������Ϣ���滺����
//    ) != 0)
//    {
//        //������Ϣ����,��׼�������
//        cout << stderr << "error in pcap_findalldevs_ex" << errbuf << endl;
//    }
//    //=1ʱ����ʾ�ӿ��б�
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
//    return alldevs;//pcap_findalldevs_ex�������óɹ���alldevs����ָ���ȡ������ӿ��б�ĵ�һ��Ԫ��
//}
////����ѡ��������ӿڿ�---������ӿ�
//void CHOOSEDEV(int M, pcap_if_t* D, pcap_if_t* alldevs) {
//    //ָ��ָ��Ҫ�������豸
//    int i = 1;
//    char        errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
//    while (i < M)
//    {
//        D = D->next;
//        i++;
//
//    }
//    //��ѡ�������ӿڣ�����һ��ָ��pcap_t��ָ��
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
////����ַ��BYTE��ʽת��Ϊ16�����ַ�������
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
////�ٴ򿪵�����ӿڿ��ϲ����������ݰ�
//void Capture() {
//
//    int i = 1;
//    struct pcap_pkthdr* pkt_header;
//    const u_char* pkt_data;
//    //ѭ������pcap_next_ex()�������ݱ�
//    int m = pcap_next_ex(choosed_dev, &pkt_header, &pkt_data);
//    while (m != -1) {
//        //cout << pcap_next_ex(choosed_dev, &pkt_header, &pkt_data) << endl;
//        if (m == 0) //pkt_dataָ�򲶻񵽵��������ݰ�
//            continue;
//        else {
//            //�����񵽵����ݱ���Ϣ���������
//            Data_t* pack; //����֡�ײ���IP�ײ������ݰ�
//            pack = (Data_t*)pkt_data;
//            cout << "���񵽵ĵ�" << i << "�����ݰ���";
//            cout << "ԴMAC��ַ��" << *(Byte2Hex(pack->FrameHeader.SrcMAC, 6)) << endl;
//            cout << "Ŀ��MAC��ַ��" << *(Byte2Hex(pack->FrameHeader.DesMAC, 6)) << endl;
//            cout << "���ͣ�" << pack->FrameHeader.TrameType << endl;
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
//    pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
//    alldevs = CAPLIST();
//    //ѡ��Ҫ�������豸
//    cout << "��ѡ��Ҫ�������豸��";
//    pcap_if_t* D;
//    D = alldevs;
//    int m;
//    cin >> m;
//    //����ѡ��������ӿڿ�---������ӿ�
//    CHOOSEDEV(m, D, alldevs);
//    Capture();
//    pcap_freealldevs(alldevs);
//}




