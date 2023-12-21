#ifndef USER_DEFINED_DATA_H
#define USER_DEFINED_DATA_H
#ifndef WIN32
#define WIN32
#endif
#define WPCAP
#define HAVE_REMOTE
#include "pcap.h"
#include<WinSock2.h>
#include <process.h>
#include <stdio.h>
#include <bitset>
#include <time.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define BYTE unsigned char
#define MAX_SIZE 2048
#define MAX_BUFFER_COUNT 50
#pragma pack(1)		//�����ֽڶ��뷽ʽ

//ǰ��������ȷ���ں���Ľṹ�����ܹ�ʹ��
struct FrameHeader_t;
struct IPHeader_t;
struct ICMPHeader_t;
struct ARPFrame_t;
struct IPFrame_t;

//֡�ײ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

//IP�ײ�
typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//��������
	BYTE Protocol;
	WORD Checksum;//У���
	ULONG SrcIP;//ԴIP
	ULONG DstIP;//Ŀ��IP
}IPHeader_t;

// ICMP�ײ�
typedef struct ICMPHeader_t {
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
}ICMPHeader_t;

//ARP����֡
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//֡�ײ�
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э�鳤��
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

//IP���ݱ�������֡�ײ���IP�ײ������ݰ�
typedef struct IPFrame_t {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;

#pragma pack()	//�ָ�ȱʡ���뷽ʽ

/*·����������ݽṹ*/

//·�ɱ���
class RouteEntry
{
public:
	RouteEntry* next;
	int number;//����
	DWORD mask;//����
	DWORD dst_net;//Ŀ������
	DWORD next_hop;//��һ����IP��ַ
	BYTE nextMAC[6];//��һ����MAC��ַ
	int type;//0Ϊֱ�����ӣ�����ɾ������1Ϊ�û����
	RouteEntry() { 
		next = NULL;
		number = 0;
		mask = 0;
		dst_net = 0;
		next_hop = 0;
		type = 0;
	}
	RouteEntry(int number, DWORD dstNetwork, DWORD mask, DWORD nextHop, int access)
	{
		this->number = number;
		this->dst_net = dstNetwork;
		this->mask = mask;
		this->next_hop = nextHop;
		this->type = access;
	}
	void print();
};

//·�ɱ�
//����������ʽ��֯�������ƥ��ԭ������Խ��Խ��ǰ������ԽС
class RouteTable {
public:
	RouteEntry* head, * tail;//ͷ�ڵ�
	int num;//����
	RouteTable();//��ʼ�������ֱ������������
	void add(RouteEntry* entry);//���·�ɱ��ֱ������������ǰ�棬����İ����ƥ��ԭ��
	void erase(int number);//ɾ����i��·�ɱ��ֱ�������Ĳ���ɾ��
	void print();
	DWORD search(DWORD dstip);//�����ƥ��ԭ�������һ����ip��ַ

};

/*ARP��ַӳ���*/
class ArpTable {
public:
	DWORD IP;
	BYTE MAC[6];
	static int num;
	static void add(DWORD IP, BYTE MAC[6]);
	static int search(DWORD IP, BYTE MAC[6]);
};


/*ת�������ݱ��ṹ*/
class PacketBuffer
{
public:
	BYTE			pktData[MAX_SIZE];// ���ݻ���
	int				totalLen;// ���ݰ��ܳ���
	ULONG			targetIP;//Ŀ��IP��ַ
	bool			valid = 1; //��Чλ������Ѿ���ת�����߳�ʱ������0
	clock_t			Time;// ��ʱ�ж�
	PacketBuffer() {};
	PacketBuffer(const PacketBuffer& x)//���ƹ��캯��--->��飡����
	{
		memcpy(this->pktData, x.pktData, x.totalLen);
		this->totalLen = x.totalLen;
		this->targetIP = x.targetIP;
		this->valid = x.valid;
		this->Time = x.Time;
	}
};


/*��־����*/
//д�����־����������ARP���ݱ�������ARP���ݱ�������IP���ݱ���ת��IP���ݱ�������ICMP���ݱ�

class Log
{
public:
	Log();//���ļ�����д��
	~Log();//�ر��ļ���
	static FILE* my_fp;
	//д����־
	static void addInfo(const char* str/*��־��Ϣ��ʶ*/);
	static void addInfohop(const char* str/*��־��Ϣ��ʶ*/,DWORD hop);
	static void ARP_info(const char* str/*��־��Ϣ��ʶ*/, ARPFrame_t* p);//arp����
	static void IP_info(const char* str, IPFrame_t* p);//ip����
	static void ICMP_info(const char* str);//icmp����
};

//����У���
// unsigned short calCheckSum(IPFrame_t* temp);

void printMac(BYTE MAC[]);
unsigned short calCheckSum1(IPHeader_t* temp);
//����У���
unsigned short calCheckSum2(unsigned short* pBuffer, int nSize);

bool check_checksum(IPFrame_t* temp);

pcap_t* open(char* name);

#endif