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
#pragma pack(1)		//进入字节对齐方式

//前向声明，确保在后面的结构体中能够使用
struct FrameHeader_t;
struct IPHeader_t;
struct ICMPHeader_t;
struct ARPFrame_t;
struct IPFrame_t;

//帧首部
typedef struct FrameHeader_t {
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

//IP首部
typedef struct IPHeader_t {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//生命周期
	BYTE Protocol;
	WORD Checksum;//校验和
	ULONG SrcIP;//源IP
	ULONG DstIP;//目的IP
}IPHeader_t;

// ICMP首部
typedef struct ICMPHeader_t {
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
}ICMPHeader_t;

//ARP数据帧
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//帧首部
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议长度
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
}ARPFrame_t;

//IP数据报：包含帧首部和IP首部的数据包
typedef struct IPFrame_t {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}IPFrame_t;

#pragma pack()	//恢复缺省对齐方式

/*路由器相关数据结构*/

//路由表项
class RouteEntry
{
public:
	RouteEntry* next;
	int number;//索引
	DWORD mask;//掩码
	DWORD dst_net;//目的网络
	DWORD next_hop;//下一跳的IP地址
	BYTE nextMAC[6];//下一跳的MAC地址
	int type;//0为直接连接（不可删除），1为用户添加
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

//路由表
//按照链表形式组织，按照最长匹配原则，掩码越长越靠前，索引越小
class RouteTable {
public:
	RouteEntry* head, * tail;//头节点
	int num;//条数
	RouteTable();//初始化，添加直接相连的网络
	void add(RouteEntry* entry);//添加路由表项，直接相连的在最前面，其余的按照最长匹配原则
	void erase(int number);//删除第i条路由表项，直接相连的不能删除
	void print();
	DWORD search(DWORD dstip);//根据最长匹配原则查找下一跳的ip地址

};

/*ARP地址映射表*/
class ArpTable {
public:
	DWORD IP;
	BYTE MAC[6];
	static int num;
	static void add(DWORD IP, BYTE MAC[6]);
	static int search(DWORD IP, BYTE MAC[6]);
};


/*转发的数据报结构*/
class PacketBuffer
{
public:
	BYTE			pktData[MAX_SIZE];// 数据缓存
	int				totalLen;// 数据包总长度
	ULONG			targetIP;//目的IP地址
	bool			valid = 1; //有效位：如果已经被转发或者超时，则置0
	clock_t			Time;// 超时判断
	PacketBuffer() {};
	PacketBuffer(const PacketBuffer& x)//复制构造函数--->检查！！！
	{
		memcpy(this->pktData, x.pktData, x.totalLen);
		this->totalLen = x.totalLen;
		this->targetIP = x.targetIP;
		this->valid = x.valid;
		this->Time = x.Time;
	}
};


/*日志操作*/
//写相关日志，包括接收ARP数据报，发送ARP数据报，接收IP数据报，转发IP数据报，发送ICMP数据报

class Log
{
public:
	Log();//打开文件进行写入
	~Log();//关闭文件！
	static FILE* my_fp;
	//写入日志
	static void addInfo(const char* str/*日志信息标识*/);
	static void addInfohop(const char* str/*日志信息标识*/,DWORD hop);
	static void ARP_info(const char* str/*日志信息标识*/, ARPFrame_t* p);//arp类型
	static void IP_info(const char* str, IPFrame_t* p);//ip类型
	static void ICMP_info(const char* str);//icmp类型
};

//计算校验和
// unsigned short calCheckSum(IPFrame_t* temp);

void printMac(BYTE MAC[]);
unsigned short calCheckSum1(IPHeader_t* temp);
//检验校验和
unsigned short calCheckSum2(unsigned short* pBuffer, int nSize);

bool check_checksum(IPFrame_t* temp);

pcap_t* open(char* name);

#endif