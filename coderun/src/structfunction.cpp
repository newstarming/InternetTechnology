#include"MYstruct.h"

/*一些全局变量*/

extern char my_ip[10][20];//打开的网卡对应的ip地址
extern char my_mask[10][20];//打开的网卡对应的掩码
extern BYTE my_mac[6];//本机MAC地址
extern PacketBuffer my_buffer[MAX_BUFFER_COUNT];//发送数据报缓存数组
extern Log my_log;//日志
extern ArpTable my_arptable[50];//ARP映射表
extern int pktNum;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern RouteTable my_route;


pcap_t* open(char* name) {

	pcap_t* temp = pcap_open(name, 65536/*最大值*/, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (temp == NULL)
		printf("无法打开设备\n");
	return temp;
}
/*路由表项*/
void RouteEntry::print()
{
	//打印序号
	printf("%d   ", number);

	
	in_addr addr;
	
	//打印掩码
	addr.s_addr = mask;
	//转成主机序
	char* str = inet_ntoa(addr);
	printf("%s\t", str);

	//打印目的主机
	addr.s_addr = dst_net;
	str = inet_ntoa(addr);
	printf("%s\t", str);

	//打印下一跳ip地址
	addr.s_addr = next_hop;
	str = inet_ntoa(addr);
	printf("%s\t", str);
	
	//用户是否可操作

	if (type == 0)
		printf("non_accessable\n");
	else
		printf("accessable\n");

	printf("\n");

}

/*路由表*/

//初始化，添加直接连接的网络

RouteTable::RouteTable()
{
	head = new RouteEntry;
	head->next = NULL;
	num = 0;
	//通过得到的双IP的掩码，在路由表中添加直接相连的网络，将类型设置为0，即不可删除项
	for (int i = 0; i < 2; i++)
	{
		RouteEntry* entry = new RouteEntry;
		//添加直接相连的网络
		entry->dst_net = (inet_addr(my_ip[i])) & (inet_addr(my_mask[i]));
		entry->mask = inet_addr(my_mask[i]);
		entry->type = 0;
		this->add(entry);
	}

}

//路由表项的添加
void RouteTable::add(RouteEntry*  r) {
	RouteEntry* temp;
	//当路由表是空的
	if (num == 0) {
		head->next = r;
		r->next = NULL;
	}
	else {

		temp = head->next;
		while (temp != NULL) {
			//掩码大小小于temp而大于temp->next
			if (temp->next == NULL || (r->mask < temp->mask && r->mask >= temp->next->mask)) {
				
				break;
			}
			temp = temp->next;
			
		}

		if (temp->next == NULL)
		{
			
			r->next = NULL;
			temp->next = r;
		}
		else {
			r->next = temp->next;
			temp->next = r;
		}
	}
	RouteEntry* p = head->next;
	//重新编号
	for (int i = 0; p != NULL; i++)
	{
		
		p->number = i;
		p = p->next;
	}
	num++;
	my_log.addInfo("路由表添加成功!");
	return;


}
//路由表项的删除
//删除第i条路由表项
void RouteTable::erase(int index) {
	
	RouteEntry* temp = new RouteEntry;
	bool hav = false;
	for (RouteEntry* t = head; t->next != NULL; t = t->next)
	{
		if (t->next->number == index)hav = true;
	}
	if (!hav) {
		printf("查无此项，请重新输入！\n");
		return;
	}

	if (index == 0)//删除第一项
	{
		temp = head->next;
		//默认路由表项不能删
		if (temp->type == 0)
		{
			printf("没有权限删除该项！\n");
			return;
		}
		else
		{
			if (num == 1)
			{
				head->next = NULL;
			}
			else
			{
				temp = head->next;
				head->next = temp->next;
				printf("已成功删除指定项！\n");
				
			}

		}
	}
	else
	{
		temp = head->next;
		for (int i = 0; i < index - 1; i++)//遍历到index处,寻找删除结点的前驱结点
		{
			temp = temp->next;
		}
		RouteEntry* rem = new RouteEntry;
		rem = temp->next;//要删除的结点x

		if (rem->type == 0)
		{
			printf("没有权限删除该项！\n");
			return;
		}
		if (rem->next == NULL)//尾删
		{
			temp->next = NULL;
			
		//	printf("已成功删除指定项！\n");
			
		}
		//中间删
		temp->next = rem->next;
		printf("已成功删除指定项！\n");

	}
	/*重新编号*/

	RouteEntry* p = head->next;
	//重新为表项编号
	for (int i = 0; p != NULL; i++)
	{
		p->number = i;
		p = p->next;
	}
	num--;
	my_log.addInfo("路由表删除成功!");
	return ;	
}

//打印路由表
void RouteTable::print() {
	RouteEntry* temp = head->next;
	printf("--------------------------路由表----------------------\n");
	int t = 0;
	while (temp!=NULL) {
		temp->print();
		temp = temp->next;
		t++;
	}
	printf("共有路由表项：");
	printf("%d   ", num);
	printf("条/n");
}

//查找下一跳的IP地址(参数为目的ip地址）
DWORD RouteTable::search(DWORD dst_ip) {

	DWORD a = -1;
	RouteEntry* t = head->next;
	for (; t!= NULL; t = t->next) {

		if ((t->mask & dst_ip) == t->dst_net) {
			if (t->type == 0)//直接相连的网络
			{
				a= dst_ip;
			}
			else
			a = t->next_hop;
		}
	}
	return a;
}

/*mac地址映射表ARP*/


/*日志打印函数*/
FILE* Log::my_fp = nullptr;

Log::Log()
{
	my_fp = fopen("my_log.txt", "a+");//以附加的方式打开文件
}
Log::~Log()
{
	fclose(my_fp);
}
//日志信息标识
void Log::addInfo(const char* str) {
	fprintf(my_fp, str);
	fprintf(my_fp, "\n");
}
void Log::addInfohop(const char* str/*日志信息标识*/, DWORD hop) {
	fprintf(my_fp, str);
	if (hop == -1)
		fprintf(my_fp, "%s  \n", "-1");
	in_addr addr;
	addr.s_addr = hop;
	char* str1 = inet_ntoa(addr);
	fprintf(my_fp, "%s  \n", str1);
}

//ARP数据报信息
void Log::ARP_info(const char* str, ARPFrame_t* p) {
	fprintf(my_fp, str);
	fprintf(my_fp, "----------------------------ARP 数据包--------------------------------\n");

	in_addr addr;
	addr.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr);
	fprintf(my_fp, "源IP： ");
	fprintf(my_fp, "%s  \n", str1);

	fprintf(my_fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->SendHa[i]);
	fprintf(my_fp, "%02X\n", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	fprintf(my_fp, "目的IP： ");
	fprintf(my_fp, "%s  \n", str2);

	fprintf(my_fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->RecvHa[i]);
	fprintf(my_fp, "%02X\n", p->RecvHa[5]);
	fprintf(my_fp, "\n");
}


//IP数据报
void Log::IP_info(const char* str, IPFrame_t* p) {
	fprintf(my_fp, str);
	fprintf(my_fp, "--------------------------IP 数据包--------------------------\n");

	in_addr addr;
	addr.s_addr = p->IPHeader.SrcIP;
	char* str1 = inet_ntoa(addr);

	fprintf(my_fp, "源IP： ");
	fprintf(my_fp, "%s\n", str1);
	addr.s_addr = p->IPHeader.DstIP;
	char* str2 = inet_ntoa(addr);
	fprintf(my_fp, "目的IP： %s\n", str2);

	fprintf(my_fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->FrameHeader.SrcMAC[i]);
	fprintf(my_fp, "%02X\n", p->FrameHeader.SrcMAC[5]);

	fprintf(my_fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->FrameHeader.DesMAC[i]);
	fprintf(my_fp, "%02X\n", p->FrameHeader.DesMAC[5]);
	fprintf(my_fp, "\n");

}
//ICMP
void Log::ICMP_info(const char* str) {
	fprintf(my_fp, str);
	fprintf(my_fp, "\n");
}

//打印MAC地址
void printMac(BYTE MAC[])//打印mac地址
{
	printf("MAC地址为： ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}


/*ARP表*/
int ArpTable::num = 0;
void ArpTable::add(DWORD ip, BYTE mac[6])
{
	my_arptable[num].IP = ip;
	memcpy(my_arptable[num].MAC, mac, 6);
	num++;
}

int ArpTable::search(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == my_arptable[i].IP)
		{
			memcpy(mac, my_arptable[i].MAC, 6);
			return 1;
		}
	}
	return 0;
}

//参数是IP数据包头
unsigned short calCheckSum1(IPHeader_t* temp)
{
	// temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	//WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	WORD* t = (WORD*)temp;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
		//如果溢出，则进行回卷
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// temp->Checksum = ~sum;//结果取反
	return (unsigned short)~sum;
}

unsigned short calCheckSum2(unsigned short* pBuffer, int nSize) {
	///*
	//* 计算方法：将校验和字段设置为0（传进来的是已经为0的）
	//* 按顺序对每16位（1个字=2字节）进行加法运算；
	//* 如果溢出就将进位加到最低位
	//* 对累加的结果取反——就是头部校验和值
	//*/
	unsigned long ulCheckSum = 0;
	while (nSize > 1)
	{
		ulCheckSum += *pBuffer++;
		nSize -= sizeof(unsigned short);//每16位一组
	}
	if (nSize)
	{
		ulCheckSum += *(unsigned short*)pBuffer;
	}

	ulCheckSum = (ulCheckSum >> 16) + (ulCheckSum & 0xffff);
	ulCheckSum += (ulCheckSum >> 16);
	return (unsigned short)(~ulCheckSum);
}
//检验
bool check_checksum(IPFrame_t* temp) {
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//包含原校验和一起进行相加
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	if (sum == 65535)return 1;//全1，校验和正确
	return 0;
}