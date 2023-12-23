#include "MYstruct.h"
#define MAX_IP_NUM 6//设定一块网卡上最多绑定的IP地址数
char errbuf[PCAP_ERRBUF_SIZE];

/*全局变量*/
pcap_if_t* alldevs;//所有网卡
pcap_t* open_dev;//open的网卡
pcap_addr* add;//网卡对应的地址
char my_ip[10][20];//打开的网卡对应的ip地址
char my_mask[10][20];//打开的网卡对应的掩码
BYTE my_mac[6];//本机MAC地址
Log my_log;//日志
ArpTable my_arptable[50];//ARP映射表
PacketBuffer my_buffer[MAX_BUFFER_COUNT];//发送数据报缓存数组
PacketBuffer my_buffer2[MAX_BUFFER_COUNT];
int pktNum = 0;//数据报缓存个数

//多线程
HANDLE hThread;
DWORD dwThreadId;

//缓冲区删除函数
void Delete_Buffer(PacketBuffer my_buffer1[50],int target) {
	int j = 0;
	for (int i = 0; i < pktNum; i++) {
		if (i != target) {
			my_buffer1[j] = my_buffer1[i];
			j++;
		}
	}
}

void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//比较两个MAC地址是否相同
bool Compare(BYTE a[6], BYTE b[6])
{
	bool like = true;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			like = false;
	}
	return like;
}

//展示ARP数据帧
void ShowArp(ARPFrame_t* p) {

	in_addr addr;
	addr.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr);
	printf("源IP地址：  %s", str1);

	printf("\n源MAC地址：");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->SendHa[i]);
	printf("%02X", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	printf("\n目的IP地址：  %s", str2);


	printf("\n目的MAC地址：");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->RecvHa[i]);
	printf("%02X", p->RecvHa[5]);
	printf("\n");
}

/*打开网卡获取双IP*/
void  Get_Two_IP() {

	pcap_if_t* dev;//用于遍历网卡信息链表
	pcap_addr_t* add;//用于遍历IP地址信息链表：一个网卡可能有多个IP地址
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf
	) == -1)//返回-1表示出错
	{
		printf("There's Error in pcap_findalldevs_ex! Program exit.\n");
		exit(1);
	}
	//显示设备列表信息
	int index = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++index, dev->name);
		if (dev->description)
			printf("( %s )\n", dev->description);
		else
			printf("(No description )\n");

		//获取该网络接口设备绑定的的IP地址信息
		for (add = dev->addresses; add != NULL; add = add->next) {
			if (add->addr->sa_family == AF_INET) { //判断该地址是否IP地址
				//输出相关的信息
				char str[INET_ADDRSTRLEN];
				//通过 inet_ntoa将一个网络字节序的IP地址转化为点分十进制的IP地址（字符串）
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr ));
				printf("IP地址：%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
				printf("网络掩码：%s\n", str);
				
			}
		}
	}
	if (index == 0)
	{
		printf("\nNo interfaces found!\n");
	}
	printf("--------------------------------------------------------------------------------\n\n");
	dev = alldevs;
	int num;
	printf("请选择您要打开的网卡：");
	scanf("%d", &num);

	//遍历寻找要打开的网络
	for (int i = 0; i < num - 1; i++) {
		dev = dev->next;
	}
	//把对应的ip和掩码存上
	int t = 0;
	for (add = dev->addresses; add != NULL && t < 10; add = add->next) {
		if (add->addr->sa_family == AF_INET) {//是IP类型的
			strcpy(my_ip[t], inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr));
			strcpy(my_mask[t], inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
			t++;
		}
	}
	open_dev = open(dev->name);//pcap_open
	if (open_dev == NULL) {
		pcap_freealldevs(alldevs);

	}

	pcap_freealldevs(alldevs);

}


/*获取本机MAC地址*/
//构造ARP数据帧
void SET_ARP_Frame_HOST(ARPFrame_t& ARPFrame1, DWORD ip) {
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;//广播地址
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;//随意
		ARPFrame1.SendHa[i] = 0x0f;//随意
		ARPFrame1.RecvHa[i] = 0x00;//全0代表未知
	}

	ARPFrame1.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame1.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame1.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);//操作类型为ARP请求
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;//本机ip地址
}

void Get_Host_Mac(DWORD ip) {
	memset(my_mac, 0, sizeof(my_mac));
	ARPFrame_t ARPF_Send;
	SET_ARP_Frame_HOST(ARPF_Send,ip);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	my_log.addInfo("---------------------------------获取本机MAC地址---------------------------------\n");
	my_log.ARP_info("发送ARP请求包", &ARPF_Send);
	//发送构造好的数据包
	//用pcap_next_ex()捕获数据包，pkt_data指向捕获到的网络数据包

	while ((k = pcap_next_ex(open_dev, &pkt_header, &pkt_data)) >= 0) {
		//发送数据包
	  
		pcap_sendpacket(open_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
		struct ARPFrame_t* arp_message;
		arp_message = (struct ARPFrame_t*)(pkt_data);
		if (k == 0)continue;
		else
		{   //帧类型为ARP，且操作类型为ARP响应
			
			if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {
				
				
				//展示一下包的内容
				my_log.ARP_info("收到ARP应答包", arp_message);
				ShowArp(arp_message);
				//用my_mac记录本机的MAC地址，
				for (int i = 0; i < 6; i++) {
					my_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
				}
				printf("成功获取本机MAC地址\n");
				break;
			}
		}
	}
	my_log.addInfo("---------------------------------成功获取本机MAC地址---------------------------------\n");
}




//获取其他机器的MAC地址
void SET_ARP_Frame_DEST(ARPFrame_t& ARPFrame, char ip[20], unsigned char* mac) {
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//将APRFrame.FrameHeader.DesMAC设置为广播地址
		ARPFrame.RecvHa[i] = 0x00;
		ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//设置为本机网卡的MAC地址
		ARPFrame.SendHa[i] = mac[i];//设置为本机网卡的MAC地址
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	ARPFrame.SendIP = inet_addr(ip);//将ARPFrame->SendIP设置为本机网卡上绑定的IP地址

}

//获取ip对应的mac
void Get_Other_Mac(DWORD ip_) {
	/*这里只发送ARP请求！！！*/
	
	ARPFrame_t ARPFrame;
	SET_ARP_Frame_DEST(ARPFrame, my_ip[0], my_mac);
	ARPFrame.RecvIP = ip_;
	
	my_log.addInfo("---------------------------------获取远程主机MAC地址---------------------------------\n");
	pcap_sendpacket(open_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	my_log.ARP_info("发送ARP请求包", &ARPFrame);

}


//发送ICMP数据报
void Send_ICMP_Pac(BYTE type, BYTE code, const u_char* pkt_data) {
	u_char* Buffer = new u_char[70];
	
	// 填充以太网帧首部
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// 填充IP首部
	((IPHeader_t*)(Buffer + 14))->Ver_HLen = ((IPHeader_t*)(pkt_data + 14))->Ver_HLen;
	((IPHeader_t*)(Buffer + 14))->TOS = ((IPHeader_t*)(pkt_data + 14))->TOS;
	((IPHeader_t*)(Buffer + 14))->TotalLen = htons(56);
	((IPHeader_t*)(Buffer + 14))->ID = ((IPHeader_t*)(pkt_data + 14))->ID;
	((IPHeader_t*)(Buffer + 14))->Flag_Segment = ((IPHeader_t*)(pkt_data + 14))->Flag_Segment;
	((IPHeader_t*)(Buffer + 14))->TTL = 64;
	((IPHeader_t*)(Buffer + 14))->Protocol = 1;
	((IPHeader_t*)(Buffer + 14))->SrcIP = ((IPHeader_t*)(pkt_data + 14))->DstIP;
	((IPHeader_t*)(Buffer + 14))->DstIP = ((IPHeader_t*)(pkt_data + 14))->SrcIP;
	((IPHeader_t*)(Buffer + 14))->Checksum = htons(calCheckSum1((IPHeader_t*)(Buffer + 14)));
	// calCheckSum1((IPHeader_t*)(Buffer + 14));
	// 填充ICMP首部:前8字节
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Sequence = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(calCheckSum2((unsigned short*)(Buffer + 34), 36));
	// ((IPHeader_t*)(Buffer + 34))->Checksum = 0;

	// 将原本计算完校验和的数据包首部填充进去
	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	//取出ICMP首部的前8个字节，到此一共是70
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	//发送报文
	pcap_sendpacket(open_dev, (u_char*)Buffer, 70);

	if (type == 11)
	{
		my_log.ICMP_info("发送ICMP超时数据包-->\n");
	}
	if (type == 3)
	{
		my_log.ICMP_info("发送ICMP目的不可达数据包-->\n");
	}

	delete[] Buffer;
}

//线程函数
//处理接收到的数据报
DWORD WINAPI Recv_Handle(LPVOID lparam) {

	RouteTable router_table = *(RouteTable*)(LPVOID)lparam;//从参数中获取路由表
	//过滤码
	struct bpf_program fcode;
	//编辑过滤字符串
	//pcap_compile()用来把用户输入的过滤字符串编译进过滤信息
	if (pcap_compile(open_dev, &fcode, "ip or arp", 1, bpf_u_int32(my_mask[0])) < 0)
	{
		fprintf(stderr, "\nError  filter\n");
		system("pause");
		return -1;
	}

	//根据编译好的过滤码设置过滤条件
	if (pcap_setfilter(open_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		system("pause");
		return -1;
	}

	//捕获数据包并转发
	while (1)
	{
		pcap_pkthdr* pkt_header = NULL;
		const u_char* pkt_data = NULL;
		while (1)
		{
			int ret = pcap_next_ex(open_dev, &pkt_header, &pkt_data);//抓包
			if (ret)break;//接收到消息
		}
		//格式化收到的包为帧首部，以获取目的MAC地址和帧类型
		FrameHeader_t* recv_header = (FrameHeader_t*)pkt_data;
		//只处理目的目的mac是自己的包
		if (Compare(recv_header->DesMAC, my_mac))
		{
			//收到IP数据报
			if (ntohs(recv_header->FrameType) == 0x800)
			{
				//格式化收到的包为帧首部+IP首部类型
				IPFrame_t* data = (IPFrame_t*)pkt_data;

				my_log.IP_info("接收IP数据报\n", data);
				//获取目的IP地址并在路由表中查找，并获取下一跳ip地址



				// ICMP超时
				if (data->IPHeader.TTL <= 0)
				{
					//发送超时报文
					Send_ICMP_Pac(11, 0, pkt_data);
					my_log.addInfo("发送ICMP超时数据包!");
					continue;
				}

				IPHeader_t* IpHeader = &(data->IPHeader);
				// 检验校验和，数据报损坏或是出错
				if (check_checksum(data) == 0)
				{
					my_log.IP_info("校验和错误，丢弃", data);
					continue;
				}
				DWORD dstip = data->IPHeader.DstIP;

				DWORD nexthop = router_table.search(dstip);

				my_log.addInfohop("接收到的IP数据报目的为", dstip);
				my_log.addInfohop("接收到的IP数据报下一跳为",nexthop);
				//无匹配项
				//目的不可达
				if (nexthop == -1)
				{
					Send_ICMP_Pac(3, 0, pkt_data);// ICMP目的不可达
					my_log.addInfo("发送ICMP目的不可达数据报!");
					continue;
				}
				else
				{

					PacketBuffer packet;
					packet.targetIP = nexthop;

					//重新封装MAC地址(源MAC地址变为my_mac)
					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = my_mac[t];
					}

					data->IPHeader.TTL -= 1;// TTL减1
					// 设IP头中的校验和为0
					data->IPHeader.Checksum = 0;
					unsigned short buff[sizeof(IPHeader_t)];

					memset(buff, 0, sizeof(IPHeader_t));
					IPHeader_t* header = &(data->IPHeader);
					memcpy(buff, header, sizeof(IPHeader_t));

					// 计算IP头部校验和
					// data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));
					data->IPHeader.Checksum = calCheckSum1(header);

					// IP-MAC地址映射表中存在该映射关系
					//根据nexthop取ARP映射表中查看是否存在映射

					if (my_arptable->search(nexthop, data->FrameHeader.DesMAC))
					{
						//查找到了数据报可以直接转发
						memcpy(packet.pktData, pkt_data, pkt_header->len);
						packet.totalLen = pkt_header->len;
						if (pcap_sendpacket(open_dev, (u_char*)packet.pktData, packet.totalLen) != 0)
						{
							// 错误处理
							continue;
						}
						my_log.addInfo("--------------------------------------转发数据包--------------------------------------");
						my_log.IP_info("转发", data);
					}
					
					
					// IP-MAC地址映射表中不存在该映射关系,获取
					//先缓存IP数据报
					//设置缓冲区my_buffer
					else
					{
						//最多存50条
						if (pktNum < MAX_BUFFER_COUNT)		// 存入缓存队列
						{
							packet.totalLen = pkt_header->len;
							// 将需要转发的数据报存入缓冲区
							memcpy(packet.pktData, pkt_data, pkt_header->len);

							my_buffer[pktNum++] = packet;

							packet.Time = clock();

							my_log.IP_info("缓存IP数据报\n", data);
							// 发送ARP请求
							Get_Other_Mac(packet.targetIP);
						}
						else
						{
							my_log.addInfo("缓冲区已满，丢弃该IP数据包");
							my_log.IP_info("缓冲区溢出，丢弃", data);
						}
					}
				}
			}
			//收到ARP数据报
			else if (ntohs(recv_header->FrameType) == 0x806)
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//格式化收到的包为帧首部+ARP首部类型
				my_log.ARP_info("接收ARP响应包", data);
				//收到ARP响应包
				//处理响应报文
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6] = { 1 };

					if (my_arptable->search(data->SendIP, tmp_mac)) {//该映射关系已经存到路由表中，不做处理
					}
					else {

						DWORD tmp_ip = data->SendIP;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}

						//IP-MAC对应关系存表
						my_arptable->add(data->SendIP, data->SendHa);

						//遍历缓冲区，看是否有可以转发的包
						for (int i = 0; i < pktNum; i++)
						{
							PacketBuffer packet = my_buffer[i];
							if (packet.valid == 0)continue;
							if (clock() - packet.Time >= 6000) {//超时
								// packet.valid = 0;
								// my_buffer[i].valid = 0;
								Delete_Buffer(my_buffer, i);
								pktNum -= 1;
								continue;
							}
							////往此IP地址转发
							if (packet.targetIP == data->SendIP)
							{
								IPFrame_t* ipframe = (IPFrame_t*)packet.pktData;
								//重新封装IP包
								for (int i = 0; i < 6; i++) {
									ipframe->FrameHeader.SrcMAC[i] = my_mac[i];
									ipframe->FrameHeader.DesMAC[i] = data->SendHa[i];
								}
								// 发送IP数据包
								pcap_sendpacket(open_dev, (u_char*)packet.pktData, packet.totalLen);
								
								my_buffer[i].valid = 0;
								my_log.addInfo("-----------------------------------------转发数据包-----------------------------------------");
								my_log.IP_info("转发", ipframe);
								my_log.addInfo("-----------------------------------------该数据包转发成功-----------------------------------------");
							}
						}

					}
				}
				else if (data->Operation == ntohs(0x0002)) {}//请求报文什么也不做

			}

		}


	}

}

int main() {

	//打开网卡获取双IP
	Get_Two_IP();


	printf("本机双IP地址为：\n");
	for (int i = 0; i < 2; i++) {
		printf("%s\t", my_ip[i]);
		printf("%s\n", my_mask[i]);
	}

	//获取本机MAC地址
	Get_Host_Mac(inet_addr(my_ip[0]));
	printMac(my_mac);

	//路由表
	RouteTable my_route;

	//建立转发线程
	hThread = CreateThread(NULL, SIZE_MAX, Recv_Handle, LPVOID(&my_route), 0, &dwThreadId);


	//对路由表的相关操作

	int op;
	while (1)
	{
		printf("\n\n请选择要进行的操作：\n1. 添加路由表项\n2. 删除路由表项\n3. 打印路由表\n");
		scanf("%d", &op);
		RouteEntry* entry = new RouteEntry;

		switch (op) {
		case 1:
			char t[30];
			printf("请输入掩码：");
			scanf("%s", &t);
			entry->mask = inet_addr(t);
			printf("请输入目的网络：");
			scanf("%s", &t);
			entry->dst_net= inet_addr(t);
			printf("请输入下一跳的IP地址：");
			scanf("%s", &t);
			entry->next_hop = inet_addr(t);
			entry->type = 1;
			entry->print();
			my_route.add(entry);
			break;
		case 2:
			my_route.print();
			printf("请输入要删除的表项的索引：");
			int i;
			scanf("%d", &i);
			my_route.erase(i);
			break;
		case 3:
			my_route.print();
			break;
		default:
			printf("无效操作，请重新输入\n");
			break;
		}
	}
	return 0;

}
