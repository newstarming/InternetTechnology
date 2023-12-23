#include "MYstruct.h"
#define MAX_IP_NUM 6//�趨һ�����������󶨵�IP��ַ��
char errbuf[PCAP_ERRBUF_SIZE];

/*ȫ�ֱ���*/
pcap_if_t* alldevs;//��������
pcap_t* open_dev;//open������
pcap_addr* add;//������Ӧ�ĵ�ַ
char my_ip[10][20];//�򿪵�������Ӧ��ip��ַ
char my_mask[10][20];//�򿪵�������Ӧ������
BYTE my_mac[6];//����MAC��ַ
Log my_log;//��־
ArpTable my_arptable[50];//ARPӳ���
PacketBuffer my_buffer[MAX_BUFFER_COUNT];//�������ݱ���������
PacketBuffer my_buffer2[MAX_BUFFER_COUNT];
int pktNum = 0;//���ݱ��������

//���߳�
HANDLE hThread;
DWORD dwThreadId;

//������ɾ������
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

//�Ƚ�����MAC��ַ�Ƿ���ͬ
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

//չʾARP����֡
void ShowArp(ARPFrame_t* p) {

	in_addr addr;
	addr.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr);
	printf("ԴIP��ַ��  %s", str1);

	printf("\nԴMAC��ַ��");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->SendHa[i]);
	printf("%02X", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	printf("\nĿ��IP��ַ��  %s", str2);


	printf("\nĿ��MAC��ַ��");
	for (int i = 0; i < 5; i++)
		printf("%02X-", p->RecvHa[i]);
	printf("%02X", p->RecvHa[5]);
	printf("\n");
}

/*��������ȡ˫IP*/
void  Get_Two_IP() {

	pcap_if_t* dev;//���ڱ���������Ϣ����
	pcap_addr_t* add;//���ڱ���IP��ַ��Ϣ����һ�����������ж��IP��ַ
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf
	) == -1)//����-1��ʾ����
	{
		printf("There's Error in pcap_findalldevs_ex! Program exit.\n");
		exit(1);
	}
	//��ʾ�豸�б���Ϣ
	int index = 0;
	for (dev = alldevs; dev; dev = dev->next) {
		printf("%d. %s", ++index, dev->name);
		if (dev->description)
			printf("( %s )\n", dev->description);
		else
			printf("(No description )\n");

		//��ȡ������ӿ��豸�󶨵ĵ�IP��ַ��Ϣ
		for (add = dev->addresses; add != NULL; add = add->next) {
			if (add->addr->sa_family == AF_INET) { //�жϸõ�ַ�Ƿ�IP��ַ
				//�����ص���Ϣ
				char str[INET_ADDRSTRLEN];
				//ͨ�� inet_ntoa��һ�������ֽ����IP��ַת��Ϊ���ʮ���Ƶ�IP��ַ���ַ�����
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->addr)->sin_addr ));
				printf("IP��ַ��%s\n", str);
				strcpy(str, inet_ntoa(((struct sockaddr_in*)add->netmask)->sin_addr));
				printf("�������룺%s\n", str);
				
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
	printf("��ѡ����Ҫ�򿪵�������");
	scanf("%d", &num);

	//����Ѱ��Ҫ�򿪵�����
	for (int i = 0; i < num - 1; i++) {
		dev = dev->next;
	}
	//�Ѷ�Ӧ��ip���������
	int t = 0;
	for (add = dev->addresses; add != NULL && t < 10; add = add->next) {
		if (add->addr->sa_family == AF_INET) {//��IP���͵�
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


/*��ȡ����MAC��ַ*/
//����ARP����֡
void SET_ARP_Frame_HOST(ARPFrame_t& ARPFrame1, DWORD ip) {
	for (int i = 0; i < 6; i++) {
		ARPFrame1.FrameHeader.DesMAC[i] = 0xff;//�㲥��ַ
		ARPFrame1.FrameHeader.SrcMAC[i] = 0x0f;//����
		ARPFrame1.SendHa[i] = 0x0f;//����
		ARPFrame1.RecvHa[i] = 0x00;//ȫ0����δ֪
	}

	ARPFrame1.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame1.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame1.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame1.HLen = 6;
	ARPFrame1.PLen = 4;
	ARPFrame1.Operation = htons(0x0001);//��������ΪARP����
	ARPFrame1.SendIP = inet_addr("10.10.10.10");
	ARPFrame1.RecvIP = ip;//����ip��ַ
}

void Get_Host_Mac(DWORD ip) {
	memset(my_mac, 0, sizeof(my_mac));
	ARPFrame_t ARPF_Send;
	SET_ARP_Frame_HOST(ARPF_Send,ip);
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	my_log.addInfo("---------------------------------��ȡ����MAC��ַ---------------------------------\n");
	my_log.ARP_info("����ARP�����", &ARPF_Send);
	//���͹���õ����ݰ�
	//��pcap_next_ex()�������ݰ���pkt_dataָ�򲶻񵽵��������ݰ�

	while ((k = pcap_next_ex(open_dev, &pkt_header, &pkt_data)) >= 0) {
		//�������ݰ�
	  
		pcap_sendpacket(open_dev, (u_char*)&ARPF_Send, sizeof(ARPFrame_t));
		struct ARPFrame_t* arp_message;
		arp_message = (struct ARPFrame_t*)(pkt_data);
		if (k == 0)continue;
		else
		{   //֡����ΪARP���Ҳ�������ΪARP��Ӧ
			
			if (arp_message->FrameHeader.FrameType == htons(0x0806) && arp_message->Operation == htons(0x0002)) {
				
				
				//չʾһ�°�������
				my_log.ARP_info("�յ�ARPӦ���", arp_message);
				ShowArp(arp_message);
				//��my_mac��¼������MAC��ַ��
				for (int i = 0; i < 6; i++) {
					my_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
				}
				printf("�ɹ���ȡ����MAC��ַ\n");
				break;
			}
		}
	}
	my_log.addInfo("---------------------------------�ɹ���ȡ����MAC��ַ---------------------------------\n");
}




//��ȡ����������MAC��ַ
void SET_ARP_Frame_DEST(ARPFrame_t& ARPFrame, char ip[20], unsigned char* mac) {
	for (int i = 0; i < 6; i++) {
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
		ARPFrame.RecvHa[i] = 0x00;
		ARPFrame.FrameHeader.SrcMAC[i] = mac[i];//����Ϊ����������MAC��ַ
		ARPFrame.SendHa[i] = mac[i];//����Ϊ����������MAC��ַ
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	ARPFrame.SendIP = inet_addr(ip);//��ARPFrame->SendIP����Ϊ���������ϰ󶨵�IP��ַ

}

//��ȡip��Ӧ��mac
void Get_Other_Mac(DWORD ip_) {
	/*����ֻ����ARP���󣡣���*/
	
	ARPFrame_t ARPFrame;
	SET_ARP_Frame_DEST(ARPFrame, my_ip[0], my_mac);
	ARPFrame.RecvIP = ip_;
	
	my_log.addInfo("---------------------------------��ȡԶ������MAC��ַ---------------------------------\n");
	pcap_sendpacket(open_dev, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	my_log.ARP_info("����ARP�����", &ARPFrame);

}


//����ICMP���ݱ�
void Send_ICMP_Pac(BYTE type, BYTE code, const u_char* pkt_data) {
	u_char* Buffer = new u_char[70];
	
	// �����̫��֡�ײ�
	memcpy(((FrameHeader_t*)Buffer)->DesMAC, ((FrameHeader_t*)pkt_data)->SrcMAC, 6);
	memcpy(((FrameHeader_t*)Buffer)->SrcMAC, ((FrameHeader_t*)pkt_data)->DesMAC, 6);
	((FrameHeader_t*)Buffer)->FrameType = htons(0x0800);

	// ���IP�ײ�
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
	// ���ICMP�ײ�:ǰ8�ֽ�
	((ICMPHeader_t*)(Buffer + 34))->Type = type;
	((ICMPHeader_t*)(Buffer + 34))->Code = code;
	((ICMPHeader_t*)(Buffer + 34))->Id = 0;
	((ICMPHeader_t*)(Buffer + 34))->Sequence = 0;
	((ICMPHeader_t*)(Buffer + 34))->Checksum = htons(calCheckSum2((unsigned short*)(Buffer + 34), 36));
	// ((IPHeader_t*)(Buffer + 34))->Checksum = 0;

	// ��ԭ��������У��͵����ݰ��ײ�����ȥ
	memcpy((u_char*)(Buffer + 42), (IPHeader_t*)(pkt_data + 14), 20);
	//ȡ��ICMP�ײ���ǰ8���ֽڣ�����һ����70
	memcpy((u_char*)(Buffer + 62), (u_char*)(pkt_data + 34), 8);
	//���ͱ���
	pcap_sendpacket(open_dev, (u_char*)Buffer, 70);

	if (type == 11)
	{
		my_log.ICMP_info("����ICMP��ʱ���ݰ�-->\n");
	}
	if (type == 3)
	{
		my_log.ICMP_info("����ICMPĿ�Ĳ��ɴ����ݰ�-->\n");
	}

	delete[] Buffer;
}

//�̺߳���
//������յ������ݱ�
DWORD WINAPI Recv_Handle(LPVOID lparam) {

	RouteTable router_table = *(RouteTable*)(LPVOID)lparam;//�Ӳ����л�ȡ·�ɱ�
	//������
	struct bpf_program fcode;
	//�༭�����ַ���
	//pcap_compile()�������û�����Ĺ����ַ��������������Ϣ
	if (pcap_compile(open_dev, &fcode, "ip or arp", 1, bpf_u_int32(my_mask[0])) < 0)
	{
		fprintf(stderr, "\nError  filter\n");
		system("pause");
		return -1;
	}

	//���ݱ���õĹ��������ù�������
	if (pcap_setfilter(open_dev, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter\n");
		system("pause");
		return -1;
	}

	//�������ݰ���ת��
	while (1)
	{
		pcap_pkthdr* pkt_header = NULL;
		const u_char* pkt_data = NULL;
		while (1)
		{
			int ret = pcap_next_ex(open_dev, &pkt_header, &pkt_data);//ץ��
			if (ret)break;//���յ���Ϣ
		}
		//��ʽ���յ��İ�Ϊ֡�ײ����Ի�ȡĿ��MAC��ַ��֡����
		FrameHeader_t* recv_header = (FrameHeader_t*)pkt_data;
		//ֻ����Ŀ��Ŀ��mac���Լ��İ�
		if (Compare(recv_header->DesMAC, my_mac))
		{
			//�յ�IP���ݱ�
			if (ntohs(recv_header->FrameType) == 0x800)
			{
				//��ʽ���յ��İ�Ϊ֡�ײ�+IP�ײ�����
				IPFrame_t* data = (IPFrame_t*)pkt_data;

				my_log.IP_info("����IP���ݱ�\n", data);
				//��ȡĿ��IP��ַ����·�ɱ��в��ң�����ȡ��һ��ip��ַ



				// ICMP��ʱ
				if (data->IPHeader.TTL <= 0)
				{
					//���ͳ�ʱ����
					Send_ICMP_Pac(11, 0, pkt_data);
					my_log.addInfo("����ICMP��ʱ���ݰ�!");
					continue;
				}

				IPHeader_t* IpHeader = &(data->IPHeader);
				// ����У��ͣ����ݱ��𻵻��ǳ���
				if (check_checksum(data) == 0)
				{
					my_log.IP_info("У��ʹ��󣬶���", data);
					continue;
				}
				DWORD dstip = data->IPHeader.DstIP;

				DWORD nexthop = router_table.search(dstip);

				my_log.addInfohop("���յ���IP���ݱ�Ŀ��Ϊ", dstip);
				my_log.addInfohop("���յ���IP���ݱ���һ��Ϊ",nexthop);
				//��ƥ����
				//Ŀ�Ĳ��ɴ�
				if (nexthop == -1)
				{
					Send_ICMP_Pac(3, 0, pkt_data);// ICMPĿ�Ĳ��ɴ�
					my_log.addInfo("����ICMPĿ�Ĳ��ɴ����ݱ�!");
					continue;
				}
				else
				{

					PacketBuffer packet;
					packet.targetIP = nexthop;

					//���·�װMAC��ַ(ԴMAC��ַ��Ϊmy_mac)
					for (int t = 0; t < 6; t++)
					{
						data->FrameHeader.SrcMAC[t] = my_mac[t];
					}

					data->IPHeader.TTL -= 1;// TTL��1
					// ��IPͷ�е�У���Ϊ0
					data->IPHeader.Checksum = 0;
					unsigned short buff[sizeof(IPHeader_t)];

					memset(buff, 0, sizeof(IPHeader_t));
					IPHeader_t* header = &(data->IPHeader);
					memcpy(buff, header, sizeof(IPHeader_t));

					// ����IPͷ��У���
					// data->IPHeader.Checksum = cal_checksum(check_buff, sizeof(IPHeader_t));
					data->IPHeader.Checksum = calCheckSum1(header);

					// IP-MAC��ַӳ����д��ڸ�ӳ���ϵ
					//����nexthopȡARPӳ����в鿴�Ƿ����ӳ��

					if (my_arptable->search(nexthop, data->FrameHeader.DesMAC))
					{
						//���ҵ������ݱ�����ֱ��ת��
						memcpy(packet.pktData, pkt_data, pkt_header->len);
						packet.totalLen = pkt_header->len;
						if (pcap_sendpacket(open_dev, (u_char*)packet.pktData, packet.totalLen) != 0)
						{
							// ������
							continue;
						}
						my_log.addInfo("--------------------------------------ת�����ݰ�--------------------------------------");
						my_log.IP_info("ת��", data);
					}
					
					
					// IP-MAC��ַӳ����в����ڸ�ӳ���ϵ,��ȡ
					//�Ȼ���IP���ݱ�
					//���û�����my_buffer
					else
					{
						//����50��
						if (pktNum < MAX_BUFFER_COUNT)		// ���뻺�����
						{
							packet.totalLen = pkt_header->len;
							// ����Ҫת�������ݱ����뻺����
							memcpy(packet.pktData, pkt_data, pkt_header->len);

							my_buffer[pktNum++] = packet;

							packet.Time = clock();

							my_log.IP_info("����IP���ݱ�\n", data);
							// ����ARP����
							Get_Other_Mac(packet.targetIP);
						}
						else
						{
							my_log.addInfo("������������������IP���ݰ�");
							my_log.IP_info("���������������", data);
						}
					}
				}
			}
			//�յ�ARP���ݱ�
			else if (ntohs(recv_header->FrameType) == 0x806)
			{
				ARPFrame_t* data = (ARPFrame_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ�+ARP�ײ�����
				my_log.ARP_info("����ARP��Ӧ��", data);
				//�յ�ARP��Ӧ��
				//������Ӧ����
				if (data->Operation == ntohs(0x0002)) {
					BYTE tmp_mac[6] = { 1 };

					if (my_arptable->search(data->SendIP, tmp_mac)) {//��ӳ���ϵ�Ѿ��浽·�ɱ��У���������
					}
					else {

						DWORD tmp_ip = data->SendIP;
						for (int i = 0; i < 6; i++) {
							tmp_mac[i] = data->SendHa[i];
						}

						//IP-MAC��Ӧ��ϵ���
						my_arptable->add(data->SendIP, data->SendHa);

						//���������������Ƿ��п���ת���İ�
						for (int i = 0; i < pktNum; i++)
						{
							PacketBuffer packet = my_buffer[i];
							if (packet.valid == 0)continue;
							if (clock() - packet.Time >= 6000) {//��ʱ
								// packet.valid = 0;
								// my_buffer[i].valid = 0;
								Delete_Buffer(my_buffer, i);
								pktNum -= 1;
								continue;
							}
							////����IP��ַת��
							if (packet.targetIP == data->SendIP)
							{
								IPFrame_t* ipframe = (IPFrame_t*)packet.pktData;
								//���·�װIP��
								for (int i = 0; i < 6; i++) {
									ipframe->FrameHeader.SrcMAC[i] = my_mac[i];
									ipframe->FrameHeader.DesMAC[i] = data->SendHa[i];
								}
								// ����IP���ݰ�
								pcap_sendpacket(open_dev, (u_char*)packet.pktData, packet.totalLen);
								
								my_buffer[i].valid = 0;
								my_log.addInfo("-----------------------------------------ת�����ݰ�-----------------------------------------");
								my_log.IP_info("ת��", ipframe);
								my_log.addInfo("-----------------------------------------�����ݰ�ת���ɹ�-----------------------------------------");
							}
						}

					}
				}
				else if (data->Operation == ntohs(0x0002)) {}//������ʲôҲ����

			}

		}


	}

}

int main() {

	//��������ȡ˫IP
	Get_Two_IP();


	printf("����˫IP��ַΪ��\n");
	for (int i = 0; i < 2; i++) {
		printf("%s\t", my_ip[i]);
		printf("%s\n", my_mask[i]);
	}

	//��ȡ����MAC��ַ
	Get_Host_Mac(inet_addr(my_ip[0]));
	printMac(my_mac);

	//·�ɱ�
	RouteTable my_route;

	//����ת���߳�
	hThread = CreateThread(NULL, SIZE_MAX, Recv_Handle, LPVOID(&my_route), 0, &dwThreadId);


	//��·�ɱ����ز���

	int op;
	while (1)
	{
		printf("\n\n��ѡ��Ҫ���еĲ�����\n1. ���·�ɱ���\n2. ɾ��·�ɱ���\n3. ��ӡ·�ɱ�\n");
		scanf("%d", &op);
		RouteEntry* entry = new RouteEntry;

		switch (op) {
		case 1:
			char t[30];
			printf("���������룺");
			scanf("%s", &t);
			entry->mask = inet_addr(t);
			printf("������Ŀ�����磺");
			scanf("%s", &t);
			entry->dst_net= inet_addr(t);
			printf("��������һ����IP��ַ��");
			scanf("%s", &t);
			entry->next_hop = inet_addr(t);
			entry->type = 1;
			entry->print();
			my_route.add(entry);
			break;
		case 2:
			my_route.print();
			printf("������Ҫɾ���ı����������");
			int i;
			scanf("%d", &i);
			my_route.erase(i);
			break;
		case 3:
			my_route.print();
			break;
		default:
			printf("��Ч����������������\n");
			break;
		}
	}
	return 0;

}
