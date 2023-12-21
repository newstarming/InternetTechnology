#include"MYstruct.h"

/*һЩȫ�ֱ���*/

extern char my_ip[10][20];//�򿪵�������Ӧ��ip��ַ
extern char my_mask[10][20];//�򿪵�������Ӧ������
extern BYTE my_mac[6];//����MAC��ַ
extern PacketBuffer my_buffer[MAX_BUFFER_COUNT];//�������ݱ���������
extern Log my_log;//��־
extern ArpTable my_arptable[50];//ARPӳ���
extern int pktNum;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern RouteTable my_route;


pcap_t* open(char* name) {

	pcap_t* temp = pcap_open(name, 65536/*���ֵ*/, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (temp == NULL)
		printf("�޷����豸\n");
	return temp;
}
/*·�ɱ���*/
void RouteEntry::print()
{
	//��ӡ���
	printf("%d   ", number);

	
	in_addr addr;
	
	//��ӡ����
	addr.s_addr = mask;
	//ת��������
	char* str = inet_ntoa(addr);
	printf("%s\t", str);

	//��ӡĿ������
	addr.s_addr = dst_net;
	str = inet_ntoa(addr);
	printf("%s\t", str);

	//��ӡ��һ��ip��ַ
	addr.s_addr = next_hop;
	str = inet_ntoa(addr);
	printf("%s\t", str);
	
	//�û��Ƿ�ɲ���

	if (type == 0)
		printf("non_accessable\n");
	else
		printf("accessable\n");

	printf("\n");

}

/*·�ɱ�*/

//��ʼ�������ֱ�����ӵ�����

RouteTable::RouteTable()
{
	head = new RouteEntry;
	head->next = NULL;
	num = 0;
	//ͨ���õ���˫IP�����룬��·�ɱ������ֱ�����������磬����������Ϊ0��������ɾ����
	for (int i = 0; i < 2; i++)
	{
		RouteEntry* entry = new RouteEntry;
		//���ֱ������������
		entry->dst_net = (inet_addr(my_ip[i])) & (inet_addr(my_mask[i]));
		entry->mask = inet_addr(my_mask[i]);
		entry->type = 0;
		this->add(entry);
	}

}

//·�ɱ�������
void RouteTable::add(RouteEntry*  r) {
	RouteEntry* temp;
	//��·�ɱ��ǿյ�
	if (num == 0) {
		head->next = r;
		r->next = NULL;
	}
	else {

		temp = head->next;
		while (temp != NULL) {
			//�����СС��temp������temp->next
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
	//���±��
	for (int i = 0; p != NULL; i++)
	{
		
		p->number = i;
		p = p->next;
	}
	num++;
	my_log.addInfo("·�ɱ���ӳɹ�!");
	return;


}
//·�ɱ����ɾ��
//ɾ����i��·�ɱ���
void RouteTable::erase(int index) {
	
	RouteEntry* temp = new RouteEntry;
	bool hav = false;
	for (RouteEntry* t = head; t->next != NULL; t = t->next)
	{
		if (t->next->number == index)hav = true;
	}
	if (!hav) {
		printf("���޴�����������룡\n");
		return;
	}

	if (index == 0)//ɾ����һ��
	{
		temp = head->next;
		//Ĭ��·�ɱ����ɾ
		if (temp->type == 0)
		{
			printf("û��Ȩ��ɾ�����\n");
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
				printf("�ѳɹ�ɾ��ָ���\n");
				
			}

		}
	}
	else
	{
		temp = head->next;
		for (int i = 0; i < index - 1; i++)//������index��,Ѱ��ɾ������ǰ�����
		{
			temp = temp->next;
		}
		RouteEntry* rem = new RouteEntry;
		rem = temp->next;//Ҫɾ���Ľ��x

		if (rem->type == 0)
		{
			printf("û��Ȩ��ɾ�����\n");
			return;
		}
		if (rem->next == NULL)//βɾ
		{
			temp->next = NULL;
			
		//	printf("�ѳɹ�ɾ��ָ���\n");
			
		}
		//�м�ɾ
		temp->next = rem->next;
		printf("�ѳɹ�ɾ��ָ���\n");

	}
	/*���±��*/

	RouteEntry* p = head->next;
	//����Ϊ������
	for (int i = 0; p != NULL; i++)
	{
		p->number = i;
		p = p->next;
	}
	num--;
	my_log.addInfo("·�ɱ�ɾ���ɹ�!");
	return ;	
}

//��ӡ·�ɱ�
void RouteTable::print() {
	RouteEntry* temp = head->next;
	printf("--------------------------·�ɱ�----------------------\n");
	int t = 0;
	while (temp!=NULL) {
		temp->print();
		temp = temp->next;
		t++;
	}
	printf("����·�ɱ��");
	printf("%d   ", num);
	printf("��/n");
}

//������һ����IP��ַ(����ΪĿ��ip��ַ��
DWORD RouteTable::search(DWORD dst_ip) {

	DWORD a = -1;
	RouteEntry* t = head->next;
	for (; t!= NULL; t = t->next) {

		if ((t->mask & dst_ip) == t->dst_net) {
			if (t->type == 0)//ֱ������������
			{
				a= dst_ip;
			}
			else
			a = t->next_hop;
		}
	}
	return a;
}

/*mac��ַӳ���ARP*/


/*��־��ӡ����*/
FILE* Log::my_fp = nullptr;

Log::Log()
{
	my_fp = fopen("my_log.txt", "a+");//�Ը��ӵķ�ʽ���ļ�
}
Log::~Log()
{
	fclose(my_fp);
}
//��־��Ϣ��ʶ
void Log::addInfo(const char* str) {
	fprintf(my_fp, str);
	fprintf(my_fp, "\n");
}
void Log::addInfohop(const char* str/*��־��Ϣ��ʶ*/, DWORD hop) {
	fprintf(my_fp, str);
	if (hop == -1)
		fprintf(my_fp, "%s  \n", "-1");
	in_addr addr;
	addr.s_addr = hop;
	char* str1 = inet_ntoa(addr);
	fprintf(my_fp, "%s  \n", str1);
}

//ARP���ݱ���Ϣ
void Log::ARP_info(const char* str, ARPFrame_t* p) {
	fprintf(my_fp, str);
	fprintf(my_fp, "----------------------------ARP ���ݰ�--------------------------------\n");

	in_addr addr;
	addr.s_addr = p->SendIP;
	char* str1 = inet_ntoa(addr);
	fprintf(my_fp, "ԴIP�� ");
	fprintf(my_fp, "%s  \n", str1);

	fprintf(my_fp, "ԴMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->SendHa[i]);
	fprintf(my_fp, "%02X\n", p->SendHa[5]);

	in_addr addr2;
	addr2.s_addr = p->RecvIP;
	char* str2 = inet_ntoa(addr2);
	fprintf(my_fp, "Ŀ��IP�� ");
	fprintf(my_fp, "%s  \n", str2);

	fprintf(my_fp, "Ŀ��MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->RecvHa[i]);
	fprintf(my_fp, "%02X\n", p->RecvHa[5]);
	fprintf(my_fp, "\n");
}


//IP���ݱ�
void Log::IP_info(const char* str, IPFrame_t* p) {
	fprintf(my_fp, str);
	fprintf(my_fp, "--------------------------IP ���ݰ�--------------------------\n");

	in_addr addr;
	addr.s_addr = p->IPHeader.SrcIP;
	char* str1 = inet_ntoa(addr);

	fprintf(my_fp, "ԴIP�� ");
	fprintf(my_fp, "%s\n", str1);
	addr.s_addr = p->IPHeader.DstIP;
	char* str2 = inet_ntoa(addr);
	fprintf(my_fp, "Ŀ��IP�� %s\n", str2);

	fprintf(my_fp, "ԴMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(my_fp, "%02X-", p->FrameHeader.SrcMAC[i]);
	fprintf(my_fp, "%02X\n", p->FrameHeader.SrcMAC[5]);

	fprintf(my_fp, "Ŀ��MAC�� ");
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

//��ӡMAC��ַ
void printMac(BYTE MAC[])//��ӡmac��ַ
{
	printf("MAC��ַΪ�� ");
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}


/*ARP��*/
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

//������IP���ݰ�ͷ
unsigned short calCheckSum1(IPHeader_t* temp)
{
	// temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	//WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	WORD* t = (WORD*)temp;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
		//������������лؾ�
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	// temp->Checksum = ~sum;//���ȡ��
	return (unsigned short)~sum;
}

unsigned short calCheckSum2(unsigned short* pBuffer, int nSize) {
	///*
	//* ���㷽������У����ֶ�����Ϊ0�������������Ѿ�Ϊ0�ģ�
	//* ��˳���ÿ16λ��1����=2�ֽڣ����мӷ����㣻
	//* �������ͽ���λ�ӵ����λ
	//* ���ۼӵĽ��ȡ����������ͷ��У���ֵ
	//*/
	unsigned long ulCheckSum = 0;
	while (nSize > 1)
	{
		ulCheckSum += *pBuffer++;
		nSize -= sizeof(unsigned short);//ÿ16λһ��
	}
	if (nSize)
	{
		ulCheckSum += *(unsigned short*)pBuffer;
	}

	ulCheckSum = (ulCheckSum >> 16) + (ulCheckSum & 0xffff);
	ulCheckSum += (ulCheckSum >> 16);
	return (unsigned short)(~ulCheckSum);
}
//����
bool check_checksum(IPFrame_t* temp) {
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			//����ԭУ���һ��������
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}

	if (sum == 65535)return 1;//ȫ1��У�����ȷ
	return 0;
}