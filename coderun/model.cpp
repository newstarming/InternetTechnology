/*
 ipv6 address to string or string to ipv6 address;
Edited by Mr Zhu,email:40222865@qq.com or weixin:40222865
*/
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
using namespace std;
int main()
{
   WSADATA wsa_data;
       WORD sockversion = MAKEWORD(2,2);
       if(WSAStartup(sockversion, &wsa_data) != 0)
       {
           return 0;
       }
    struct sockaddr_in6 ser_addr;
    int addr_size=sizeof(struct sockaddr_in6);
    char ip_addr[100]="";
    DWORD string_leng=100;
    int i;

        WSAStringToAddressA("ff::1:ff:1",
                           AF_INET6,
                           NULL,
                           (LPSOCKADDR)&ser_addr,
                           &addr_size);

        printf("16进制ip地址是:");
        for (i = 0; i < 15; i = i + 2)
        {
            printf("%x%x:", ser_addr.sin6_addr.u.Byte[i], ser_addr.sin6_addr.u.Byte[i + 1]);
        }

        ser_addr.sin6_port = htons(5240);
        WSAAddressToStringW((LPSOCKADDR)&ser_addr, // sockaddr类型指针
                            addr_size,             //地址长度
                            NULL,                  //地址协议指针
                            (LPWSTR)ip_addr,       //转换后字符串地址
                            &string_leng           //函数返回的字符串长度
        );

        printf("\nipv6 address is\"%ls\"\n", ip_addr);

        memset(ip_addr, 0, 100);
        ser_addr.sin6_port = htons(0);
        WSAAddressToStringW((LPSOCKADDR)&ser_addr, // sockaddr类型指针
                            addr_size,             //地址长度
                            NULL,                  //地址协议指针
                            (LPWSTR)ip_addr,       //转换后字符串地址
                            &string_leng           //函数返回的字符串长度
        );
        printf("\n端口为0后显示 address is\"%ls\"\n", ip_addr);
        return 1;
}