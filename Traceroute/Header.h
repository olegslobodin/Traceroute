#pragma once

#include <iostream>
#include <string>


#if  defined _WIN32 || defined _WIN64

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <crtdbg.h>

#pragma comment (lib,"ws2_32")

#elif defined __linux__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> //for getnameinfo()
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h> //for getpid()
#include <string.h> //for memcpy()

#define SOCKET_ERROR -1
#define SOCKET int
#define USHORT unsigned short
#define DWORD time_t
#define NI_MAXHOST 1025
#define NI_MAXSERV 32

int MySelect(int socket);

#endif

using namespace std;

typedef struct ip_hdr //IP header
{
	unsigned char verhlen;
	unsigned char tos : 6;
	unsigned char additional : 2;
	unsigned short totallent;
	unsigned short id;
	unsigned short offset;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int source;
	unsigned int destination;
}IpHeader;

typedef  struct icmp_hdr //ICMP header
{
	unsigned char i_type;
	unsigned char i_code;
	unsigned short i_crc;
	unsigned short i_seq;
	unsigned short i_id;

}IcmpHeader;

void Input(string* ip, string* ipLocal);

SOCKET InitSocket(sockaddr_in my_addr);

sockaddr_in InitAddress(unsigned long addr);

void Work(SOCKET my_socket, string ip, string ipLocal, sockaddr_in remoteAddr);

IcmpHeader* GetIcmpPackage(int icmp_size, char* package_memory);

void InitIpPackage(char* ip_package, SOCKET my_socket, int ip_size, int icmp_size, IcmpHeader *icmp_package, string ip, string ipLocal);

void Ping(SOCKET my_socket, string ip, char* package, int package_size, sockaddr_in remoteAddr);

void Traceroute(SOCKET my_socket, string ip, char* package, int package_size, sockaddr_in remoteAddr, bool manualIp);

unsigned int Analyze(char* data, sockaddr_in* adr, DWORD time = NULL);

USHORT crc2(USHORT* addr, int count);

void PrintLastError();

unsigned long inet_addr(string cp);