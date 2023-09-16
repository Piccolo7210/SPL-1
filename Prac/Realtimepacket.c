#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
void IP_header(unsigned char*,int);
void TCP_header(unsigned char*,int);
void UDP_header(unsigned char*,int);
void ICMP_header(unsigned char*,int);
void Dumphex(unsigned char*,int);
void CapturingPacket(unsigned char*,int);
int rawSocket;
struct sockaddr_in source,destination;
int ICMP_num=0,UDP_num=0,TCP_num=0,others=0,total=0,i,j;
FILE *fp;
int RealtimePacket(){
	int sockaddSize,dataSize;
	struct sockaddr saddr;
	struct in_addr in;
	unsigned char *buff = (unsigned char *)malloc(65536);
	printf("Starting .......\n");
	fp=fopen("info.txt","w+");
	if(fp==NULL){
		printf("Error on creating FILE.\n");
		return -5;
	}
	rawSocket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(rawSocket<0){
		printf("Socket creating ERROR.\n");
		return -2;// -2 defining as socket error
	}
	while(1){
		sockaddSize= sizeof(struct sockaddr);
		dataSize=recvfrom(rawSocket,buff,65536,0,&saddr,&sockaddSize);
		if(dataSize<0){
			printf("Receiving Failed. Failed to Capture Packets.\n");
			return -3;// Receiving failure defining as -3
		}
		CapturingPacket(buff,dataSize);	
	}
	close(rawSocket);
	printf("Complete.\n");
	return 0;
}
void CapturingPacket(unsigned char*,int){
	struct iphdr *iph=(struct iphdr*)buffer;
	total++;
	switch (iph->protocol) {
		case 1:  
			++icmp;
			PrintIcmpPacket(Buffer,Size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d    Others : %d   Total : %d\n",TCP_num,UDP_num,ICMP_num,others,total);
}
}
