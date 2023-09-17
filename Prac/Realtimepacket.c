#include<stdio.h>
#include <unistd.h>
#include <signal.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
void IPheader(unsigned char*,int);
void tcpPacket(unsigned char*,int);
void udpPacket(unsigned char*,int);
void icmpPacket(unsigned char*,int);
void Hexdata(unsigned char*,int);
void CapturingPacket(unsigned char*,int);
int rawSocket;
struct sockaddr_in source,dest;
int ICMP_num=0,UDP_num=0,TCP_num=0,others=0,total=0,i,j;
FILE *fp;
int main(){
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
	rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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
void CapturingPacket(unsigned char* buff,int dataSize){
	struct iphdr *iph=(struct iphdr*)buff;
	total++;
	switch (iph->protocol) {
		case 1:  
			ICMP_num++;
			icmpPacket(buff,dataSize);
			break;
		case 6:  //TCP Protocol
			TCP_num++;
			tcpPacket(buff , dataSize);
			break;
		
		case 17: //UDP Protocol
			UDP_num++;
			udpPacket(buff , dataSize);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			sleep(1);
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d    Others : %d   Total : %d\n",TCP_num,UDP_num,ICMP_num,others,total);
}
void IPheader(unsigned char* buff, int dataSize)
{
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)buff;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(fp,"\n");
	fprintf(fp,"IP Header\n");
	fprintf(fp,"     IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(fp,"     IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(fp,"     Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(fp,"     IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(fp,"     Identification    : %d\n",ntohs(iph->id));
	fprintf(fp,"     TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(fp,"     Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(fp,"     Checksum : %d\n",ntohs(iph->check));
	fprintf(fp,"     Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(fp,"     Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void tcpPacket(unsigned char* buff, int dataSize)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)buff;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(buff + iphdrlen);
			
	fprintf(fp,"\n\n***********************TCP Packet*************************\n");	
		
	IPheader(buff,dataSize);
		
	fprintf(fp,"\n");
	fprintf(fp,"TCP Header\n");
	fprintf(fp,"     Source Port      : %u\n",ntohs(tcph->source));
	fprintf(fp,"     Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(fp,"     Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(fp,"     Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(fp,"     Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(fp,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(fp,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(fp,"     Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(fp,"     Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(fp,"     Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(fp,"     Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(fp,"     Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(fp,"     Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(fp,"     Window         : %d\n",ntohs(tcph->window));
	fprintf(fp,"     Checksum       : %d\n",ntohs(tcph->check));
	fprintf(fp,"     Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(fp,"\n");
	fprintf(fp,"                        DATA Dump                         ");
	fprintf(fp,"\n");
		
	fprintf(fp,"IP Header\n");
	Hexdata(buff,iphdrlen);
		
	fprintf(fp,"TCP Header\n");
	Hexdata(buff+iphdrlen,tcph->doff*4);
		
	fprintf(fp,"Data Payload\n");	
	Hexdata(buff + iphdrlen + tcph->doff*4 , (dataSize - tcph->doff*4-iph->ihl*4) );
						
	fprintf(fp,"\n###########################################################");
	//refresh();
}

void udpPacket(unsigned char *buff , int dataSize)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)buff;
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(buff + iphdrlen);
	
	fprintf(fp,"\n\n***********************UDP Packet*************************\n");
	
	IPheader(buff,dataSize);			
	
	fprintf(fp,"\nUDP Header\n");
	fprintf(fp,"   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(fp,"   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(fp,"   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(fp,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(fp,"\n");
	fprintf(fp,"IP Header\n");
	Hexdata(buff , iphdrlen);
		
	fprintf(fp,"UDP Header\n");
	Hexdata(buff+iphdrlen , sizeof udph);
		
	fprintf(fp,"Data Payload\n");	
	Hexdata(buff + iphdrlen + sizeof udph ,( dataSize - sizeof udph - iph->ihl * 4 ));
	
	fprintf(fp,"\n###########################################################");
	//refresh();
}

void icmpPacket(unsigned char* buff , int dataSize)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)buff;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(buff + iphdrlen);
			
	fprintf(fp,"\n\n***********************ICMP Packet*************************\n");	
	
	IPheader(buff , dataSize);
			
	fprintf(fp,"\n");
		
	fprintf(fp,"ICMP Header\n");
	fprintf(fp,"   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11) 
		fprintf(fp,"  (TTL Expired)\n");
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
		fprintf(fp,"  (ICMP Echo Reply)\n");
	fprintf(fp,"   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(fp,"   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(fp,"   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(fp,"   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(fp,"\n");

	fprintf(fp,"IP Header\n");
	Hexdata(buff,iphdrlen);
		
	fprintf(fp,"UDP Header\n");
	Hexdata(buff + iphdrlen , sizeof icmph);
		
	fprintf(fp,"Data Payload\n");	
	Hexdata(buff + iphdrlen + sizeof icmph , (dataSize - sizeof icmph - iph->ihl * 4));
	
	fprintf(fp,"\n###########################################################");
	//refresh();
}

void Hexdata (unsigned char* data , int dataSize)
{
	
	for(i=0 ; i < dataSize ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(fp,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(fp,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(fp,"."); //otherwise print a dot
			}
			fprintf(fp,"\n");
		} 
		
		if(i%16==0) fprintf(fp,"   ");
			fprintf(fp," %02X",(unsigned int)data[i]);
				
		if( i==dataSize-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(fp,"   "); //extra spaces
			
			fprintf(fp,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(fp,"%c",(unsigned char)data[j]);
				else fprintf(fp,".");
			}
			fprintf(fp,"\n");
		}
	}
}



