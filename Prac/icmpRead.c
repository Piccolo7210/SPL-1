#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
#include "icmpRead.h"
void ICMPinfo(unsigned char *data,int size){
	int i,j=0;
	unsigned char type[2];
	printf("######################## PACKET ANALYSING ##########################\n\n\n");
	//1.ETHERNET II PART
	printf("************************ETHERNET PART*******************************\n\n");
	// DETERMINING MAC ADDRESS OF DESTINATION first 6 bytes
	printf("DESINATION MAC ADDRESS: ");
	for(i=0;i<6;i++){
		printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	//SOURCE ADDRESS. 6bytes after destination mac address
	printf("SOURCE:  ");
	for(;i<12;i++){
		printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	//PACKET TYPE Showing. 2bytes after 12 bytes
	printf("IP TYPE: ");
	for(;i<14;i++){
		type[j++]=((unsigned char *)data)[i];
		printf("%02X ",((unsigned char *)data)[i]);
	}
	IPtype(type);
	printf("\n\n");
	printf("*****************IP PART*********************\n\n");
	i=15;
	printf("DIFFERENTIATED SERVICE FIELD : %02X",((unsigned char *)data)[i]);
	printf("\n");
	printf("TOTAL LENGTH: ");
	for(i=16;i<18;i++){
		printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("(in HexaDecimal)\n");
	printf("IDENTIFICATION: ");
	for(;i<20;i++){
		printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("(in HexaDecimal)\n");
	printf("FLAGS: ");//i=21;
	printf("%d\n",((unsigned char *)data)[i++]);
	printf("FRAGMENT OFFSET: ");//i=22;
	printf("%d\n",((unsigned char *)data)[i++]);
	printf("TIME TO LIVE: ");//i=23;
	printf("%d\n",((unsigned char *)data)[i++]);
	if(data[i]==1)
	printf("PROTOCOL : ICMP(1)\n");
	i++; //i=24
	printf("HEADER CHECKSUM: ");
	for(;i<26;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	printf("SOURCE IP ADDRESS: ");
	for(;i<30;i++){
	printf("%d",((unsigned char *)data)[i]);
	if(i!=29)printf(".");
	}
	printf("\n");
	printf("DESTINATION IP ADDRESS: ");
	for(;i<34;i++){
	printf("%d",((unsigned char *)data)[i]);
	if(i!=33)printf(".");
	}
	printf("\n\n");
	printf("*********************ICMP PART*************************\n\n");
	if(data[i] == 0){
	printf("TYPE: ");
	printf("%d",((unsigned char *)data)[i++]);
	printf(" (REPLY)\n");
	}
	else if(data[i] == 8){
	printf("TYPE: ");
	printf("%d",((unsigned char *)data)[i++]);
	printf(" (REQUEST)\n");
	}
	printf("CODE: ");
	printf("%d\n",((unsigned char *)data)[i++]);
	printf("CHECKSUM: ");
	for(;i<38;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	printf("IDENTIFIER: ");
	for(;i<40;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	printf("SEQUENCE NUMBER: ");
	for(;i<42;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	printf("TIMESTAMP FOR THE ICMP DATA: ");
	for(;i<50;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n\n");
	printf("DATA:\n\n");
	for(;i<size;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n\n");
}
void IPtype(unsigned char *type){
	if(type[0] == 8 && type[1] == 0){
		printf("(IPv4)");
	}
}
void packettype(unsigned char *type){
	if(type[0] == 8 && type[1] == 6){
		printf("(ARP PACKET)");
	}
}
void hardwaretype(unsigned char *type){
	if(type[0] == 0 && type[1] == 1){
		printf("(ETHERNET)");
	}
}
void protocoltype(unsigned char *type){
	if(type[0] == 8 && type[1] == 0){
		printf("(IPv4)");
	}
}

