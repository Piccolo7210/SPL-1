#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
#include "icmpRead.h"
#include "arpRead.h"
void packetinfo(unsigned char *data,int size){
	int i,j=0;
	unsigned char type[2];
	printf("######################## PACKET ANALYSING ##########################\n\n");
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
	printf("PACKET TYPE: ");
	for(;i<14;i++){
		type[j++]=((unsigned char *)data)[i];
		printf("%02X ",((unsigned char *)data)[i]);
	}
	packettype(type);
	printf("\n");
	// PADDING PART 43th BYTES TO LAST BYTE.
	if(size>42){
	printf("PADDING : ");
	for(j=42;j<size;j++){
	printf("%02X ",((unsigned char *)data)[j]);
	}
	printf("\n\n");
	}
	//2.ARP PART :
	printf("*****************************ARP PART********************************\n");
	j=0;
	//HARDWARE TYPE 15TH-16TH BYTE
	printf("\nHARDWARE TYPE: ");
	for(;i<16;i++){
	type[j++]=((unsigned char *)data)[i];
	printf("%02X ",((unsigned char *)data)[i]);
	}
	hardwaretype(type);
	printf("\n");
	// PROTOCOL TYPE 17-18TH BYTE
	printf("PROTOCOL TYPE: ");
	j=0;
	for(;i<18;i++){
	type[j++]=((unsigned char *)data)[i];
	printf("%02X ",((unsigned char *)data)[i]);
	}
	protocoltype(type);
	printf("\n");
	//HARDWARE SIZE 19TH BYTE
	printf("HARDWARE SIZE: %d\n",((unsigned char *)data)[i++]);
	//PROTOCOL SIZE 20 TH BYTE
	printf("PROTOCOL SIZE: %d\n",((unsigned char *)data)[i++]);
	//OPCODE 21-22 BYTE
	printf("OPCODE: %02X ",((unsigned char *)data)[i++]);
	printf("%02X\n",((unsigned char *)data)[i++]);
	//SOURCE MAC ADDRESS 23-28byte
	printf("SENDER MAC ADDRESS: ");
	for(;i<28;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	//SENDER IP ADDRESS 29-32 BYTE
	printf("SENDER IP ADDRESS : ");
	for(;i<32;i++){
	printf("%d",((unsigned char *)data)[i]);
	if(i!=31)printf(".");
	}
	printf("\n");
	//TARGET MAC ADDRESS 33-38byte
	printf("TARGET MAC ADDRESS: ");
	for(;i<38;i++){
	printf("%02X ",((unsigned char *)data)[i]);
	}
	printf("\n");
	//TARGET IP ADDRESS 39-42 BYTE
	printf("TARGET IP ADDRESS : ");
	for(;i<42;i++){
	printf("%d",((unsigned char *)data)[i]);
	if(i!=41)printf(".");
	}
	printf("\n");
}
