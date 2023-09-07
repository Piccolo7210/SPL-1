#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
void packetinfo(unsigned char *packet,int size);
void ICMPinfo(unsigned char *packet,int size);
void packettype(unsigned char *type);
void protocoltype(unsigned char *type);
void hardwaretype(unsigned char *type);
void IPtype(unsigned char *type);
void pipeline();
void commandLine(char *pcapfile);
int main(int argc,char *arg[]){
	if(argc==1)pipeline();
	if(argc==2)commandLine(arg[1]);

}
void pipeline(){
	unsigned int value=0;
	//while(value!=-1){
	
	unsigned char data[2000];
	int i,packetlen,pac_num=0;
	
	// Global Header reading;
	printf("GLOBAL HEADER READING:\n");
	for(i=0;i<24;i++)
	{
		value=getchar();
		if(value==EOF)
		{
		  putchar('\n');
		  return;
		}
		data[i]= value & 0xFF;
	}
	data[i]='\0';
	//ptr=&data[0];
	
	DumpHex(data,i);
	printf("\n\n");
	// Record
	while(1){
	
	for(i=0;i<16;i++)
	{
	    value=getchar();
	    if(value==EOF)
	     {
		 putchar('\n');
		 return;
	     }
		data[i]= value & 0xFF;
		
	}
	printf("PCAP RECORD HEADER:\n");
	data[i]='\0';
	DumpHex(data,i);
	printf("\n\n");
	
	packetlen=data[8];
	printf("*** PACKET NUMBER : (%d) ***\n\n",++pac_num);
	// PAcket data
	printf("Packet Data:\n");
	for(i=0;i<packetlen;i++)
	{
	    value=getchar();
	    if(value==EOF)
	     {
		 putchar('\n');
		 return;
	     }
		data[i]= value & 0xFF;
		
	}
	data[i]='\0';
	
	DumpHex(data,i);
	packetinfo(data,packetlen);
	printf("\n");
	//ptr=NULL;
	}
}
void commandLine(char *pcapfile){
	FILE *fp;
	if((fp=fopen(pcapfile,"rb"))== NULL){
        printf("No such pcap file found. Error.\n");
        exit(1);
    }
    	unsigned char data[2000];
	unsigned int value;
	int i,packetlen;
	// Global Header reading;
	printf("GLOBAL HEADER READING:\n");
	for(i=0;i<24;i++)
	{
		value=fgetc(fp);
		if(value==EOF)
		{
		  putchar('\n');
		  return;
		}
		data[i]= value & 0xFF;
	}
	data[i]='\0';
	DumpHex(data,i);
	printf("\n\n");
	while(1){
	// Record
	for(i=0;i<16;i++)
	{
	    value=fgetc(fp);
	    if(value==EOF)
	     {
		 putchar('\n');
		 return;
	     }
		data[i]= value & 0xFF;
		
	}
	printf("PCAP RECORD HEADER:\n");
	data[i]='\0';
	packetlen=data[8];
	DumpHex(data,i);
	// PAcket data
	printf("Packet Data:\n");
	for(i=0;i<packetlen;i++)
	{
	    value=fgetc(fp);
	    if(value==EOF)
	     {
		 putchar('\n');
		 break;
	     }
		data[i]= value & 0xFF;
		
	}
	data[i]='\0';
	DumpHex(data,i);
	printf("\n");	
	ICMPinfo(data,packetlen);
	packetlen=0;
	}
	fclose(fp);
	//packetlen=0;	
	
}
void packetinfo(unsigned char *data,int size){
	int i,j=0;
	unsigned char type[2];
	printf("######################## PACKET ANALYSING ##########################\n\n");
	//1.ETHERNET II PART
	printf("************************ETHERNET PART*******************************\n");
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
	printf("*****************************ARP PART********************************");
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
void IPtype(unsigned char *type){
	if(type[0] == 8 && type[1] == 0){
		printf("(IPv4)");
	}
}




