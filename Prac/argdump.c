#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
void packetinfo(unsigned char *packet,int size);
void packettype(unsigned char *type);
void protocoltype(unsigned char *type);
void hardwaretype(unsigned char *type);
void pipeline();
void commandLine(char *pcapfile);
int main(int argc,char *arg[]){
	if(argc==1)pipeline();
	if(argc==2)commandLine(arg[1]);

}
void pipeline(){
	unsigned char data[2000],*ptr;
	unsigned int value;
	int i,packetlen;
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
	DumpHex(data,i);
	printf("\n\n");
	// Record
	printf("PCAP RECORD HEADER:\n");
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
	data[i]='\0';
	DumpHex(data,i);
	printf("\n\n");
	ptr=data;
	packetlen=*((unsigned int*)(ptr+8));
	
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
	printf("\n");
}
void commandLine(char *pcapfile){
	FILE *fp;
	unsigned char data[2000],*ptr;
	unsigned int value;
	int i,packetlen;
	if((fp=fopen(pcapfile,"rb"))== NULL){
        printf("No such pcap file found. Error.\n");
        exit(1);
    }
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
	// Record
	printf("PCAP RECORD HEADER:\n");
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
	data[i]='\0';
	DumpHex(data,i);
	printf("\n\n");
	ptr=data;
	packetlen=*((unsigned int*)(ptr+8));
	
	// PAcket data
	printf("Packet Data:\n");
	for(i=0;i<packetlen;i++)
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
	fclose(fp);	
	packetinfo(data,packetlen);	
}
void packetinfo(unsigned char *data,int size){
	int i,j;
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
	printf("PADDING : ");
	for(j=42;j<size;j++){
	printf("%02X ",((unsigned char *)data)[j]);
	}
	printf("\n\n");
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
void packettype(unsigned char *type){
	if((int)type[0] == 8 && (int)type[1] == 6){
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




