#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include "icmpRead.h"
#include "hexdump.h"
#include "arpRead.h"
void pipeline();
void commandLine(char *pcapfile[100]);
int main(int argc,char *arg[]){
	if(argc==1)pipeline();
	if(argc==3)commandLine(arg);

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
	printf("*** PACKET NUMBER : (%d) ***\n\n",++pac_num);
	printf("PCAP RECORD HEADER:\n");
	data[i]='\0';
	DumpHex(data,i);
	printf("\n\n");
	
	packetlen=data[8];
	
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
	printf("\n\n");
	packetinfo(data,packetlen);
	//printf("\n");
	//ptr=NULL;
	}
}
void commandLine(char *pcapfile[100]){
	FILE *fp;
	if((fp=fopen(pcapfile[2],"rb"))== NULL){
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
	// Pcap Record Header
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
	if(!strcmp(pcapfile[1],"-A"))packetinfo(data,packetlen);
	else if(!strcmp(pcapfile[1],"-I"))ICMPinfo(data,packetlen);
	packetlen=0;
	}
	fclose(fp);
}








