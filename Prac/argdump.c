#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
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
	fclose(fp);
	printf("\n");
	
}






