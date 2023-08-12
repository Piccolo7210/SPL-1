#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
void DumpHex(const void* data, size_t size,unsigned int line);
int main(){
    FILE *fp;
    char str[16];
    int i=0;
    if((fp=fopen("test.pcap","r"))== NULL){
        printf("Error on opening.\n");
        exit(1);
    }
   unsigned char a;
   unsigned int c=0,line=0;
   while(!feof(fp)){
   	a=fgetc(fp);
   	if(a==-1)break;
   	str[c]=a;
   	c++;
   	
   	if(c==16){
   	DumpHex(str,c,line);
   	line+=c;
   	c=0;
   	}
   }
   if(c!=0){
   DumpHex(str,c-1,line);
   	}
   fclose(fp);
    return 0;

}
void DumpHex(const void* data, size_t size ,unsigned int line){
	size_t i, j;
	int c=(int)size;
	printf("%08x ",line);
	for (i = 0; i < size; ++i) {
	printf("%02x ", ((unsigned char*)data)[i]);
		if ((i+1) % 8 == 0 || i+1 == size) 
		{
			if((i+1)% 8 ==0)printf(" ");
			if ((i+1) % 16 == 0) printf("\n");
			else if (i+1 == size) {
			printf("\n");
			printf("%08x\n",line+c);
			}
		}
	}
}
