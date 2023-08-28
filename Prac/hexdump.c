#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "hexdump.h"
void DumpHex(const void* data, size_t size){
	int i=0;
	int len=(int)size;
	
	for (i = 0; i < len; ++i) 
	{
	    if(i==0)printf("%06X ",i);
	    else {
	    	if(i%16==8)printf(" =");
	    	 else if(i%16 == 0)printf("\n%06X ",i);
	    	}
	    printf(" %02X",((unsigned char*)data)[i]);
	    if(i+1==size)printf("\n");
	}
}
