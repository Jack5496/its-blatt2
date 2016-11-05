#include <stdio.h>

#include <string.h>


#define GB  0

#define KB  1

#define ZL  2

#define PL  3

#define MI  4


/** Kodiert einen 20 Byte SHA1 Hash in Base64 (28Byte)
  
* \param in 20 Byte SHA1 Hash
  
* \param out Pointer auf mindestens 28 Byte Speicher
  
* \return 0 wenn erfolgreich
  **/


int b64sha1(unsigned char* in, unsigned char* out);

int getclass(unsigned char c);

unsigned char translate(unsigned char c);

int b643byte(unsigned char* inp, unsigned char* out,int len);



int getclass(unsigned char c){
	
	if( c < 26) return GB;

	if( c < 52) return KB;

	if( c < 62) return ZL;

	if( c == 62) return PL;

	if( c == 63) return MI;

	return -1;

}



unsigned char translate(unsigned char c){

	switch(getclass(c)){

		case GB:

			return c+0x41;

		case KB:

			return c+71;

		case ZL:

			return c-4;

		case PL:

			return '+';

		case MI:

			return '/';

		default:

			printf("Error in translate\n");

	}

	return 0xFF;

}



int b643byte(unsigned char* inp, unsigned char* out,int len){

	char in[3]={0};
	memcpy(in,inp,len);

	out[0] = (in[0]&0xFC) >> 2;

	out[1] = ((in[0]&0x03) << 4)|((in[1]&0xF0) >> 4);

	out[2] = ((in[1]&0x0F) << 2)|((in[2]&0xC0) >> 6);

	out[3] = (in[2]&0x3F);

	for(int x = 0; x < 4; x++){

		out[x]=translate(out[x]);
 
	}
	if(len <= 2){

		out[3]='=';

	}
	if(len == 1){

		out[2]='=';

	}
	return 0;

}



int b64sha1(unsigned char* in, unsigned char* out){

	for(int x= 0; x< 6; x++){

		b643byte(in+x*3,out+x*4,3);
	}

	b643byte(in+18,out+24,2);

	out[28]='\0';

	return 0;

}

