#include <stdio.h>

char path_to_dictionary[] = "rfc793.txt";
char path_to_passfile[] = "passfile";

int main(int argc, char **argv){
	printf("\n");
	prinf("Starting Passwordfinder\n");
	printf("%d",argc);
	for(int i=0; i<argc; i++){
		printf("%s \n",argv[i]);
	}
}
