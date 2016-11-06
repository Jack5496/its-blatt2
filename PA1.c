#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include "util.h"

char* path_to_dictionary;
char* path_to_passfile;
FILE *pass_file;
char* passBase;
char* pass_file_line;

int getStringReplacedWithNumbers(char input[]){

	int i;
	for(i=0; i<strlen(input); i++){
		switch(input[i]){
			case 'o': case 'O': input[i] = '0'; break;
			case 'i': case 'I': input[i] = '1'; break;
			case 'r': case 'R': input[i] = '2'; break;
			case 'e': case 'E': input[i] = '3'; break;
			case 'a': case 'A': input[i] = '4'; break;
			case 's': case 'S': input[i] = '5'; break;
			case 't': case 'T': input[i] = '7'; break;
			case 'b': case 'B': input[i] = '8'; break;
			case 'g': case 'G': input[i] = '9'; break;
			default: break;
		}
	}
	
	return 0;
}

int savePassBase(){
	pass_file = fopen(path_to_passfile,"r");

	if(!pass_file){
		printf("Error: while opening Passfile");
		return 1;
	}

	int lineBufferSize = 256;

	char line[lineBufferSize];
	
	while(fgets(line, lineBufferSize, pass_file)){
		int offset;
		int startpos = -1;
		for(offset=0; offset<strlen(line); offset++){
			if(line[offset]=='}'){
				startpos=offset+1;
				break;
			}
		}

		if(startpos!=-1){
			int length = strlen(line)-startpos;
			printf("PassBaseLength: %d\n",length);
			passBase = malloc(length*sizeof(char));
			memcpy(passBase, &line[startpos],length);
			
			pass_file_line = malloc(strlen(line)*sizeof(char));
			memcpy(pass_file_line, line,strlen(line));
		}
	}
	return 0;
}

int checkIfBase64SHA1Matches(char word[], char base[]){
		int comp = strcmp(passBase,base);
		printf("Word: %s Base: %s",word,base);
	
		if(comp==0){
			printf("%s: %s",word,pass_file_line);	
		}
}

int checkIfIsPassword(char word[]){	
	unsigned char hash[SHA_DIGEST_LENGTH];
	
	SHA1(word,strlen(word),hash);
	
	unsigned char base[29];
	b64sha1(hash,base);

	checkIfBase64SHA1Matches(word,base);

	return 0;
}

int checkVersionsOfWord(char word[], int word_length){
	char alternWord[word_length];
	memcpy(alternWord,word,word_length);
	
	getStringReplacedWithNumbers(alternWord);
	
	checkIfIsPassword("53cu217y");
	checkIfIsPassword(alternWord);	
	
	return 0;
}

int word_found(char line[], int word_length, int position){
	char word[word_length];
	memcpy(word, &line[position],word_length);
		
	checkVersionsOfWord(word,word_length);
	
	return 0;
}

int searchForWordsInLine(char line[]){
	int i;
	int word_length = 0;
	for(i=0; i<strlen(line); i++){
		if(isalpha(line[i])){
			word_length=word_length+1;
		}
		else{
			if(word_length>0){
				word_found(line,word_length,i-word_length);
			}			
			word_length = 0;
		}
	}
	if(word_length>0){
		word_found(line,word_length,i);
	}
	
	return 0;
}

int iterateOverLinesInDictionary(){
	FILE *dict_file;
	dict_file = fopen(path_to_dictionary,"r");

	if(!dict_file){
		printf("Error: While opening Dictionary File: %s"
			,path_to_dictionary);
		return 1;
	}

	int lineBufferSize = 256;
	char line[lineBufferSize];
	
	while(fgets(line, lineBufferSize, dict_file)){
		searchForWordsInLine(line);
	}
	fclose(dict_file);
	
	return 0;
}

int freeAllAlocated(){

}

int main(int argc, char **argv){
	printf("\n");
	
	if(argc==3){
		path_to_dictionary = argv[1];
		path_to_passfile = argv[2];
	
		savePassBase();

		iterateOverLinesInDictionary();
		
		freeAllAlocated();

	}
		
	return 0;
}
