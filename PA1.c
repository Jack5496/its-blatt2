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

int getStringReplacedWithNumbers(char* input){

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
		printf("Length Line: %d\0",strlen(line));
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
			passBase = malloc(length*sizeof(char));
			memcpy(passBase, &line[startpos],length);
			
			pass_file_line = malloc(strlen(line)*sizeof(char));
			strcpy(pass_file_line, line);
		}
	}
	return 0;
}

int checkIfBase64SHA1Matches(char word[], char base[]){
		int comp = strcmp(passBase,base);
	
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

int checkVersionsOfWord(char* word){
	char* alternWord = (char*)malloc(strlen(word) * sizeof(char));
	strcpy(alternWord,word);
	getStringReplacedWithNumbers(alternWord);
	
	checkIfIsPassword(word);
	checkIfIsPassword(alternWord);	
	
	return 0;
}

int word_found(char* line, int word_length, int position){
	char* word = (char*)malloc((word_length)*sizeof(char));
	memcpy(word, &line[position-word_length],word_length);
	word[word_length] = '\0';
		
	checkVersionsOfWord(word);
	
	return 0;
}

int searchForWordsInLine(char* line){
	int i;
	int found_words = 0;
	int word_length = 0;
	for(i=0; i<strlen(line); i++){
		if(isalpha(line[i])){
			word_length=word_length+1;
		}
		else{
			if(word_length>0){
				found_words = found_words+1;
				word_found(line,word_length,i);
			}			
			word_length = 0;
		}
	}
	if(word_length>0){
		found_words = found_words+1;
		word_found(line,word_length,i);
	}
	
	return found_words;
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
	
	int line_number = 0;
	int word_amount = 0;
	while(fgets(line, lineBufferSize, dict_file)){
		word_amount = word_amount+searchForWordsInLine(line);
		line_number = line_number+1;
	}
	printf("Finished Reading %d words\n",word_amount);
	fclose(dict_file);
	printf("Ende\n");
	return 0;
}

int freeAllAlocated(){
	free(path_to_dictionary);
	free(path_to_passfile);
}

int main(int argc, char **argv){
	printf("\n");
	
	else if(argc==3){
		path_to_dictionary = argv[1];
		path_to_passfile = argv[2];
	
		savePassBase();

		iterateOverLinesInDictionary();
		
		freeAllAlocated();

	}
		
	return 0;
}
