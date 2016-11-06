#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include "util.h"

char* path_to_dictionary;
char* path_to_passfile;
FILE *pass_file;
char* realBase;
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

int printFoundPassword(char* word, char* line){
	printf("%s: %s",word,line);
}

int checkPasswordMatches(char* word, char* base){
	int comp = strcmp(realBase,base);

	if(comp==0){		
		printFoundPassword(word,pass_file_line);
	}
}

int readBasedHashFromPassfile(){
	
	pass_file = fopen(path_to_passfile,"r");

	if(!pass_file){
		printf("Error: while opening Passfile");
		return 1;
	}

	int lineBufferSize = 256;

	char line[lineBufferSize];
	
	while(fgets(line, lineBufferSize, pass_file)){
		int startpos = -1;
		int offset;
		for(offset=0; offset<strlen(line); offset++){
			if(line[offset]=='}'){
				startpos=offset+1;
				break;
			}
		}

		if(startpos!=-1){
			int length = strlen(line)-startpos-1;
			realBase = (char*)malloc((length)*sizeof(char));
			memcpy(realBase, &line[startpos],length);
			
			pass_file_line = (char*)malloc((strlen(line))*sizeof(char));
			memcpy(pass_file_line, &line[0],strlen(line));
			
		}	
	}
	
	fclose(pass_file);
	
	return 0;
}

int checkIfIsPassword(char* word){
	int old_size = strlen(word);
	char fixed[old_size+1];

	int pos;
	for(pos=0;pos<old_size; pos++){
		fixed[pos]=word[pos];
	}	
	fixed[old_size] = '\0';
	size_t length = strlen(fixed);

	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(fixed,length,hash);	
	char* base = (char*)malloc(29*sizeof(char));
	b64sha1(hash,base);

	checkPasswordMatches(word,base);
	
	free(base);

	return 0;
}

int checkVersionsOfWord(char* word){
	char* alternWord = (char*)malloc(sizeof(char)*strlen(word));
	memcpy(alternWord,word,strlen(word));
	getStringReplacedWithNumbers(alternWord);
	
	checkIfIsPassword(word);
	checkIfIsPassword(alternWord);	
	
	free(alternWord);
	
	return 0;
}

int word_found(char* line, int word_length, int position){
	char* word = (char*)malloc((word_length)*sizeof(char));
	memcpy(word, &line[position-word_length],word_length);
		
	checkVersionsOfWord(word);
	
	free(word);
	
	return 0;
}

int searchForWordsInLine(char* line){
	int i;
	int found_words = 0;
	int word_length = 0;
	for(i=0; i<strlen(line); i++){
		if(isalpha(line[i])){
			word_length++;
		}
		else{
			if(word_length>0){
				found_words++;
				word_found(line,word_length,i);
			}			
			word_length = 0;
		}
	}
	if(word_length>0){
		found_words++;
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

int freeAllAllocated(){
	free(realBase);
	free(pass_file_line);	
}

int main(int argc, char **argv){
	printf("\n");

	if(argc==3){
		path_to_dictionary = argv[1];
		path_to_passfile = argv[2];
		
		readBasedHashFromPassfile();

		iterateOverLinesInDictionary();
		
		freeAllAllocated();
	}
	

	return 0;
}
