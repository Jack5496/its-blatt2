#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

char* path_to_dictionary = "rfc793.txt";
char* path_to_passfile = "passfile";

char* getStringReplacedCharWithNumbers(char* input){
	char* output = (char*)malloc(strlen(input) * sizeof(char));
	strcpy(output,input);

	int i;
	for(i=0; i<strlen(output); i++){
		switch(output[i]){
			case 'o': case 'O': output[i] = '0'; break;
			case 'i': case 'I': output[i] = '1'; break;
			case 'r': case 'R': output[i] = '2'; break;
			case 'e': case 'E': output[i] = '3'; break;
			case 'a': case 'A': output[i] = '4'; break;
			case 's': case 'S': output[i] = '5'; break;
			case 't': case 'T': output[i] = '7'; break;
			case 'b': case 'B': output[i] = '8'; break;
			case 'g': case 'G': output[i] = '9'; break;
			default: break;
		}
	}
	printf("\n");

	return output;
}

int word_found(char* line, int word_length, int position){
	char* word = (char*)malloc((word_length+1)*sizeof(char));
	memcpy(word, &line[position-word_length],word_length);
	word[word_length] = '\0';
	//printf("%s ",word);
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
	// what if line ends with word?
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
	return 0;
}


int main(int argc, char **argv){
	printf("\n");
	
	if(argc==1){
		printf("Using standard Paths:\n");
	}
	else if(argc==3){
		path_to_dictionary = (char*)malloc(strlen(argv[1]) * 
					sizeof(char));
		strcpy(path_to_dictionary,argv[1]);

		path_to_passfile = (char*)malloc(strlen(argv[2]) * 
					sizeof(char));
		strcpy(path_to_passfile,argv[2]);
	}
	else{
		printf("Usage: PA1 PathToDictionary PathToPassfile\n");
	}
	
	printf("Path to Dictionary: %s\n",path_to_dictionary);
	printf("Path to Passfile: %s\n",path_to_passfile);

	char* replaced_text = getStringReplacedCharWithNumbers("Testen");
	printf("Replace 'Testen' -> %s\n",replaced_text);

	iterateOverLinesInDictionary();
}
