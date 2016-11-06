#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include "util.h"

char* path_to_dictionary;
char* path_to_passfile;
char* passBase;
char* pass_file_line;

/**
* Einfache ersetzung eines Wortes mit Zahlen
**/
int getStringReplacedWithNumbers(char input[]){

	int i;
	//Durchlaufe das gesammte Wort
	for(i=0; i<strlen(input); i++){
		//Ersetzte passend C00L
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

/**
* Abspeichern des Base64 in extra Variable sowie
* abspeichern der Zeile in extra Variable
**/
int savePassBase(){
	//Initilisiere alles zum zugriff auf die Datei
	FILE *pass_file;
	pass_file = fopen(path_to_passfile,"r");

	//minimale Fehlerbehandlung
	if(!pass_file){
		printf("Error: while opening Passfile");
		return 1;
	}

	int lineBufferSize = 256;
	char line[lineBufferSize];
	
	//Gehe alle Zeilen durch (nur eine wird benutzt endlich)
	while(fgets(line, lineBufferSize, pass_file)){
		int offset;
		int startpos = -1;
		//Gehe die Zeile durch
		for(offset=0; offset<strlen(line); offset++){
			//Prüfe ob Base64 gleich beginnt
			if(line[offset]=='}'){
				//Base64 beginnt nach unserem Zeiger
				startpos=offset+1;
				break;//springe aus for Schleife
			}
		}
		
		//Wenn wir ein Base64 gefunden haben
		if(startpos!=-1){
			int length = 29; //Setzte Länge auf 29
			passBase = malloc(length*sizeof(char)); //Allociere genug platz
			memcpy(passBase, &line[startpos],length-1); //Koopiere reinen Base64
			passBase[length-1]='\0'; //Speichere das ende des String
			pass_file_line = malloc((strlen(line))*sizeof(char)); //Allociere genug platz
			memcpy(pass_file_line, &line[0],strlen(line)-1); //Koopiere Zeile
		}
	}
	
	//Schließe Datei
	fclose(pass_file);
	return 0;
}

/**
* Vergleiche erstellen Base64 mit orginalem
* Gebe ggf. eine Meldung aus
**/
int checkIfBase64SHA1Matches(char word[], char base[]){
		//Vergleiche beide Base64
		int comp = strcmp(passBase,base);
	
		//Wenn diese Übereinstimmen
		if(comp==0){
			//Gebe auf Console aus
			printf("%s: %s\n",word,pass_file_line);	
		}
}

/**
* Erstellen des SHA1 und Base64 davon und prüfung desser
**/
int checkIfIsPassword(char word[]){	
	//Initilisiere platz für Hash
	unsigned char hash[SHA_DIGEST_LENGTH];
	
	//SHA1 das Wort
	SHA1(word,strlen(word),hash);
	
	//Initialisiere platz für die Base
	unsigned char base[29];
	//Erstelle Base64 von SHA1
	b64sha1(hash,base);

	//Prüfe ob erstellter Base64 übereinstimmt mit dem
	//Base64 in der Passwort Datei
	checkIfBase64SHA1Matches(word,base);

	return 0;
}

/**
* Veränderung und Angriff eines Wortes mit bestimmter Länger
**/
int checkVersionsOfWord(char* word, int word_length){
	//Initilisiere Alternatives Wort gleicher Länger
	char alternWord[word_length+1];
	
	int i;
	//koopiere das Wort
	for(i=0;i<word_length+1;i++){
		alternWord[i]=word[i];
	}
	alternWord[word_length]='\0';
	
	//Führe eine einfache ersetzung durch auf der Alternativ
	getStringReplacedWithNumbers(alternWord);
	
	checkIfIsPassword(word); //Angriff mit normalen Wort
	checkIfIsPassword(alternWord);	//Angriff mit veränderten Wort
	
	return 0;
}

/**
* Lese das Wort aus der Linie mit bestimmter Länge von Position
**/
int word_found(char line[], int word_length, int position){
	//Initialisiere Wort mit übergöße
	char word[word_length+1];
	
	int i; //Zeiger var.
	//Fülle unser Wort (nicht die übergröße)
	for(i=0;i<word_length+1;i++){
		//mit dem Buchstaben von der Position ab in der Zeile
		word[i]=line[i+position];
	}
	//Beende das Wort mit dem Escape Char.
	word[word_length]='\0';
	
	//Erstellen von Abwandlungen des Wortes und Angriff
	checkVersionsOfWord(word,word_length);
	
	return 0;
}

/**
* Suchen von Wörtern in einer Zeile
**/
int searchForWordsInLine(char line[]){
	int i; //Zeiger innerhalb der Zeile
	int word_length = 0;	//Gefundene Wortlänge
	
	//Laufe die gesammte Zeile entlang
	for(i=0; i<strlen(line); i++){
		//Falls ein Buchstabe eines Wortes gefunden wurde
		if(isalpha(line[i])){
			//erhöhe die Wortlänge um 1
			word_length=word_length+1;
		}
		//Ein Zeichen dass zu keinem Wort gehört wurde gefunden
		else{
			//Falls wir zuvor ein Wort gelesen haben
			if(word_length>0){
				//möchten wir mit dem Wort angreifen
				word_found(line,word_length,i-word_length);
			}			
			//Entweder ist das Wort zuende oder es gab keines
			word_length = 0;
		}
	}
	//Wir sind komplett durch und schauen nochmal ob wir ein Wort haben
	if(word_length>0){
		//möchten mit dem Wort angreifen
		word_found(line,word_length,i);
	}
	
	return 0;
}

/**
* Der eigentliche Angriff wird hier gestartet
**/
int iterateOverLinesInDictionary(){
	//Initialisiere für die File nötige Variablen
	FILE *dict_file;
	dict_file = fopen(path_to_dictionary,"r");

	//Minimale Fehlerbehandlung
	if(!dict_file){
		printf("Error: While opening Dictionary File: %s"
			,path_to_dictionary);
		return 1;
	}

	//Init. der Variablen zum einlesen einer Line (max. 256)
	int lineBufferSize = 256;
	char line[lineBufferSize];
	
	//Gehe alle Zeilen durch des Wörterbuchs
	while(fgets(line, lineBufferSize, dict_file)){
		//Halte ausschau nach Wörtern zum benutzen
		//und benutze diese dann
		searchForWordsInLine(line);
	}
	
	//Schließen des Wörterbuch
	fclose(dict_file);
	
	return 0;
}

/**
* Aufräumen der Allocated Variablen
**/
int freeAllAlocated(){
	free(passBase);
	free(pass_file_line);
}

/**
* Die Main Function in der Das Programm einsetzt
**/
int main(int argc, char **argv){
	printf("\n");
		
	//Überprüfe ob genügend Argumente vorhanden
	if(argc==3){
		//Speichere Pfade ab auf Parameter
		path_to_dictionary = argv[1];
		path_to_passfile = argv[2];
		
		//Speichere das Base64 Passwort ab
		savePassBase();
		
		//Beginne Wörterbuch Angriff
		iterateOverLinesInDictionary();
		
		//Räum auf
		freeAllAlocated();
	}
	else{
		//Es wurden falsche Eingaben getätigt
		printf("Ungenügend Argumente");
		return 1;
	}
	return 0;
}
