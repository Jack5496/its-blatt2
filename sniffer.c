#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<sys/socket.h>
#include<arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include "PA2.h"
 
int ProcessPacket(unsigned char* , int);
int filter_remaining_length(unsigned char* , int);
int filter_connect_packet(unsigned char* , int);
int filter_protocol_name(unsigned char* , int,int,int);
int filter_connect_flags(unsigned char* , int,int,int);
 
int sock_raw;
int password_found = 0;
FILE *logfile;
int tcp=0,others=0,total=0,i,j;
struct sockaddr_in source,dest;
 
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
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}
 
int ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 6:
            filter_connect_packet(buffer , size);
            break;
        default: 
            break;
    }
 
  return 0;
}

int filter_connect_packet(unsigned char* Buffer, int Size)
{
    struct iphdr* iph;
    struct tcphdr* tcph;
 
    char* data_payload = get_tcp_payload(Buffer,&iph ,&tcph );
 
    char mqtt_packet_type = data_payload[0] & 0xF0;
    int is_connect_packet = mqtt_packet_type==16;
 
    if(is_connect_packet){
       printf("Found a Connect Packet !\n");
       return filter_remaining_length(data_payload,Size);
    }
    else{
       return 0;
    }
}
 
int filter_remaining_length(unsigned char* data_payload, int Size)
{
    int pos = 1;
    int multiplier = 1;
    int remaining_length = 0;
 
    remaining_length = data_payload[pos];
    
 
    pos++;
    char encodedByte = data_payload[pos];
   
    while((encodedByte & 128) != 0){
      remaining_length += (encodedByte & 127) * multiplier;
      multiplier *= 128;
      if (multiplier > 128*128*128){
          printf("Error: Remaining Length is not valid!");
          return -1;
      }
     
      pos++;
      encodedByte = data_payload[pos];
    }
 
    fprintf(logfile,"\n\n***********************Connect Packet*************************\n");    
    fprintf(logfile,"Remaining Length: %d\n",remaining_length);  
    filter_protocol_name(data_payload, Size, remaining_length, pos);
 
    fprintf(logfile,"\n###########################################################"); 
 
     return 0;
}
 
int filter_protocol_name(unsigned char* data_payload, int Size, int remaining_length, int pos ){
 
 pos++;
 int length_protocol_name = (int)data_payload[pos];
 pos++;
 
 char protocol_name[length_protocol_name];
 
 fprintf(logfile,"Protocol Name: ");  
 int i;
 for(i=0;i<length_protocol_name;i++){
  
  protocol_name[i] = data_payload[pos];
  fprintf(logfile,"%c",protocol_name[i]);
  pos++;
 }
 fprintf(logfile,"\n");  
 
 int is_mqtt = strcmp(protocol_name,"MQTT");
 int is_mqisdp = strcmp(protocol_name,"MQIsdp");
 
 if(is_mqtt || is_mqisdp){
  pos++; // skip Protocol Level
  filter_connect_flags(data_payload, Size, remaining_length, pos);
 }
 
 
 return 0;
}


int filter_connect_flags(unsigned char* data_payload, int Size, int remaining_length, int pos ){
 //pos stands now on connect flags
 fprintf(logfile,"Connect Flags: \n");
 
 int is_user_name_flag = data_payload[pos] && 0x80;
 int is_password_flag = data_payload[pos] && 0x40;
 
 fprintf(logfile,"-- User Name Flag: %d\n",is_user_name_flag);
 fprintf(logfile,"-- Password Flag: %d\n",is_password_flag);
 
 
 
 
}











