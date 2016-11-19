#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<sys/socket.h>
#include<arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include "PA2.h"
 
int ProcessPacket(unsigned char* , int);
int filter_authentication(unsigned char* , int);
int filter_connect_packet(unsigned char* , int);
void PrintData (unsigned char* , int);
 
int sock_raw;
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
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    while(1)
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
       printf("Found a Connect Packer !\n");
       return filter_authentication(data_payload,Size);
    }
    else{
       return 0;
    }
}
 
int filter_authentication(unsigned char* data_payload, int Size)
{
    /**
 
    unsigned short iphdrlen;
     
    struct iphdr* iph;
    struct tcphdr* tcph;
 
    char* data_payload = get_tcp_payload(Buffer,&iph ,&tcph );
              
    int header_len = 4*(tcph->doff + iph->ihl);
    */
    int pos = 0;
    int multiplier = 1;
    int remaining_length = 0;
    char encodedByte;   
 
    do{
     encodedByte = data_payload[pos];
     remaining_length += (encodedByte & 127) * multiplier;
     multiplier *= 128;
     if (multiplier > 128*128*128){
         printf("Error: Remaining Length is not valid!");
         return -1;
     }
     pos++;
    }
    while((encodedByte & 128) != 0);
 
    printf("Remaining Length: %d",remaining_length);
 
        fprintf(logfile,"\n\n***********************Connect Packet*************************\n");    
        /**
        print_ip_header(Buffer,Size);

        fprintf(logfile,"\n");
        fprintf(logfile,"TCP Header\n");
        fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest)); // Benötigt
        //fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
        fprintf(logfile,"\n");
        fprintf(logfile,"                        DATA Dump                         ");
        fprintf(logfile,"\n");
        
        */
     
        fprintf(logfile,"Remaining Length: %d\n",remaining_length);  
        fprintf(logfile,"\n###########################################################"); 
 
     return 0;
}
 
void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
             
            fprintf(logfile,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}
