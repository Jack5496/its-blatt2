#ifndef TCP_PAYLOAD_H
#define TCP_PAYLOAD_H

#include <linux/ip.h>
#include <linux/tcp.h>

char* get_tcp_payload(char * buffer, struct iphdr** iph, struct tcphdr** tcph){
        struct iphdr* ip = (struct iphdr*) buffer;
        struct tcphdr* tcp =( struct tcphdr*) (buffer + (ip->ihl*4));
        int header_len = 4*(tcp->doff + ip->ihl);
        if(iph!=NULL) *iph=ip;
        if(iph!=NULL) *tcph=tcp;
        return buffer + header_len;
}
#endif
