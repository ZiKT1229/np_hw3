#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
 
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Please input pcap file name");
        return 0;
    }
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(argv[1], errbuff);
    struct pcap_pkthdr *header;
 
    const u_char *data;
 
    u_int packetCount = 0;
    int returnValue;
    while (returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        printf("Packet # %i\n", ++packetCount);
        printf("Packet size: %d bytes\n", header->len);
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
        printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        struct ip *ip;
        struct tcphdr *tcp;
        ip = (struct ip*)(data+sizeof(struct ether_header));
        tcp = (struct tcphdr*)(data+sizeof(struct ether_header)+sizeof(struct ip));
        char* src = inet_ntoa(ip->ip_src);
        char* dst = inet_ntoa(ip->ip_dst);
        printf("src %s:%d\n",src,ntohs(tcp->source));
        printf("des %s:%d\n", dst, ntohs(tcp->dest));
        /*for (u_int i=0; (i < header->caplen ) ; i++)
        {
            if ( (i % 16) == 0) printf("\n");

            printf("%.2x ", data[i]);
        }*/

        printf("\n\n");
    }
    return 0;
}