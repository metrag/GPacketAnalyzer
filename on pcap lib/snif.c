#include <stdio.h>
#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

// #include <net/ethernet.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <arpa/inet.h>
// #include <sys/time.h>


char errbuf[PCAP_ERRBUF_SIZE];
uint8_t eth_src[ETH_ALEN];
uint8_t eth_dst[ETH_ALEN];
char ip4_src[INET_ADDRSTRLEN];
char ip4_dst[INET_ADDRSTRLEN];
int src_port;
int dst_port;
int priority;
//FILE *fp;

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet);

int main(int argc, char* argv[])
{
    char ch;
    int i, ret;


    if (argc < 2){
		printf("\nError of input\n");
		return -1;
	}

	char *fname = argv[1];
    //fp = fopen("trace.txt", "w");

    pcap_t *p;  
    p = pcap_open_offline(fname, errbuf);
    if(p == NULL) {
        printf("Unable to open pcap file!\n");
        return 1;
    }       

    if(pcap_loop(p, 10, callback, NULL) < 0) {
        printf("pcap_loop() failed!\n");
        return 1; 
    }
    printf("Capture %d packets.\n", priority);
    return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    priority++; 
    const struct ether_header *ethernet;
    const struct ip *ip;
    const struct tcphdr *tcp;
    const char *payload;
    //uint32_t usec = h->caplen;
    //uint32_t len = h->len;
    //printf("%u %u\n", usec, len);

    //printf("%lu %lu %lu\n", sizeof(struct ether_header), sizeof(struct ip), sizeof(struct tcphdr));
    ethernet = (struct ether_header *)packet;

    unsigned short ethernet_type = ntohs(ethernet->ether_type);

    /* Extract IP information. */
    ip = (struct ip*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip->ip_src), ip4_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), ip4_dst, INET_ADDRSTRLEN);

    /* Extract TCP information. */ 
    tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);

    payload = (unsigned char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));  
    printf("%hu %s %s %d %d %s\n", ethernet_type, ip4_src, ip4_dst, src_port, dst_port, payload);
}
