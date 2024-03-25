#include <iostream>
#include <set>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


int main(int argc, char* argv[]){
    if (argc < 2){
        std::cout << "\nError of input\n";
        return -1;
    }

    char *name = argv[1];
    std::cout << "_______" << name << "_______\n";

    //init  pcap file
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    //struct pcap_file_header
    struct pcap_pkthdr* header; /* Заголовок который нам дает PCAP */
    const u_char *packet;  /* Пакет */

    int total_packets = 0;
    int tcp_packets = 0;
    int udp_packets = 0;
    std::set<int> packet_lengths;

    fp = pcap_open_offline(name, errbuf);

    if (!fp){
        std::cout << "\nError to open the file\n";
        return -1;
    }

    const u_char* pkt_data;
    while(( packet = pcap_next_ex(fp, &header, &(pkt_data))) >= 0){
        total_packets++;
        packet_lengths.insert(header->len);

        struct ether_header *eth_header;
        eth_header = (struct ether_header *) packet;

        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct iphdr *ip_header;
            ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));

            if (ip_header->protocol == IPPROTO_TCP) {
                tcp_packets++;
            } else if (ip_header->protocol == IPPROTO_UDP) {
                udp_packets++;
            }
        }
    }

    auto minLen = packet_lengths.begin();
    auto midLen = std::next(packet_lengths.begin(), std::distance(packet_lengths.begin(), packet_lengths.end()) / 2);
    auto maxLen = packet_lengths.rbegin();

    std::cout << "Total packets: " << total_packets << std::endl;
    std::cout << "Minimum length: " << *minLen << std::endl;
    std::cout << "Middle length: " << *midLen << std::endl;
    std::cout << "Maximum length: " << *maxLen << std::endl;

    std::cout << "TCP packets: " << tcp_packets << std::endl;
    std::cout << "UDP packets: " << udp_packets << std::endl;

    pcap_close(fp);

    return 0;
}