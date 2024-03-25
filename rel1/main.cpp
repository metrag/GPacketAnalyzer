#include <iostream>
#include <set>

#include <pcap.h>

#define SIZE 100
#define LINE_LEN 16

/*
	gcc main.c -o main -lpcap
    g++ main.cpp -o main -lpcap
*/

int main(int argc, char* argv[]){
    //choose file
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
    struct pcap_pkthdr* header;
    const u_char *packet;
	const u_char *pkt_data;
    int res;

  
	fp = pcap_open_offline(name,errbuf);

	if (!fp)
	{
		std::cout << "\nError to open the file\n";
		return -1;
	}

    //counting the number of packages
	int pcount = 0;
    std::set<int> packetsLens; 
	
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		++pcount;
		packetsLens.insert(header->len);
	}
    
    //counting the len of packages
    auto minLen = packetsLens.begin();
    auto midLen = packetsLens.begin();
    std::advance(midLen,std::distance(packetsLens.begin(),packetsLens.end())/2);
	auto maxLen = packetsLens.rbegin();


	std::cout << "Count of packets: "<< pcount << std::endl;
	std::cout << "Min len of packet: " << *minLen << std::endl;
    std::cout << "Mid len of packet: " << *midLen << std::endl;
	std::cout << "Max len of packet: " << *maxLen << std::endl;

	if (*packet == -1)
	{
		std::cout << "Error reading the packets: " << pcap_geterr(fp) << std::endl;
	}

	pcap_close(fp);

	return 0;
}
