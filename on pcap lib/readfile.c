#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#define SIZE 100
#define LINE_LEN 16

/*
	gcc main.c -o main -lpcap
*/

int main(int argc, char* argv[]){
	if (argc < 2){
		printf("\nError of input\n");
		return -1;
	}

	char *name = argv[1];
	printf("%s\n",name);

	pcap_t *fp;   /* Дескриптор сессии */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Строка для хранения ошибки */

    struct pcap_pkthdr* header; /* Заголовок который нам дает PCAP */
    const u_char *packet;  /* Пакет */
	const u_char *pkt_data;
	u_int i=0;
	int res;

	//open the capture file
	fp = pcap_open_offline(name,errbuf);

	if (!fp)
	{
		printf("\nError to open the file %s.\n", name);
		return -1;
	}

	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
		
		/* Print the packet */
		for (i=1; (i < header->caplen + 1 ) ; i++)
		{
			printf("%.2x ", pkt_data[i-1]);
			if ( (i % LINE_LEN) == 0) printf("\n");
		}
		
		printf("\n\n");		
	}
	
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}

	pcap_close(fp);

	printf("\n\n");
	system("pause");
	return 0;
}