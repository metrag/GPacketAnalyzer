#include <stdio.h>
#include <stdlib.h>

//сдвиг внутри Ethernet кадра (преамбула и ip заголовок)
#define PREAMBL 34 //14+20

#define TCP_CODE 6
#define UDP_CODE 17

//структыры данных
typedef struct pcap_file_header{
	int magic;
	short older_version;
	short young_version;
	int time_zone;
	int accuracy;
	int length_leash;
	int channel_type;
} PF_header;

typedef struct timeval {
  long tv_sec;
  long tv_usec;
} TVal;

typedef struct pcap_pkthdr {
	TVal ts;	
	int caplen;	
	int len;
} PPK_header;

typedef struct Ether_Header {
	char mac_dest[6];
	char mac_source[6];	
	short type;
} ETH_header;

typedef struct IP_Header {
	//пропускаем ненужную информацию, смотрим только на тип протокола
	char anotherInform[9];
	char protocol;
	char endInform[10];
} IP_header;

//для отладки вывод данных
void info_PCAP_header(PF_header* PFH){
	printf("%d\n",sizeof(PFH));
	printf("magic - %d\n",PFH->magic);
	printf("older_version - %d\n",PFH->older_version);
	printf("young_version - %d\n",PFH->young_version);
	printf("time_zone - %d\n",PFH->time_zone);
	printf("accuracy - %d\n",PFH->accuracy);
	printf("length_leash - %d\n",PFH->length_leash);
	printf("channel_type - %d\n",PFH->channel_type);
}

void info_PCAP_pkthdr(PPK_header* PPK){
	// printf("v_sec - %d\n",PPK->ts.tv_sec);
	// printf("tv_usec - %d\n",PPK->ts.tv_usec);
	printf("caplen - %d\n",PPK->caplen);
	// printf("len - %d\n",PPK->len);
}

void info_Ether_Header(ETH_header* ETHP){
	//printf("%d\n",sizeof(ETHP));
	// printf("mac_dest - ");
	// for (size_t i = 0; i < 6; i++)
	// 	printf("%d",ETHP->mac_dest[i]);

	// printf("\nmac_source - ");
	// for (size_t i = 0; i < 6; i++)
	// 	printf("%d",ETHP->mac_source[i]);

	printf("type - %d\n",ETHP->type);
}

void info_IP_Header(IP_header* IPH){
	//printf("%d\n",sizeof(IPH));
	// printf("%d\n",sizeof(IPH));
	// printf("ver - %d\n",IPH->ver);
	// printf("IHL - %d\n",IPH->IHL);
	printf("protocol - %d\n",IPH->protocol);
}

void  print_data(char* data, int l){
	for (size_t i = 0; i < l; i++){
		printf("%d",data[i]);

		if (i%10 == 0 && i != 0){
			printf("\n");
		}
	}
	printf("\n");
}

int main(int argc, char* argv[]){

	//обработака параметра - нужный файл
	if (argc < 2){
		printf("Error of input\n");
        return -1;
	}

	char *name = argv[1];

	printf("_____________%s_____________\n",name);

	//открытие файла на чтение в бинарном виде
	FILE* file = fopen(name, "rb");

	//инициализация необходимых структур
	PF_header header;
	PPK_header pck_headr;
	ETH_header eth_pack;
	IP_header ip_header;

	//чтение pcap заголовка
	fread(&header, sizeof(header), 1, file);

	//обработка, если файл пустой
	if(feof(file)){
		printf("File is empty");
		return -1;
	}

	char* data;
	int len_data = 0;

	//счётчики
	int pcount = 0;
	int udp_packets = 0;
	int tcp_packets = 0;

	int minLen = -1;
	long sum_len_packets = 0;
	int maxLen = -1;

	//while (!feof(file)){
	for(int i = 0; i < 10000; i++){
		++pcount;
		//printf("#%d\n",pcount);

		//чтение заголовков и пакетов
		fread(&pck_headr, sizeof(pck_headr), 1, file);
		info_PCAP_pkthdr(&pck_headr);

		fread(&eth_pack, sizeof(eth_pack), 1, file);
		info_Ether_Header(&eth_pack);

		fread(&ip_header, sizeof(ip_header), 1, file);
		info_IP_Header(&ip_header);

		//подсчёт суммы для средней величины
		sum_len_packets += pck_headr.caplen;

		//подсчёт типо протоколов (см. документацию)
		if (ip_header.protocol == TCP_CODE){
			++tcp_packets;
		} else if (ip_header.protocol = UDP_CODE){
			++udp_packets;
		}

		//вычисление максимальной и минимальной длины пакета
		if (pck_headr.caplen < minLen || minLen == -1) {
        	minLen = pck_headr.caplen;
   		}

    	if (pck_headr.caplen > maxLen) {
        	maxLen = pck_headr.caplen;
    	}


		//чтение данных
		len_data = pck_headr.caplen - PREAMBL;
		data = (char*)malloc(len_data * sizeof(char));
		fread(data, len_data, sizeof(data[0]), file);
		//print_data(data, l);
		printf("\n");

		//освободение памяти
		free(data);
		data = NULL;
	}
	//закрытие чтения файла
	fclose(file);

	//среднее значение	
	int midLen = sum_len_packets/(float)pcount;

	//вывод информации
	printf("Total packets: %d\n",pcount);
	printf("TCP packets: %d\n", tcp_packets);
    printf("UDP packets: %d\n", udp_packets);

    printf("Minimum length: %d\n", minLen);
	printf("Middle lengh: %d\n", midLen);
    printf("Maximum length: %d\n", maxLen);

	printf("\n\n");
	system("pause");
	return 0;
}