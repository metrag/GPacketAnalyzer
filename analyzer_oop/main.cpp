#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <vector>
#include <limits>
#include <cstring>
#include <winsock2.h> //для работы ntohs - преобразование сетевого порядка байтов в порядок байтов хоста
using namespace std;

#define PCAP_FILE_HEAD 24
#define PCAP_PACK_HEAD 16
#define TCP_CODE 6 //10 б в IPV4 (39 от начала)
#define UDP_CODE 17
#define ETHERNET_HEAD_LEN 14
#define IPV4_HEAD 20
#define ICMP_CODE 20
#define ICMP6_CODE 58

/*
    обработка исключений try-catch
    перегрузка (+ для добавления пакетов)
*/

/*
    в файле 
    ipv 4 - 364
    ipv 6 - 25
    no ip - 2
*/

//общий класс пакетов
class Packet {
protected:
    int id;
    int size;
    int head_size;
    int body_size;
    char* data;

public:
    Packet(int id, int head_size = 0, int body_size = 0);
    int get_size() const;
    int get_id() const;
    virtual void decode() = 0;
    virtual void print() const = 0;
    virtual ~Packet();
};

Packet::Packet(int id, int head_size, int body_size) {
    this->id = id;   
    this->head_size = head_size;
    this->body_size = body_size;
    this->size = head_size + body_size;
    this->data = nullptr;
}

int Packet::get_size() const {
    return size;
}

int Packet::get_id() const {
    return id;
}

Packet::~Packet() {
    delete[] data;
}

//класс Ethernet
class Ethernet : public Packet {
private:
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short type;

public:
    Ethernet(int id, char* data, int size) : Packet(id, 0, size) {
        this->data = new char[size];
        memcpy(this->data, data, size);
    }

    void decode() override {
        memcpy(dst_mac, data, 6);
        memcpy(src_mac, data + 6, 6);
        type = (static_cast<unsigned char>(data[12]) << 8) | static_cast<unsigned char>(data[13]);
    }

    void print() const override {
        cout << "\n__Ethernet Header__" << endl;
        cout << "Destination MAC: ";
        for(int i = 0; i < 6; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(dst_mac[i]);
            if(i < 5) cout << ":";
        }
        cout << endl;
        
        cout << "Source MAC: ";
        for(int i = 0; i < 6; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(src_mac[i]);
            if(i < 5) cout << ":";
        }
        cout << endl;
    }
};

//класс IPv4
class IPv4 : public Packet {
private:
    unsigned char version;
    unsigned char ihl;
    unsigned char protocol;
    unsigned int src_ip;
    unsigned int dst_ip;

public:
    IPv4(int id, char* data, int size) : Packet(id, 0, size) {
        this->data = new char[size];
        memcpy(this->data, data, size);
    }

    void decode() override {
        version = (static_cast<unsigned char>(data[0]) >> 4) & 0xF;
        ihl = static_cast<unsigned char>(data[0]) & 0xF;
        protocol = static_cast<unsigned char>(data[9]);
        

        memcpy(&src_ip, data + 12, 4);
        memcpy(&dst_ip, data + 16, 4);
    }

    void print() const override {
        cout << "\n__IPv4 Header__" << endl;
        cout << "Version: " << static_cast<int>(version) << endl;
        cout << "Protocol: " << static_cast<int>(protocol) << endl;
        
        unsigned char* sip = (unsigned char*)&src_ip;
        unsigned char* dip = (unsigned char*)&dst_ip;
        
        cout << "Source IP: "
             << static_cast<int>(sip[0]) << "."
             << static_cast<int>(sip[1]) << "."
             << static_cast<int>(sip[2]) << "."
             << static_cast<int>(sip[3]) << endl;
        
        cout << "Destination IP: "
             << static_cast<int>(dip[0]) << "."
             << static_cast<int>(dip[1]) << "."
             << static_cast<int>(dip[2]) << "."
             << static_cast<int>(dip[3]) << endl;
    }
};

//класс TCP
class TCP : public Packet {
private:
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned short flags;

public:
    TCP(int id, char* data, int size) : Packet(id, 0, size) {
        this->data = new char[size];
        memcpy(this->data, data, size);
    }

    void decode() override {
        memcpy(&src_port, data, 2);
        memcpy(&dst_port, data + 2, 2);
        memcpy(&seq_num, data + 4, 4);
        memcpy(&ack_num, data + 8, 4);
        memcpy(&flags, data + 12, 2);
    }

    void print() const override {
        cout << "\nTCP Header:" << endl;
        cout << "Source Port: " << ntohs(src_port) << endl;
        cout << "Destination Port: " << ntohs(dst_port) << endl;
    }
};

//класс UDP
class UDP : public Packet {
private:
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;

public:
    UDP(int id, char* data, int size) : Packet(id, 0, size) {
        this->data = new char[size];
        memcpy(this->data, data, size);
    }

    void decode() override {
        memcpy(&src_port, data, 2);
        memcpy(&dst_port, data + 2, 2);
        memcpy(&length, data + 4, 2);
        memcpy(&checksum, data + 6, 2);
    }

    void print() const override {
        cout << "\nUDP Header:" << endl;
        cout << "Source Port: " << ntohs(src_port) << endl;
        cout << "Destination Port: " << ntohs(dst_port) << endl;
    }
};

//pcap пакет
class Pcap_Packet : public Packet {
private:
    typedef struct pcap_pkthdr {
        unsigned int ts_sec;
        unsigned int ts_usec;
        unsigned int caplen;
        unsigned int len;
    } PPK_header;
    PPK_header head;

public:
    Pcap_Packet(int id);
    void write_head(const char* buffer);
    int get_body_size();
    void write_body(char* buffer);
    void decode() override;
    void print() const override;
    bool isTCP() const;
    bool isUDP() const;
    const char* get_data() const { return data; }
};

Pcap_Packet::Pcap_Packet(int id) : Packet(id) {
    data = nullptr;
}

void Pcap_Packet::write_head(const char* buffer) {
    memcpy(&head, buffer, sizeof(head));

    head_size = PCAP_PACK_HEAD;
    body_size = head.caplen;
    size = head_size + body_size;

    data = new char[size];
    memcpy(data, &head, head_size);
}

int Pcap_Packet::get_body_size() {
    return body_size;
}

void Pcap_Packet::write_body(char* buffer) {
    memcpy(data + head_size, buffer, body_size);
}

bool Pcap_Packet::isTCP() const {
    if (data[39] == TCP_CODE)
        return true;
    else
        return false;
}

bool Pcap_Packet::isUDP() const {
    if (data[39] == UDP_CODE)
        return true;
    else
        return false;
}

void Pcap_Packet::decode() {
    
}

void Pcap_Packet::print() const {
    cout << "\n__PCAP Packet #" << id << "__" << endl;
    cout << "Capture length: " << head.caplen << endl;
    cout << "Actual length: " << head.len << endl;
    cout << "All data: ";
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0) cout << endl;
        cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)data[i] << " ";
    }
    cout << endl;
    cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)data[23] << " ";
    cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)data[39] << " ";
    cout << dec << endl;
}

class PacketSequence {
private:
    string filename;
    ifstream inputFile;
    char* buffer;
    int packetCount;
    int tcp_c;
    int udp_c;
    vector<Pcap_Packet*> seq;
    vector<int>packetLengths;

    typedef struct pcap_file_header {
        int magic;
        short version_major;
        short version_minor;
        int thiszone;
        int sigfigs;
        int snaplen;
        int linktype;
    } PF_header;
    PF_header fileHeader;

    int minPacketSize;
    int maxPacketSize;

    void print_remaining_data(const char* data, int offset, int total_size) const {
        cout << "\n__Data__";
        for (int i = offset; i < total_size; i++) {
            if ((i - offset) % 16 == 0) cout << endl;
            cout << hex << setw(2) << setfill('0') 
                 << static_cast<int>(static_cast<unsigned char>(data[i])) << " ";
        }
        cout << dec << endl;
    }

public: 
    PacketSequence(string filename);
    void print_pcap_file_head();
    void openFile();
    int get_packet_count() const;
    void print_full();
    void print_info();
    void print_by_id(int& id);
    void decode();

    PacketSequence& operator+=(Pcap_Packet* packet) {
        if (packet != nullptr) {
            seq.push_back(packet);
            packetLengths.push_back(packet->get_body_size());
            packetCount++;
        }
        return *this;
    }
};

PacketSequence::PacketSequence(string filename) { 
    this->filename = filename;
    this->packetCount = 0;
    this->tcp_c = 0;  // Инициализация локального счетчика TCP
    this->udp_c = 0;
    this->minPacketSize = 0;
    this->maxPacketSize = 0;
}

void PacketSequence::print_info() {
    cout << "\nCount of packets:  " << packetCount << endl;
    cout << "Count of IPV4 packets:  " << tcp_c+udp_c << endl;
    cout << "Count of Another packets (IPV6, no IP):  " << packetCount - (tcp_c+udp_c) << endl;
    cout << "TCP packets: " << tcp_c << endl;
    cout << "UDP packets: " << udp_c << endl;
    cout << "Min size of packets:  " << minPacketSize << endl;
    cout << "Max size of packets:  " << maxPacketSize << endl;
}

void PacketSequence::print_pcap_file_head() {
    const unsigned char* bytePtr = reinterpret_cast<const unsigned char*>(&fileHeader);
    cout << "\n__Pcap file header__" << endl;
    for (int i = 0; i < PCAP_FILE_HEAD; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytePtr[i]) << " ";
    }
    cout << dec << endl;
}

void PacketSequence::print_full() {
    cout << "__PCAP file header__" << endl;
    print_pcap_file_head();
}

void PacketSequence::print_by_id(int& id) {
    try {
        if (id < 1 || id > packetCount) {
            throw std::out_of_range("Error!");
        }
        if (id > 0 && id <= packetCount) {
            seq[id-1]->print();
            
            cout << "\n__Pcap file header__" << endl;
            auto heder = seq[id - 1]->get_data();
            int headerSize = PCAP_PACK_HEAD;
            for (int i = 0; i < headerSize; i++) {
                cout << hex << setw(2) << setfill('0') << static_cast<unsigned int>(static_cast<unsigned char>(heder[i]));
                if (i < headerSize - 1) {
                    cout << " ";
                }
            }
            cout << endl;
        
            //cоздаем и декодируем Ethernet заголовок
            Ethernet eth(id, const_cast<char*>(seq[id-1]->get_data()) + PCAP_PACK_HEAD, 14);
            eth.decode();
            eth.print();

            //cоздаем и декодируем IPv4 заголовок
            IPv4 ip(id, const_cast<char*>(seq[id-1]->get_data()) + PCAP_PACK_HEAD + 14, 20);
            ip.decode();
            ip.print();

            //выводим оставшиеся данные после IPv4 заголовка
            print_remaining_data(seq[id-1]->get_data(), 
                            PCAP_PACK_HEAD + 14 + 20,  //смещение после IPv4
                            seq[id-1]->get_size());
        } 
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
}

void PacketSequence::openFile() {
    //обработка ошибки открытия файла
    try {
        inputFile.open(filename, ios::binary);
        if (!inputFile.is_open()) {
            throw std::runtime_error("Ошибка открытия файла");
        }

        inputFile.read((char*)(&fileHeader), PCAP_FILE_HEAD);
        cout << "PCAP file header read successfully." << endl;
        
        while (true) {
            packetCount++;
            Pcap_Packet* pac = new Pcap_Packet(packetCount);

            buffer = new char[PCAP_PACK_HEAD];
            inputFile.read(buffer, PCAP_PACK_HEAD);

            if (inputFile.eof()) {
                delete[] buffer;
                delete pac;
                break;
            } else if (inputFile.fail()) {
                cout << "Failed to read header." << endl;
                delete[] buffer;
                delete pac;
                break;
            }

            pac->write_head(buffer);
            delete[] buffer;

            buffer = new char[pac->get_body_size()];
            packetLengths.push_back(pac->get_body_size());
        
            if (pac->get_body_size() <= 0) {
                cout << "Invalid body size for packet #" << packetCount << endl;
                delete[] buffer;
                delete pac;
                break;
            }

            inputFile.read(buffer, pac->get_body_size());

            if (inputFile.eof()) {
                cout << "End of files." << endl;
                delete[] buffer;
                delete pac;
                break;
            } else if (inputFile.fail()) {
                cout << "Failed to read body for packet #" << packetCount << endl;
                delete[] buffer;
                delete pac;
                break;
            }

            pac->write_body(buffer);
            delete[] buffer;

            cout << "Reading Packet #" << packetCount << " (" << pac->get_body_size() << ")..." << endl;
            
            *this += pac;
            
        }
        cout << "Finished reading packets!" << endl;
        packetCount--;
        inputFile.close();
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        exit(1);
    }
}

void PacketSequence::decode() {
    //обработка ошибки декодирования
    try{
        int min = packetLengths[0];
        int max = packetLengths[0];
        
        for (int i = 0; i < seq.size(); i++) {
            seq[i]->decode();

            //cчитаем TCP и UDP
            if (seq[i]->isTCP()) {
                tcp_c++;
            }
            if (seq[i]->isUDP()) {
                udp_c++;
            }

            //ищем минимальную и максимальную длину пакета
            if (packetLengths[i] < min) {
                min = packetLengths[i];
            }
            if (packetLengths[i] > max) {
                max = packetLengths[i];
            }
        }

        this->minPacketSize = min;
        this->maxPacketSize = max;
    } catch (const exception& e) {
        cerr << "Ошибка декодирования пакета: " << e.what() << endl;
    }
}

int PacketSequence::get_packet_count() const {
    return packetCount;
}

int main() { 
    string file = "et.pcap";
    cout << "_____________" << file << "_____________" << endl;

    PacketSequence seq(file);
    seq.openFile();
    seq.decode();

    seq.print_info();
    seq.print_pcap_file_head();

    cout << "\nEnter id of packet to decode: ";
    int id;
    cin >> id;
    seq.print_by_id(id);

    return 0;
}
