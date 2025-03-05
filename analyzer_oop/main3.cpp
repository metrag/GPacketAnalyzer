#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <vector>
#include <limits>
#include <cstring>
#include <windows.h> // для правильного вывода
#include <winsock2.h> // для работы ntohs - преобразование сетевого порядка байтов в порядок байтов хоста

using namespace std;

#define PCAP_HEADER_SIZE 24
#define PCAP_PACKET_HEADER_SIZE 16
#define TCP_PROTOCOL_CODE 6 // 10 байт в IPV4 (39 от начала)
#define UDP_PROTOCOL_CODE 17
#define ETHERNET_HEADER_SIZE 14
#define IPV4_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 20
#define ICMP6_HEADER_SIZE 58

class NetworkPacket {
protected:
    int packetId;
    int totalSize;
    int headerSize;
    int payloadSize;
    char* payloadData;

public:
    NetworkPacket(int id, int headerSize = 0, int payloadSize = 0) {
        this->packetId = id;   
        this->headerSize = headerSize;
        this->payloadSize = payloadSize;
        this->totalSize = headerSize + payloadSize;
        this->payloadData = nullptr;
    }

    int getTotalSize() const {
        return totalSize;
    }

    int getPacketId() const {
        return packetId;
    }

    virtual void decode() = 0;
    virtual void display() const = 0;
    
    virtual ~NetworkPacket() {
        delete[] payloadData;
    }
};

class EthernetFrame : public NetworkPacket {
private:
    unsigned char destinationMac[6];
    unsigned char sourceMac[6];
    unsigned short etherType;

public:
    EthernetFrame(int id, char* data, int size) : NetworkPacket(id, 0, size) {
        this->payloadData = new char[size];
        memcpy(this->payloadData, data, size);
    }

    void decode() override {
        memcpy(destinationMac, payloadData, 6);
        memcpy(sourceMac, payloadData + 6, 6);
        etherType = (static_cast<unsigned char>(payloadData[12]) << 8) | static_cast<unsigned char>(payloadData[13]);
    }

    void display() const override {
        cout << "MAC отправителя: ";
        for (int i = 0; i < 6; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(sourceMac[i]);
            if (i < 5) cout << ":";
        }
        cout << endl;
        
        cout << "MAC получателя: ";
        for (int i = 0; i < 6; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(destinationMac[i]);
            if (i < 5) cout << ":";
        }
        cout << endl;
    }
};

class IPv4Packet : public NetworkPacket {
private:
    unsigned char version;
    unsigned char headerLength;
    unsigned char protocol;
    unsigned int sourceIp;
    unsigned int destinationIp;

public:
    IPv4Packet(int id, char* data, int size) : NetworkPacket(id, 0, size) {
        this->payloadData = new char[size];
        memcpy(this->payloadData, data, size);
    }

    void decode() override {
        version = (static_cast<unsigned char>(payloadData[0]) >> 4) & 0xF;
        headerLength = static_cast<unsigned char>(payloadData[0]) & 0xF;
        protocol = static_cast<unsigned char>(payloadData[9]);
        
        memcpy(&sourceIp, payloadData + 12, 4);
        memcpy(&destinationIp, payloadData + 16, 4);
    }

    void display() const override {
        cout << "Версия: " << static_cast<int>(version) << endl;
        cout << "Протокол: " << static_cast<int>(protocol) << endl;
        
        unsigned char* sip = (unsigned char*)&sourceIp;
        unsigned char* dip = (unsigned char*)&destinationIp;
        
        cout << "IP отправителя: "
             << static_cast<int>(sip[0]) << "."
             << static_cast<int>(sip[1]) << "."
             << static_cast<int>(sip[2]) << "."
             << static_cast<int>(sip[3]) << endl;
        
        cout << "IP получателя: "
             << static_cast<int>(dip[0]) << "."
             << static_cast<int>(dip[1]) << "."
             << static_cast<int>(dip[2]) << "."
             << static_cast<int>(dip[3]) << endl;
    }
};

// Класс TCP
class TCPPacket : public NetworkPacket {
private:
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned int sequenceNumber;
    unsigned int acknowledgmentNumber;
    unsigned short flags;

public:
    TCPPacket(int id, char* data, int size) : NetworkPacket(id, 0, size) {
        this->payloadData = new char[size];
        memcpy(this->payloadData, data, size);
    }

    void decode() override {
        memcpy(&sourcePort, payloadData, 2);
        memcpy(&destinationPort, payloadData + 2, 2);
        memcpy(&sequenceNumber, payloadData + 4, 4);
        memcpy(&acknowledgmentNumber, payloadData + 8, 4);
        memcpy(&flags, payloadData + 12, 2);
    }

    void display() const override {
        cout << "Порт отправителя: " << ntohs(sourcePort) << endl;
        cout << "Порт получателя: " << ntohs(destinationPort) << endl;
    }
};

class UDPPacket : public NetworkPacket {
private:
    unsigned short sourcePort;
    unsigned short destinationPort;
    unsigned short length;
    unsigned short checksum;

public:
    UDPPacket(int id, char* data, int size) : NetworkPacket(id, 0, size) {
        this->payloadData = new char[size];
        memcpy(this->payloadData, data, size);
    }

    void decode() override {
        memcpy(&sourcePort, payloadData, 2);
        memcpy(&destinationPort, payloadData + 2, 2);
        memcpy(&length, payloadData + 4, 2);
        memcpy(&checksum, payloadData + 6, 2);
    }

    void display() const override {
        cout << "Порт отправителя: " << ntohs(sourcePort) << endl;
        cout << "Порт получателя: " << ntohs(destinationPort) << endl;
    }
};

class PcapPacket : public NetworkPacket {
private:
    struct PcapHeader {
        unsigned int timestampSec;
        unsigned int timestampUsec;
        unsigned int capturedLength;
        unsigned int originalLength;
    } pcapHeader;

    char* payloadData;
    size_t headerSize;
    size_t payloadSize;
    size_t totalSize;

public:
    PcapPacket(int id) : NetworkPacket(id), payloadData(nullptr), headerSize(0), payloadSize(0), totalSize(0) {}

    // Деструктор для освобождения памяти
    ~PcapPacket() {
        delete[] payloadData;
    }

    void writeHeader(const char* buffer) {
        memcpy(&pcapHeader, buffer, sizeof(pcapHeader));

        headerSize = PCAP_PACKET_HEADER_SIZE;
        payloadSize = pcapHeader.capturedLength;
        totalSize = headerSize + payloadSize;

        payloadData = new char[totalSize];
        memcpy(payloadData, &pcapHeader, headerSize);
    }

    int getPayloadSize() const {
        return payloadSize;
    }

    void writeBody(const char* buffer) {
        if (payloadData) {
            memcpy(payloadData + headerSize, buffer, payloadSize);
        }
    }

    void decode() override {

    }

    void display() const override;

    bool isTCP() const {
        return payloadData && payloadData[39] == TCP_PROTOCOL_CODE;
    }

    bool isUDP() const {
        return payloadData && payloadData[39] == UDP_PROTOCOL_CODE;
    }

    const char* getPayloadData() const { return payloadData; }
};

void PcapPacket::display() const {
    cout << "Захваченный размер: " << pcapHeader.capturedLength << endl;
    cout << "Данные: ";
    for (int i = 0; i < totalSize; i++) {
        if (i % 16 == 0) cout << endl;
        cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)payloadData[i] << " ";
    }
    cout << endl;
    cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)payloadData[23] << " ";
    cout << hex << setw(2) << setfill('0') << (unsigned int)(unsigned char)payloadData[39] << " ";
    cout << dec << endl;
}

class PacketCollection {
private:
    string fileName;
    ifstream inputFile;
    char* buffer;
    int totalPackets;
    int tcpCount;
    int udpCount;
    vector<PcapPacket*> packets;
    vector<int> packetSizes;

    struct PcapFileHeader {
        int magic;
        short versionMajor;
        short versionMinor;
        int timezone;
        int sigfigs;
        int snaplen;
        int linktype;
    } fileHeader;

    int minPacketSize;
    int maxPacketSize;

    void printRemainingData(const char* data, int offset, int totalSize) const {
        for (int i = offset; i < totalSize; i++) {
            if ((i - offset) % 16 == 0) cout << endl;
            cout << hex << setw(2) << setfill('0') 
                 << static_cast<int>(static_cast<unsigned char>(data[i])) << " ";
        }
        cout << dec << endl;
    }

public: 
    PacketCollection(string filename);
    void printPcapFileHeader();
    void openFile();
    int getPacketCount() const;
    void printFull();
    void printInfo();
    void printById(int& id);
    void decode();

    // Перегрузка оператора +=
    PacketCollection& operator+=(PcapPacket* packet) {
        if (packet != nullptr) {
            packets.push_back(packet);
            packetSizes.push_back(packet->getPayloadSize());
            totalPackets++;
        }
        return *this;
    }
};

PacketCollection::PacketCollection(string filename) { 
    this->fileName = filename;
    this->totalPackets = 0;
    this->tcpCount = 0;  
    this->udpCount = 0;
    this->minPacketSize = 0;
    this->maxPacketSize = 0;
}

void PacketCollection::printInfo() {
    cout << "\nКоличество пакетов:  " << totalPackets << endl;
    cout << "IPV4 пакеты:  " << tcpCount + udpCount << endl;
    cout << "Другие виды пакетов (IPV6 и др.):  " << totalPackets - (tcpCount + udpCount) << endl;
    cout << "TCP пакеты: " << tcpCount << endl;
    cout << "UDP пакеты: " << udpCount << endl;
    cout << "Минимальный размер:  " << minPacketSize << endl;
    cout << "Максимальный размер:  " << maxPacketSize << endl;
}

void PacketCollection::printPcapFileHeader() {
    const unsigned char* bytePtr = reinterpret_cast<const unsigned char*>(&fileHeader);
    for (int i = 0; i < PCAP_HEADER_SIZE; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(bytePtr[i]) << " ";
    }
    cout << dec << endl;
}

void PacketCollection::printFull() {
    printPcapFileHeader();
}

void PacketCollection::printById(int& id) {
    try {
        if (id < 1 || id > totalPackets) {
            throw std::out_of_range("Неверный идентификатор пакета");
        }
        if (id > 0 && id <= totalPackets) {
            packets[id - 1]->display();
        
            const char* headerData = packets[id - 1]->getPayloadData();
            int headerSize = PCAP_PACKET_HEADER_SIZE;
            for (int i = 0; i < headerSize; i++) {
                cout << hex << setw(2) << setfill('0') << static_cast<unsigned int>(static_cast<unsigned char>(headerData[i]));
                if (i < headerSize - 1) {
                    cout << " ";
                }
            }
            cout << endl;
        
            // Создаем и декодируем Ethernet заголовок
            EthernetFrame eth(id, const_cast<char*>(packets[id - 1]->getPayloadData()) + PCAP_PACKET_HEADER_SIZE, 14);
            eth.decode();
            eth.display();

            // Создаем и декодируем IPv4 заголовок
            IPv4Packet ip(id, const_cast<char*>(packets[id - 1]->getPayloadData()) + PCAP_PACKET_HEADER_SIZE + 14, 20);
            ip.decode();
            ip.display();

            // Выводим оставшиеся данные после IPv4 заголовка
            printRemainingData(packets[id - 1]->getPayloadData(), 
                            PCAP_PACKET_HEADER_SIZE + 14 + 20,  // Смещение после IPv4
                            packets[id - 1]->getTotalSize());
        } 
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
}

void PacketCollection::openFile() {
    // Обработка ошибки открытия файла
    try {
        inputFile.open(fileName, ios::binary);
        if (!inputFile.is_open()) {
            throw std::runtime_error("Ошибка открытия файла");
        }

        inputFile.read(reinterpret_cast<char*>(&fileHeader), PCAP_HEADER_SIZE);
        cout << "PCAP файл прочитан успешно." << endl;

        while (true) {
            PcapPacket* packet = new PcapPacket(); // Создаем новый пакет
            inputFile.read(reinterpret_cast<char*>(&packet->header), PCAP_PACKET_HEADER_SIZE);
            if (inputFile.eof()) {
                delete packet; // Освобождаем память, если достигнут конец файла
                break; // Достигнут конец файла
            }
            packet->setPayloadSize(packet->header.len);
            packet->setPayloadData(new char[packet->header.len]);
            inputFile.read(packet->getPayloadData(), packet->header.len);
            *this += packet; // Добавляем пакет в коллекцию
        }
        inputFile.close();
    } catch (const std::exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
}

int PacketCollection::getPacketCount() const {
    return totalPackets;
}

void PacketCollection::decode() {
    for (int i = 0; i < totalPackets; i++) {
        // Декодируем каждый пакет
        packets[i]->decode();
    }
}

// Основная функция
int main() {
    string fileName;
    cout << "Введите имя файла PCAP: ";
    cin >> fileName;

    PacketCollection packetCollection(fileName);
    packetCollection.openFile();
    packetCollection.decode();
    packetCollection.printInfo();

    int packetId;
    cout << "Введите идентификатор пакета для просмотра: ";
    cin >> packetId;
    packetCollection.printById(packetId);

    return 0;
}