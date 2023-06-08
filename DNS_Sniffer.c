#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>

#define SIZE_ETHERNET             14
#define IPV4_ADDRESS_TYPE         4
#define IPV6_ADDRESS_TYPE         6
#define DNS_TYPE_A                1
#define DNS_TYPE_AAAA             28


#define GET_ADDRESS_LENGTH(x) ((x == IPV4_ADDRESS_TYPE) ? sizeof(struct in_addr) : sizeof(struct in6_addr))

void processPacket(const u_char *packet);
void processDNS(const u_char *packet);
void printDomainIP(const u_char *payload, int address_type, int position);

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    // Open the network device for sniffing
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Start capturing packets
    while (1) {
        packet = pcap_next(handle, &header);
        processPacket(packet);
    }

    // Close the handle when finished
    pcap_close(handle);

    return 0;
}

void processPacket(const u_char *packet) {
    struct ip *ipHeader;
    struct udphdr *udpHeader;
    int ipHeader_Length, udpPacketSize, size_ip;

    // Get the size of the IP header
    ipHeader = (struct ip *)(packet + SIZE_ETHERNET);
    ipHeader_Length = ipHeader->ip_hl * 4;

    if (ipHeader->ip_p == IPPROTO_UDP) {
        // Get the size of the UDP header
        udpHeader = (struct udphdr *)(packet + SIZE_ETHERNET + ipHeader_Length);
        udpPacketSize = ntohs(udpHeader->len);

        // Check if it's a DNS response packet (filter by size)
        if (udpPacketSize >= 8) {
            processDNS(packet + SIZE_ETHERNET + ipHeader_Length + sizeof(struct udphdr));
        }
    }
}

void processDNS(const u_char *packet) {
    int i, j, position, questionameServersCount, answersCount, nameServersCount, additionalRecordsCount;

    // Get the number of records
    position = 4; // Skip transaction ID (2 bytes) and flags (2 bytes)
    questionameServersCount = (packet[position] << 8) + packet[position+1];

    position += 2;
    answersCount = (packet[position] << 8) + packet[position+1];

    position += 2;
    nameServersCount = (packet[position] << 8) + packet[position+1];

    position += 2;
    additionalRecordsCount = (packet[position] << 8) + packet[position+1];

    // Skip the DNS header
    position += 12;

    // Skip the query section
    for (i = 0; i < questionameServersCount; i++) {
        while (packet[position] != 0) {
            if (packet[position] >= 192) {
                position += 2;
                break;
            }
            position++;
        }
        position += 4; // Skip qtype and qclass fields
    }

    // Process answer section
    for (i = 0; i < answersCount; i++) {
        if (packet[position] >= 192) {
            position += 2;
        } else {
            j = 0;
            while (packet[position + j] != 0) {
                j += packet[position + j] + 1;
            }
            position += j + 1;

            int address_type = 0; 
            // Check address type (IPv4(A) or IPv6(AAAA))
            if (packet[position] == DNS_TYPE_A) {
                address_type = IPV4_ADDRESS_TYPE;
            } else if (packet[position] == DNS_TYPE_AAAA) {
                address_type = IPV6_ADDRESS_TYPE;
            }
            printDomainIP(packet, address_type, position + 1);
        }
    }
}


void printDomainIP(const u_char *payload, int address_type, int position) {
    char address_str[INET6_ADDRSTRLEN];
    if (address_type == IPV4_ADDRESS_TYPE) {
        struct in_addr addr;
        memcpy(&addr, &payload[position], sizeof(struct in_addr));
        strcpy(address_str, inet_ntoa(addr));
    } else if (address_type == IPV6_ADDRESS_TYPE) {
        struct in6_addr addr;
        memcpy(&addr, &payload[position], sizeof(struct in6_addr));
        inet_ntop(AF_INET6, &addr, address_str, INET6_ADDRSTRLEN);
    }
    
    // Skip the address
    position += GET_ADDRESS_LENGTH(address_type);

    // Skip the remaining fields (type, class, TTL, RDLength)
    position += 10;

    // Get the length of the domain name
    int domain_length = payload[position++];

    // Extract the domain name
    char domain[256];
    strncpy(domain, (char *)(&payload[position]), domain_length);
    domain[domain_length] = '\0';
    
    printf("Domain: %s, ", domain);
    printf("IP: %s\n", address_str);
    printf("\n");
}