/* GCC Command Line: gcc netlimit.c -o netlimit.exe -I "C:\Program Files (x86)\WinPcap\Include" -L "C:\Program Files (x86)\WinPcap\Lib" -lwpcap -lwsock32 -Wall */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <Winsock2.h>

#define WPCAP
#define HAVE_REMOTE

#include <pcap.h>

/* Ethernet Defines */
    /* Ethernet Type in Little-Endianess*/
    #define ETHER_TYPE_DEC 0x0060
    #define ETHER_TYPE_DEC_ 0x0906
    #define ETHER_TYPE_XNS 0x0006
    #define ETHER_TYPE_IPV4 0x0008
    #define ETHER_TYPE_ARP 0x0608
    #define ETHER_TYPE_DOMAIN 0x1980
    #define ETHER_TYPE_RARP 0x3580
    #define ETHER_TYPE_APPLETALK 0x809B
    #define ETHER_TYPE_802_1Q 0x0081
    #define ETHER_TYPE_IPV6 0xDD86

/* IP Defines */
#define VERSION_IPV4            0x04
#define VERSION_STDatagramMode  0x05
#define VERSION_IPV6            0x06

    /* ToS */
        /* ToS Priority */
        #define ROUTINE                     0x0
        #define PRIORITY                    0x1
        #define IMMEDIATE                   0x2
        #define URGENT                      0x3
        #define _URGENT                     0x4
        #define CRITICAL                    0x5
        #define INTERCONNECTION_SUPERVISOR  0x6
        #define NETWORK_SUPERVISOR          0x7

        /* ToS Delay */
        #define NORMAL_DELAY    0x0
        #define LOW_DELAY       0x1

        /* ToS Debit */
        #define NORMAL_DEBIT    0x0
        #define HIGH_DEBIT      0x1

        /* ToS Fiability */
        #define NORMAL_FIABILITY    0x0
        #define HIGH_FIABILITY      0x1

        /* ToS Cost */
        #define NORMAL_COST 0x0
        #define LOW_COST    0x1

        /* ToS MBZ */
        #define MBZ 0x0

    /* Data Protocols */
    #define PROTOCOL_ICMP    0x01
    #define PROTOCOL_IGMP    0x02
    #define PROTOCOL_TCP     0x06
    #define PROTOCOL_UDP     0x11

    /* Options */
        /* Options Class */
        #define CLASS_NETWORK_SUPERVISOR 0x0
        #define CLASS_DEBUG 0x2

        /* Options Num */


typedef struct MAC_addr {
    unsigned char ether0;
    unsigned char ether1;
    unsigned char ether2;
    unsigned char ether3;
    unsigned char ether4;
    unsigned char ether5;
} MAC_addr;

typedef struct ethernet_header {
    MAC_addr dest_mac; /* Destination MAC Address */
    MAC_addr source_mac; /* Source MAC Address */
    unsigned short ether_type; /* Ethernet Data Protocol Type */
} ethernet_header;

typedef struct ethernet_extended_802_1Q {
    unsigned short priority_cfi_vlan;
    unsigned short ether_type; /* Ethernet Data Protocol Type */
} ethernet_extended_802_1Q;

typedef struct ip_addr {
    unsigned char u0;
    unsigned char u1;
    unsigned char u2;
    unsigned char u3;
} ip_addr;

typedef struct ip_header {
    unsigned char vers_IHL; /* 4 bits for IP Protocol version, 4 bits for IP Header Length. */
    unsigned char tos; /* Type of service */ 
    unsigned short total_packet_size; /* Total size of IP header + Data */
    unsigned short identification;
    unsigned short flags_fo; /* Fragmentations flags + Fragment offset */
    unsigned char ttl; /* Time to live */
    unsigned char protocol; /* Following Data Protocol */
    unsigned short checksum; /* Checksum */
    ip_addr source_ip; /* IP Source */
    ip_addr dest_ip; /* IP Dest */
    unsigned int op_pad; /* Options + Padding */
} ip_header;

typedef struct udp_header {
    unsigned short source_port; /* UDP Source Port */
    unsigned short dest_port; /* UDP Destination Port */
    unsigned short udp_size; /* UDP Packet size */
    unsigned udp_crc; /* UDP Checksum */
} udp_header;

typedef struct tcp_header {
    unsigned short source_port; /* TCP Source Port */
    unsigned short dest_port; /* TCP Destination Port */
    unsigned int seq_num; /* Sequence number */
    unsigned int ack_num; /* Acknowlegment number */
    unsigned short off_res_flags; /* Offset + 6 Reserved bits + TCP Flags */
    unsigned short tcp_window; /* TCP Window */
    unsigned short tcp_crc; /* TCP Checksum */
    unsigned short urg_ptr; /* URG Flag Pointer */
    unsigned int op_pad; /* Options + Padding */
} tcp_header;

unsigned short ushort_big_endian(unsigned short le_short);
void callback_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
    pcap_if_t *network_devices;
    pcap_if_t *iterate_devices_struct;
    int device_num = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    int interface_index = 0;
    int input_index = 0;

    pcap_t *adapter_handler;

    /* Get devices list */
    if ( pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &network_devices, errbuf) == -1 ) {
        fprintf(stderr, "Error while pcap_findalldevs_ex call: %s\n", errbuf);
        exit(-1);
    }

    /* Print devices */
    for ( iterate_devices_struct = network_devices; iterate_devices_struct != NULL; iterate_devices_struct = iterate_devices_struct->next) {
        printf("(%d) - %s", ++device_num, iterate_devices_struct->name);
        if ( iterate_devices_struct->description ) {
            printf(" (%s)\n", iterate_devices_struct->description);
        }
        else {
            printf(" (None)\n");
        }
    }

    if ( device_num == 0 ) {
        printf("\nNo devices found ! Make sure if WinPcap in installed on this computer.");
        return (-1);
    }

    printf("Select Interface (1-%d): ", device_num);
    scanf("%d", &input_index);

    /* Jump to index */
    for ( iterate_devices_struct = network_devices, interface_index = 0; interface_index < input_index-1; iterate_devices_struct = iterate_devices_struct->next, interface_index++ );

    /* Open Interface */
    if ( (adapter_handler = pcap_open(iterate_devices_struct->name,
                                        65536, /* Portion of packet to capture, 65536 is safe */
                                        PCAP_OPENFLAG_PROMISCUOUS, /* Promiscuous mode */
                                        1000, /* 1s of before Timeout */
                                        NULL,
                                        errbuf)) == NULL ) {
        fprintf(stderr, "\nUnable to open adapter. %s is not supported by WinPcap.");
        /* Free devices list */
        pcap_freealldevs(network_devices);
        return (-1);
    }

    if ( iterate_devices_struct->description ) {
        printf("Listening on %s...\n", iterate_devices_struct->description);
    }
    else {
        printf("Listening on None...\n");
    }

    /* Free devices struct allocated memory */
    pcap_freealldevs(network_devices);

    pcap_loop(adapter_handler, 0, callback_packet_handler, NULL);
    return 1;
}

unsigned short ushort_big_endian(unsigned short le_short) {
    return (le_short >> 8) | (le_short << 8);
}

void callback_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    /* Unused variable */
    (VOID)(param);

    unsigned int ip_start = 14;

    ethernet_header *ethernet = (ethernet_header *) (pkt_data);
    printf("MAC Informations:\n");
    printf("\tSource MAC Addr: %x-%x-%x-%x-%x-%x\n\tDest MAC Addr: %x-%x-%x-%x-%x-%x\n",
            ethernet->source_mac.ether0,
            ethernet->source_mac.ether1,
            ethernet->source_mac.ether2,
            ethernet->source_mac.ether3,
            ethernet->source_mac.ether4,
            ethernet->source_mac.ether5,
            ethernet->dest_mac.ether0,
            ethernet->dest_mac.ether1,
            ethernet->dest_mac.ether2,
            ethernet->dest_mac.ether3,
            ethernet->dest_mac.ether4,
            ethernet->dest_mac.ether5);

    switch ( ethernet->ether_type ) {
        case ETHER_TYPE_DEC:
            printf("\tEther Type: DEC\n");
            break;
        case ETHER_TYPE_DEC_:
            printf("\tEther Type: DEC\n");
            break;
        case ETHER_TYPE_XNS:
            printf("\tEther Type: XNS\n");
            break;
        case ETHER_TYPE_IPV4:
            printf("\tEther Type: IPV4\n");
            break;
        case ETHER_TYPE_ARP:
            printf("\tEther Type: ARP\n");
            break;
        case ETHER_TYPE_DOMAIN:
            printf("\tEther Type: Domain\n");
            break;
        case ETHER_TYPE_RARP:
            printf("\tEther Type: RARP\n");
            break;
        case ETHER_TYPE_APPLETALK:
            printf("\tEther Type: AppleTalk\n");
            break;
        case ETHER_TYPE_802_1Q: ; /* Empty statement to bypass declaration fact */
            ethernet_extended_802_1Q *ext_ethernet = (ethernet_extended_802_1Q *) (pkt_data + 14);
            unsigned char priority = ( ext_ethernet->priority_cfi_vlan & 0xE000 ) >> 13;
            unsigned char CFI = ( ext_ethernet->priority_cfi_vlan & 0x1000 ) >> 12;
            unsigned short VLAN_ID = ext_ethernet->priority_cfi_vlan & 0xFFF;
            unsigned short EtherType = ext_ethernet->ether_type;
            printf("\tEther Type: 802.1Q\n\t\tExtended Data:\n\t\t\tPriority: %d\n\t\t\tCFI: %d\n\t\t\tVLAN_ID: %d\n\t\t\tEther Type: 0x%x\n",
                    priority,
                    CFI,
                    VLAN_ID,
                    EtherType);
            ip_start = 18;
            break;
        case ETHER_TYPE_IPV6:
            printf("\tEther Type: IPV6\n");
            break;
    }


    ip_header *ip = (ip_header *) (pkt_data + ip_start);
    unsigned int ip_header_length = (ip->vers_IHL & 0xf) * 4;
    unsigned char ip_version = (ip->vers_IHL & 0xf0) >> 4;
    unsigned char packet_protocol = ip->protocol;
    unsigned short packet_total_size = ushort_big_endian(ip->total_packet_size);

    unsigned short source_port = 0;
    unsigned short dest_port = 0;

    if ( packet_protocol == PROTOCOL_TCP ) {
        tcp_header *tcp = (tcp_header *) (pkt_data + (14+ip_header_length));
        source_port = ntohs(tcp->source_port);
        dest_port = ntohs(tcp->dest_port);
    }
    else if ( packet_protocol == PROTOCOL_UDP ) {
        udp_header *udp = (udp_header *) (pkt_data + (14+ip_header_length));
        source_port = ntohs(udp->source_port);
        dest_port = ntohs(udp->dest_port);
    }

    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, packet_size=%d bytes, iph_length=%d, ", 
            ip->source_ip.u0,
            ip->source_ip.u1,
            ip->source_ip.u2,
            ip->source_ip.u3,
            source_port,
            ip->dest_ip.u0,
            ip->dest_ip.u1,
            ip->dest_ip.u2,
            ip->dest_ip.u3,
            dest_port,
            packet_total_size,
            ip_header_length);

    if ( ip_version == VERSION_IPV4 )
        printf("version=IPV4, ");
    else if ( ip_version == VERSION_IPV6 ) 
        printf("version=IPV6, ");

    if ( packet_protocol == PROTOCOL_TCP ) 
        printf("protocol=TCP\n");
    else if ( packet_protocol == PROTOCOL_UDP )
        printf("protocol=UDP\n");

    printf("\n");
}