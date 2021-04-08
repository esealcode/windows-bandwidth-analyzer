/* GCC Command Line: gcc bandwidth.c -o bandwidth.exe -I "C:\Program Files (x86)\WinPcap\Include" -L "C:\Program Files (x86)\WinPcap\Lib" -lwpcap -lwsock32 -lpsapi -Wall */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define WPCAP
#define HAVE_REMOTE

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <Psapi.h>
#include <Iphlpapi.h>
#include <Winsock2.h>
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

typedef struct ip_header {
    unsigned char vers_IHL; /* 4 bits for IP Protocol version, 4 bits for IP Header Length. */
    unsigned char tos; /* Type of service */ 
    unsigned short total_packet_size; /* Total size of IP header + Data */
    unsigned short identification;
    unsigned short flags_fo; /* Fragmentations flags + Fragment offset */
    unsigned char ttl; /* Time to live */
    unsigned char protocol; /* Following Data Protocol */
    unsigned short checksum; /* Checksum */
    unsigned int source_ip; /* IP Source */
    unsigned int dest_ip; /* IP Dest */
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

typedef struct connectionEntry connectionEntry;
struct connectionEntry {
    unsigned char protocol;
    unsigned int source_addr;
    unsigned short source_port;
    unsigned int dest_addr;
    unsigned short dest_port;
    unsigned int amountData;
    connectionEntry *next;
};

typedef struct Connections Connections;
struct Connections {
    unsigned int dwEntriesCount;
    connectionEntry* first;
};

int set_application_privileges();
unsigned short ushort_big_endian(unsigned short le_short);
void callback_packet_handler( u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data );
Connections *init_connections();
void add_connectionEntry( Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port, unsigned int amountData );
int update_connectionEntry( Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port, unsigned int newAmountData );
connectionEntry *match_connectionEntry( Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port );
void clear_connections_storage(Connections *connections);
void get_triggered_connectionEntries(Connections *connections, unsigned int bandwidth_cap);
int list_connectionEntries( Connections *connections );
int get_process_name(int dwProcessId, char *imageFileName);
int get_pid_by_connection(MIB_UDPTABLE_OWNER_PID *extUdpTable, MIB_TCPTABLE_OWNER_PID *extTcpTable, unsigned char PROTOCOL, unsigned int source_addr, unsigned short source_port);

DWORD ( WINAPI *pGetExtendedTcpTable)(
                PVOID pTcpTable,
                PDWORD pdwSize,
                BOOL bOrder,
                ULONG ulAf,
                TCP_TABLE_CLASS TableClass,
                ULONG Reserved
                );

DWORD ( WINAPI *pGetExtendedUdpTable)(
                PVOID pUdpTable,
                PDWORD pdwSize,
                BOOL bOrder,
                ULONG ulAf,
                UDP_TABLE_CLASS TableClass,
                ULONG Reserved
                );

int main(int argc, char *argv[]) {
    if ( argc != 2 ) {
        printf("Usage: bandwidth.exe <bandwidth_cap>\nNote: Bandwidth cap need to be in Kbps representation.");
        exit(-1);
    }

    char *e;
    unsigned int bandwidth_cap;
    bandwidth_cap = strtol(argv[1], &e, 10);
    printf("Bandwidth cap: %d\n", bandwidth_cap);

    set_application_privileges();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        return 255;
    }

    char localhost[128];
    unsigned int local_addresses[128] = {0};
    if ( gethostname(localhost, sizeof(localhost)) == SOCKET_ERROR ) {
        printf("Unable to get hostname. %d\n", WSAGetLastError());
        exit(-1);
    }

    struct hostent *struct_localhost = gethostbyname(localhost);
    if ( struct_localhost == NULL ) {
        printf("Unable to get hostent structure. %d\n", WSAGetLastError());
        exit(-1);
    }

    printf("Local Addresses: %s\n", struct_localhost->h_name);

    int i;
    for ( i=0 ; struct_localhost->h_addr_list[i] != 0; i++ ) {
        struct in_addr addr;
        memcpy(&addr, struct_localhost->h_addr_list[i], sizeof(struct in_addr));
        printf("0x%lx\n", addr.S_un.S_addr);
        local_addresses[i] = addr.S_un.S_addr;
    }

    WSACleanup();

    HMODULE dll_iphlpapi = LoadLibrary("iphlpapi.dll");
    pGetExtendedTcpTable = (DWORD (WINAPI *)(PVOID,PDWORD,BOOL,ULONG,TCP_TABLE_CLASS,ULONG)) GetProcAddress(dll_iphlpapi, "GetExtendedTcpTable");
    pGetExtendedUdpTable = (DWORD (WINAPI *)(PVOID,PDWORD,BOOL,ULONG,UDP_TABLE_CLASS,ULONG)) GetProcAddress(dll_iphlpapi, "GetExtendedUdpTable");
    CloseHandle(dll_iphlpapi);

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

    Connections *connections_struct = init_connections();

    /*
    add_connectionEntry(connections_struct, PROTOCOL_TCP, 0x0100A8C0, 16300, 0x0F331E50, 80, 300); /* source_addr = 192.168.0.1, source_port = 16300, dest_addr = 80.30.51.15, dest_port = 80 
    add_connectionEntry(connections_struct, PROTOCOL_UDP, 0x0F331E50, 8000, 0x0100A8C0, 16300, 5500); /* source_addr = 80.30.51.15, source_port = 80, dest_addr = 192.168.0.1, dest_port = 16300
    add_connectionEntry(connections_struct, PROTOCOL_TCP, 0x32140A0A, 443, 0x322D1546, 8000, 58301); /* source_addr = 10.10.20.50, source_port = 443, dest_addr = 70.21.45.50, dest_port = 8000 
    if ( update_connectionEntry(connections_struct, PROTOCOL_TCP, 0x0100A8C0, 16301, 0x0F331E50, 80, 1000) == -1 ) printf("Unable to update connection, probably unexisting.\n");
    if ( update_connectionEntry(connections_struct, PROTOCOL_TCP, 0x0100A8C0, 16300, 0x0F331E50, 80, 1000) == -1 ) printf("Unable to update connection, probably unexisting.\n");

    connectionEntry *matchedEntry = match_connectionEntry(connections_struct, PROTOCOL_TCP, 0x0100A8C0, 16300, 0x0F331E50, 80);
    if ( matchedEntry != NULL ) {
        printf("Entry matched amountData: %d bytes.\n", matchedEntry->amountData);
    }
    else printf("No connectionEntry matched !\n");
    */

    connectionEntry *matchedEntry;

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    unsigned char pkt_status;

    time_t unix_timestamp_ref = time(NULL);
    time_t current_unix_timestamp = 0;

    while ( ( pkt_status = pcap_next_ex(adapter_handler, &header, &pkt_data) ) >= 0 ) {

        current_unix_timestamp = time(NULL);
        if ( current_unix_timestamp - unix_timestamp_ref >= 10 ) {
            unix_timestamp_ref = current_unix_timestamp;
            printf("dwEntriesCount: %d\n", connections_struct->dwEntriesCount);
            //list_connectionEntries(connections_struct);
            get_triggered_connectionEntries(connections_struct, bandwidth_cap);
            clear_connections_storage(connections_struct);
        }

        if ( pkt_status == 0 ) continue; /* Timeout elapsed */
        unsigned int ip_start = 14;

        ethernet_header *ethernet = (ethernet_header *) (pkt_data);
        if ( ethernet->ether_type == ETHER_TYPE_802_1Q )
            ip_start = 18;

        ip_header *ip = (ip_header *) (pkt_data + ip_start);
        unsigned int ip_version = (ip->vers_IHL & 0xf0) >> 4;
        unsigned int ip_header_length = (ip->vers_IHL & 0xf) * 4;
        unsigned char packet_protocol = ip->protocol;
        unsigned short packet_total_size = ushort_big_endian(ip->total_packet_size);

        unsigned short source_port = 0;
        unsigned short dest_port = 0;

        if ( ip_version == VERSION_IPV4 ) {
            if ( packet_protocol == PROTOCOL_TCP ) {
                tcp_header *tcp = (tcp_header *) (pkt_data + (14+ip_header_length));
                source_port = ntohs(tcp->source_port);
                dest_port = ntohs(tcp->dest_port);
                /*printf("[TCP] Couple: %d.%d.%d.%d:%d , for packet size of %d bytes\n", 
                        ( ip->source_ip & 0x000000FF ),
                        ( ip->source_ip & 0x0000FF00 ) >> 8,
                        ( ip->source_ip & 0x00FF0000 ) >> 16,
                        ( ip->source_ip & 0xFF000000 ) >> 24,
                        source_port,
                        packet_total_size);*/
            }
            else if ( packet_protocol == PROTOCOL_UDP ) {
                udp_header *udp = (udp_header *) (pkt_data + (14+ip_header_length));
                source_port = ntohs(udp->source_port);
                dest_port = ntohs(udp->dest_port);
                /*printf("[UDP] Couple: %d.%d.%d.%d:%d , for packet size of %d bytes\n", 
                        ( ip->source_ip & 0x000000FF ),
                        ( ip->source_ip & 0x0000FF00 ) >> 8,
                        ( ip->source_ip & 0x00FF0000 ) >> 16,
                        ( ip->source_ip & 0xFF000000 ) >> 24,
                        source_port,
                        packet_total_size);*/
            }

            matchedEntry = match_connectionEntry(connections_struct, packet_protocol, ip->source_ip, source_port, ip->dest_ip, dest_port);
            if ( matchedEntry == NULL ) {
                /* New connection */
                add_connectionEntry(connections_struct, packet_protocol, ip->source_ip, source_port, ip->dest_ip, dest_port, packet_total_size);
            }
            else {
                if ( update_connectionEntry(connections_struct, packet_protocol, ip->source_ip, source_port, ip->dest_ip, dest_port, packet_total_size) == -1 ) {
                    printf("Unable to update connection.\n");
                }
            }
        }

    }

    clear_connections_storage(connections_struct);
    free(connections_struct);

    return 1;
}

int set_application_privileges() {
    // Privilege elevation
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tokenPriv;
    LUID luidDebug;
    int dwAdjust;
    int getLastError;

    if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken ) != 0 ) {
        if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luidDebug ) != 0 ) {
            printf("Setting privileges...\n");
            tokenPriv.PrivilegeCount = 1;
            tokenPriv.Privileges[0].Luid = luidDebug;
            tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            dwAdjust = AdjustTokenPrivileges( hToken, FALSE, &tokenPriv, 0, NULL, NULL);
            if ( dwAdjust != 0 ) {
                getLastError = GetLastError();
                if ( getLastError == ERROR_SUCCESS ) {
                    printf("Privileges set !\n");
                    return 1;
                }
                else if ( getLastError == ERROR_NOT_ALL_ASSIGNED ) {
                    printf("Privileges not all set !\n");
                    return (-1);
                }
            }
        }
    }
    return (-1);
}

unsigned short ushort_big_endian(unsigned short le_short) {
    return (le_short >> 8) | (le_short << 8);
}

Connections *init_connections() {
    Connections *connections = malloc(sizeof(*connections));
    connectionEntry *connectionEntryFirst = malloc(sizeof(*connectionEntryFirst));

    if ( connections == NULL || connectionEntryFirst == NULL ) {
        printf("Unable to allocate memory for Init().\n"); 
        exit(EXIT_FAILURE);
    }

    connections->first = NULL;
    connections->dwEntriesCount = 0;

    return connections;
}

void add_connectionEntry(Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port, unsigned int amountData) {
    /* New connectionEntry struct */
    connectionEntry *connectionEntryNew = malloc(sizeof(*connectionEntryNew));
    if ( connections == NULL || connectionEntryNew == NULL ) {
        printf("Unable to allocate memory for new connectionEntry.\n");
        exit(EXIT_FAILURE);
    }

    /* Filling */
    connectionEntryNew->protocol = protocol;
    connectionEntryNew->source_addr = source_addr;
    connectionEntryNew->source_port = source_port;
    connectionEntryNew->dest_addr = dest_addr;
    connectionEntryNew->dest_port = dest_port;
    connectionEntryNew->amountData = amountData;

    /* Refresh storage */
    connectionEntryNew->next = connections->first;
    connections->first = connectionEntryNew;
    connections->dwEntriesCount++;
}

int update_connectionEntry(Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port, unsigned int addAmountData ) {
    if ( connections == NULL ) {
        printf("NULL Structure was passed to update_connectionEntry().\n");
        exit(EXIT_FAILURE);
    }

    connectionEntry *entryIndex = connections->first;

    while ( entryIndex != NULL ) {
        /* Check connections parameters matches */
        if ( entryIndex->protocol == protocol && entryIndex->source_addr == source_addr && entryIndex->source_port == source_port /*&& entryIndex->dest_addr == dest_addr && entryIndex->dest_port == dest_port*/ ) {
            /* Connection matched */
            entryIndex->amountData += addAmountData;
            return 1;
        }
        entryIndex = entryIndex->next;
    }

    return -1;
}

connectionEntry *match_connectionEntry(Connections *connections, unsigned char protocol, unsigned int source_addr, unsigned short source_port, unsigned int dest_addr, unsigned short dest_port) {
    if ( connections == NULL ) {
        printf("NULL Structure was passed to match_connectionEntry().\n");
        exit(EXIT_FAILURE);
    }

    connectionEntry *entryIndex = connections->first;

    while ( entryIndex != NULL ) {
        /* Check connections parameters matches */
        if ( entryIndex->protocol == protocol && entryIndex->source_addr == source_addr && entryIndex->source_port == source_port /*&& entryIndex->dest_addr == dest_addr && entryIndex->dest_port == dest_port*/ ) {
            /* Matched connection */
            return entryIndex;
        }

        entryIndex = entryIndex->next;
    }

    return NULL;
}

void clear_connections_storage(Connections *connections) {
    if ( connections == NULL ) {
        printf("NULL Structure was passed to clear_connections_storage().\n");
        exit(EXIT_FAILURE);
    }

    connectionEntry *entryIndex = connections->first;
    connectionEntry *nextEntry = NULL;

    while ( entryIndex != NULL ) {
        nextEntry = entryIndex->next;
        free(entryIndex);
        entryIndex = nextEntry;
    }

    connections->first = NULL;
    connections->dwEntriesCount = 0;
}


int list_connectionEntries(Connections *connections) {
    if ( connections == NULL ) {
        printf("NULL Structure was passed to list_connectionEntries().\n");
        exit(EXIT_FAILURE);
    }

    printf("[connectionsEntries] Structure:\n");
    if ( connections->first == NULL ) {
        printf("\tNo entries.\n");
        printf("[connectionsEntries] End of structure.\n\n");
        return 1;
    }

    connectionEntry *entryIndex = connections->first;

    while ( entryIndex != NULL ) {
        printf("\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, Protocol=0x%x, Data length= %d bytes (%.2f kb/s)\n",
                    ( entryIndex->source_addr & 0x000000FF ),
                    ( entryIndex->source_addr & 0x0000FF00 ) >> 8,
                    ( entryIndex->source_addr & 0x00FF0000 ) >> 16,
                    ( entryIndex->source_addr & 0xFF000000 ) >> 24,
                    entryIndex->source_port,
                    ( entryIndex->dest_addr & 0x000000FF ),
                    ( entryIndex->dest_addr & 0x0000FF00 ) >> 8,
                    ( entryIndex->dest_addr & 0x00FF0000 ) >> 16,
                    ( entryIndex->dest_addr & 0xFF000000 ) >> 24,
                    entryIndex->dest_port,
                    entryIndex->protocol,
                    entryIndex->amountData,
                    (double)(entryIndex->amountData/5) / 1000);
        entryIndex = entryIndex->next;
    }

    printf("[connectionsEntries] End of structure.\n\n");
    return 1;
}

void get_triggered_connectionEntries(Connections *connections, unsigned int bandwidth_cap) {
    if ( connections == NULL ) {
        printf("NULL Structure was passed to get_triggered_connectionEntries().");
        exit(EXIT_FAILURE);
    }

    MIB_TCPTABLE_OWNER_PID *extTcpTable;
    MIB_UDPTABLE_OWNER_PID *extUdpTable;
    ULONG ulAf = AF_INET;
    DWORD callTableReturn;
    DWORD estimatedSize;

    /* Get Extended Tcp Table */
    callTableReturn = pGetExtendedTcpTable(NULL, &estimatedSize, 0, ulAf, TCP_TABLE_OWNER_PID_ALL, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid GetExtendedTcpTable parameters.");
        exit(-1);
    }

    extTcpTable = (MIB_TCPTABLE_OWNER_PID *) calloc(estimatedSize, sizeof(MIB_TCPTABLE_OWNER_PID));
    if ( extTcpTable == NULL ) {
        printf("Unable to allocate TCP Table memory.\n");
        exit(-1);
    }
    printf("Estimated TCP Table structure size: %ld\n", estimatedSize);

    callTableReturn = pGetExtendedTcpTable(extTcpTable, &estimatedSize, 0, ulAf, TCP_TABLE_OWNER_PID_ALL, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid GetExtendedTcpTable parameters.");
        exit(-1);
    }
    else if ( callTableReturn == ERROR_INSUFFICIENT_BUFFER ) {
        printf("Not enough allocated memory for TCP Table.");
        exit(-1);
    }

    printf("TcpTable retrieved with %ld entries\n", extTcpTable->dwNumEntries);

    /* Get Extended Udp Table */

    callTableReturn = pGetExtendedUdpTable(NULL, &estimatedSize, 0, ulAf, UDP_TABLE_OWNER_PID, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid pGetExtendedUdpTable parameters.");
        exit(-1);
    }

    extUdpTable = (MIB_UDPTABLE_OWNER_PID *) calloc(estimatedSize, sizeof(MIB_UDPTABLE_OWNER_PID));
    if ( extUdpTable == NULL ) {
        printf("Unable to allocate UDP Table memory.\n");
        exit(-1);
    }
    printf("Estimated UDP Table structure size: %ld\n", estimatedSize);

    callTableReturn = pGetExtendedUdpTable(extUdpTable, &estimatedSize, 0, ulAf, UDP_TABLE_OWNER_PID, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid GetExtendedUdpTable parameters.");
        exit(-1);
    }
    else if ( callTableReturn == ERROR_INSUFFICIENT_BUFFER ) {
        printf("Not enough allocated memory for UDP Table.");
        exit(-1);
    }

    printf("UdpTable retrieved with %ld entries\n", extUdpTable->dwNumEntries);

    connectionEntry *entryIndex = connections->first;
    double bandwidth = 0;
    int dwOwningPid = 0;
    char imageFileName[512];
    char protocolName[24];

    printf("[Triggered connectionsEntries] Bandwidth Usage\n");
    while ( entryIndex != NULL ) {
        bandwidth = (entryIndex->amountData / 10) / 1000;
        if ( bandwidth >= bandwidth_cap ) {
            dwOwningPid = -1;

            /* Retrieving PID from ExtendedTcpTable */
            if ( entryIndex->protocol == PROTOCOL_TCP ) {
                memset(protocolName, 0x00, 24);
                memcpy(protocolName, "TCP", 3);
                dwOwningPid = get_pid_by_connection(NULL, extTcpTable, PROTOCOL_TCP, entryIndex->source_addr, entryIndex->source_port);
            }
            else if ( entryIndex->protocol == PROTOCOL_UDP ) {
                memset(protocolName, 0x00, 24);
                memcpy(protocolName, "UDP", 3);
                dwOwningPid = get_pid_by_connection(extUdpTable, NULL, PROTOCOL_UDP, entryIndex->source_addr, entryIndex->source_port);
                if ( dwOwningPid == -1 ) dwOwningPid = get_pid_by_connection(extUdpTable, NULL, PROTOCOL_UDP, entryIndex->dest_addr, entryIndex->dest_port);
            }

            if ( dwOwningPid == -1 ) {
                printf("Undefined PID, connections probably closed before triggering...\n");
            }
            else {
                get_process_name(dwOwningPid, imageFileName);
            }

            printf("\t[%s] (%s - %d) %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d, Protocol=0x%x, Data length= %d bytes (%.2f kb/s)\n",
                    protocolName,
                    imageFileName,
                    dwOwningPid,
                    ( entryIndex->source_addr & 0x000000FF ),
                    ( entryIndex->source_addr & 0x0000FF00 ) >> 8,
                    ( entryIndex->source_addr & 0x00FF0000 ) >> 16,
                    ( entryIndex->source_addr & 0xFF000000 ) >> 24,
                    entryIndex->source_port,
                    ( entryIndex->dest_addr & 0x000000FF ),
                    ( entryIndex->dest_addr & 0x0000FF00 ) >> 8,
                    ( entryIndex->dest_addr & 0x00FF0000 ) >> 16,
                    ( entryIndex->dest_addr & 0xFF000000 ) >> 24,
                    entryIndex->dest_port,
                    entryIndex->protocol,
                    entryIndex->amountData,
                    bandwidth);
        }
        memset(imageFileName, 0x00, 512);
        entryIndex = entryIndex->next;
    }
    printf("[End of triggered connectionsEntries]\n\n");
}

int get_pid_by_connection(MIB_UDPTABLE_OWNER_PID *extUdpTable, MIB_TCPTABLE_OWNER_PID *extTcpTable, unsigned char PROTOCOL, unsigned int source_addr, unsigned short source_port) {

    if ( PROTOCOL == PROTOCOL_TCP ) {
        MIB_TCPROW_OWNER_PID *tcpOwner;
        unsigned int dwNumLoop;

        for ( dwNumLoop = 0; dwNumLoop < extTcpTable->dwNumEntries; dwNumLoop++ ) {
            tcpOwner = &extTcpTable->table[dwNumLoop];
            if ( tcpOwner->dwRemoteAddr == source_addr && ntohs(tcpOwner->dwRemotePort) == source_port ) {
                printf("STATE: %ld\n", tcpOwner->dwState);
                return tcpOwner->dwOwningPid;
            }
        }
    }
    else if ( PROTOCOL == PROTOCOL_UDP ) {
        MIB_UDPROW_OWNER_PID *udpOwner;
        unsigned int dwNumLoop;

        for ( dwNumLoop = 0; dwNumLoop < extUdpTable->dwNumEntries; dwNumLoop++ ) {
            udpOwner = &extUdpTable->table[dwNumLoop];
            if ( ntohs(udpOwner->dwLocalPort) == source_port ) {
                return udpOwner->dwOwningPid;
            }
        }
    }

    return (-1);
}

int get_process_name(int dwProcessId, char *imageFileName) {

    if ( dwProcessId == 0 ) {
        memcpy(imageFileName, "System Idle Process", 19);
        return 1;
    }
    else if ( dwProcessId == 4 ) {
        memcpy(imageFileName, "System", 6);
        return 1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, dwProcessId);
    if ( processHandle == NULL ) {
        printf("Unable to open process with PID: %d\n", dwProcessId);
        memcpy(imageFileName, "<unknown>", 9);
        return (-1);
    }

    char _imageFileName[512] = {0};
    int process_length = GetProcessImageFileName(processHandle, _imageFileName, 512);

    if ( process_length == 0 ) {
        printf("Unable to get process name for the process with PID: %d, Error: 0x%lx\n", dwProcessId, GetLastError());
        memcpy(imageFileName, "<unknown>", 9);
        return (-1);
    }

    char* imageFileNameTrunc = strrchr(_imageFileName, '\\');
    if ( imageFileNameTrunc == NULL ) 
        memcpy(imageFileName, _imageFileName, process_length);
    else 
        memcpy(imageFileName, imageFileNameTrunc+1, process_length-1);

    CloseHandle(processHandle);
    return 1;
}
