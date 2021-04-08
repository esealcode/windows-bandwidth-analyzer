/* Compile command line: gcc udptable.c -o udptable -lwsock32 -lpsapi */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define _WIN32_WINNT 0x0600
#include <Windows.h>
#include <Psapi.h>
#include <Iphlpapi.h>
#include <Winsock2.h>

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

int get_process_name(DWORD dwProcessId);
int set_privilege();

int main() {
    set_privilege();
    printf("Getting UDP connections...\n");

    DWORD ( WINAPI *pGetExtendedUdpTable)(
            PVOID pUdpTable,
            PDWORD pdwSize,
            BOOL bOrder,
            ULONG ulAf,
            UDP_TABLE_CLASS TableClass,
            ULONG Reserved
            );

    HMODULE dll_iphlpapi = LoadLibrary("iphlpapi.dll");
    pGetExtendedUdpTable = (DWORD (WINAPI *)(PVOID,PDWORD,BOOL,ULONG,UDP_TABLE_CLASS,ULONG)) GetProcAddress(dll_iphlpapi, "GetExtendedUdpTable");


    MIB_UDPTABLE_OWNER_PID *extUdpTable;
    MIB_UDPROW_OWNER_PID *udpOwner;
    ULONG ulAf = AF_INET;
    DWORD callTableReturn;
    DWORD estimatedSize;
    
    unsigned short local_port;
    unsigned short remote_port;
    DWORD owner_pid;

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
    printf("Estimated UDP Table structure size: %d\n", estimatedSize);

    callTableReturn = pGetExtendedUdpTable(extUdpTable, &estimatedSize, 0, ulAf, UDP_TABLE_OWNER_PID, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid GetExtendedUdpTable parameters.");
        exit(-1);
    }
    else if ( callTableReturn == ERROR_INSUFFICIENT_BUFFER ) {
        printf("Not enough allocated memory for UDP Table.");
        exit(-1);
    }

    printf("UdpTable retrieved with %d entries\n", extUdpTable->dwNumEntries);

    int dwNumLoop;
    int not_handled = 0;
    for ( dwNumLoop = 0; dwNumLoop < extUdpTable->dwNumEntries; dwNumLoop++ ) {
        udpOwner = &extUdpTable->table[dwNumLoop];
        local_port = ntohs(udpOwner->dwLocalPort);
        owner_pid = udpOwner->dwOwningPid;

        if ( get_process_name(owner_pid) == -1 ) {
            printf("Not handled PID: %d\n", owner_pid);
            not_handled++;
        }

        printf("%d.%d.%d.%d:%d -- Owner PID: %d\n",
                ( udpOwner->dwLocalAddr & 0x000000FF ),
                ( udpOwner->dwLocalAddr & 0x0000FF00 ) >> 8,
                ( udpOwner->dwLocalAddr & 0x00FF0000 ) >> 16,
                ( udpOwner->dwLocalAddr & 0xFF000000 ) >> 24,
                local_port,
                owner_pid
                );
    }

    free(extUdpTable);
    printf("Connections not handled: %d\n", not_handled);

    return 1;
}

int get_process_name(DWORD dwProcessId) {

    if ( dwProcessId == 0 ) {
        printf("System Idle Process (0)\n");
        return 1;
    }
    else if ( dwProcessId == 4 ) {
        printf("System (4)\n");
        return 1;
    }

    unsigned short module_length;

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, dwProcessId);
    if ( processHandle == NULL ) {
        printf("Unable to open process with PID: %d\n", dwProcessId);
        return (-1);
    }

    char baseName[512] = {0};
    int process_length = GetProcessImageFileName(processHandle, baseName, 512);
    if ( process_length == 0 ) {
        printf("Unable to get process name for the process with PID: %d, Error: 0x%x\n", dwProcessId, GetLastError());
        return (-1);
    }

    char* baseNameTrunc = strrchr(baseName, '\\');
    if ( baseNameTrunc == NULL ) 
        printf("%s (%d)\n", baseName, dwProcessId);
    else 
        printf("%s (%d)\n", baseNameTrunc+1, dwProcessId);

    CloseHandle(processHandle);
    return 1;
}

int set_privilege() {
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
                }
                else if ( getLastError == ERROR_NOT_ALL_ASSIGNED ) {
                    printf("Privileges not all set !\n");
                }
            }
        }
    }
}