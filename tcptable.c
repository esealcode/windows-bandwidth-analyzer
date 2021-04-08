/* Compile command line: gcc tcptable.c -o tcptable -lwsock32 -lpsapi */

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
    printf("Getting TCP connections...\n");

    DWORD ( WINAPI *pGetExtendedTcpTable)(
            PVOID pTcpTable,
            PDWORD pdwSize,
            BOOL bOrder,
            ULONG ulAf,
            TCP_TABLE_CLASS TableClass,
            ULONG Reserved
            );

    HMODULE dll_iphlpapi = LoadLibrary("iphlpapi.dll");
    pGetExtendedTcpTable = (DWORD (WINAPI *)(PVOID,PDWORD,BOOL,ULONG,TCP_TABLE_CLASS,ULONG)) GetProcAddress(dll_iphlpapi, "GetExtendedTcpTable");


    MIB_TCPTABLE_OWNER_PID *extTcpTable;
    MIB_TCPROW_OWNER_PID *tcpOwner;
    ULONG ulAf = AF_INET;
    DWORD callTableReturn;
    DWORD estimatedSize;
    
    unsigned short local_port;
    unsigned short remote_port;
    DWORD owner_pid;

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
    printf("Estimated TCP Table structure size: %d\n", estimatedSize);

    callTableReturn = pGetExtendedTcpTable(extTcpTable, &estimatedSize, 0, ulAf, TCP_TABLE_OWNER_PID_ALL, 0);
    if ( callTableReturn == ERROR_INVALID_PARAMETER ) {
        printf("Invalid GetExtendedTcpTable parameters.");
        exit(-1);
    }
    else if ( callTableReturn == ERROR_INSUFFICIENT_BUFFER ) {
        printf("Not enough allocated memory for TCP Table.");
        exit(-1);
    }

    printf("TcpTable retrieved with %d entries\n", extTcpTable->dwNumEntries);

    int dwNumLoop;
    int not_handled = 0;
    for ( dwNumLoop = 0; dwNumLoop < extTcpTable->dwNumEntries; dwNumLoop++ ) {
        tcpOwner = &extTcpTable->table[dwNumLoop];
        local_port = ntohs(tcpOwner->dwLocalPort);
        remote_port = ntohs(tcpOwner->dwRemotePort);
        owner_pid = tcpOwner->dwOwningPid;

        if ( get_process_name(owner_pid) == -1 ) {
            printf("Not handled PID: %d\n", owner_pid);
            not_handled++;
        }

        printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d -- Owner PID: %d, STATE=",
                ( tcpOwner->dwRemoteAddr & 0x000000FF ),
                ( tcpOwner->dwRemoteAddr & 0x0000FF00 ) >> 8,
                ( tcpOwner->dwRemoteAddr & 0x00FF0000 ) >> 16,
                ( tcpOwner->dwRemoteAddr & 0xFF000000 ) >> 24,
                remote_port,
                ( tcpOwner->dwLocalAddr & 0x000000FF ),
                ( tcpOwner->dwLocalAddr & 0x0000FF00 ) >> 8,
                ( tcpOwner->dwLocalAddr & 0x00FF0000 ) >> 16,
                ( tcpOwner->dwLocalAddr & 0xFF000000 ) >> 24,
                local_port,
                owner_pid
                );

        switch ( tcpOwner->dwState ) {
            case MIB_TCP_STATE_CLOSED:
                printf("CLOSED\n");
                break;
            case MIB_TCP_STATE_LISTEN:
                printf("LISTENING\n");
                break;
            case MIB_TCP_STATE_SYN_SENT:
                printf("SYN SENT\n");
                break;
            case MIB_TCP_STATE_SYN_RCVD:
                printf("SYN RECEIVED\n");
                break;
            case MIB_TCP_STATE_ESTAB:
                printf("ETABLISHED\n");
                break;
            case MIB_TCP_STATE_FIN_WAIT1:
                printf("FIN WAIT 1\n");
                break;
            case MIB_TCP_STATE_FIN_WAIT2:
                printf("FIN WAIT 2\n");
                break;
            case MIB_TCP_STATE_CLOSE_WAIT:
                printf("CLOSE WAIT\n");
                break;
            case MIB_TCP_STATE_CLOSING:
                printf("CLOSING\n");
                break;
            case MIB_TCP_STATE_LAST_ACK:
                printf("LAST ACK\n");
                break;
            case MIB_TCP_STATE_TIME_WAIT:
                printf("TIME WAIT\n");
                break;
            case MIB_TCP_STATE_DELETE_TCB:
                printf("DELETE TCB\n");
                break;
        }
    }

    free(extTcpTable);
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