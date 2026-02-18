#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * stealthy_netstat - Network connection enumeration
 *
 * Uses GetExtendedTcpTable / GetExtendedUdpTable for PID-aware tables
 * (single call each, vs original's per-entry approach).
 *
 * PID-to-name resolution uses NtQuerySystemInformation instead of
 * per-process OpenProcess calls (major stealth improvement).
 *
 * Inline byte swap replaces WS2_32 dependency entirely.
 */

/* Inline network-to-host byte order (avoid ws2_32) */
#define SWAP16(x) ((USHORT)(((USHORT)(x) >> 8) | ((USHORT)(x) << 8)))

#define SystemProcessInformation    5
#define MY_AF_INET                  2
#define TCP_TABLE_OWNER_PID_ALL     5
#define UDP_TABLE_OWNER_PID         1

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* ================================================================
 *  Declarations not in bofdefs.h
 * ================================================================ */

#ifdef BOF

DECLSPEC_IMPORT NTSTATUS NTDLL$NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(
    PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder,
    ULONG ulAf, ULONG TableClass, ULONG Reserved);

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedUdpTable(
    PVOID pUdpTable, PDWORD pdwSize, BOOL bOrder,
    ULONG ulAf, ULONG TableClass, ULONG Reserved);

#else

__declspec(dllimport) NTSTATUS WINAPI NtQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);
#define NTDLL$NtQuerySystemInformation NtQuerySystemInformation

/* Link with -liphlpapi for standalone test build */
__declspec(dllimport) DWORD WINAPI GetExtendedTcpTable(
    PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
__declspec(dllimport) DWORD WINAPI GetExtendedUdpTable(
    PVOID, PDWORD, BOOL, ULONG, ULONG, ULONG);
#define IPHLPAPI$GetExtendedTcpTable  GetExtendedTcpTable
#define IPHLPAPI$GetExtendedUdpTable  GetExtendedUdpTable

#endif

/* ================================================================
 *  TCP / UDP table structures with owning PID
 * ================================================================ */

typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} MY_TCPROW_PID;

typedef struct {
    DWORD dwNumEntries;
    MY_TCPROW_PID table[1];
} MY_TCPTABLE_PID;

typedef struct {
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwOwningPid;
} MY_UDPROW_PID;

typedef struct {
    DWORD dwNumEntries;
    MY_UDPROW_PID table[1];
} MY_UDPTABLE_PID;

/* Minimal SPI struct for PID-to-name lookup */
typedef struct _MY_SPI {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
} MY_SPI, *PMY_SPI;

/* ================================================================
 *  Helpers
 * ================================================================ */

static const char* TcpStateStr(DWORD state)
{
    switch (state) {
        case 1:  return "CLOSED";
        case 2:  return "LISTEN";
        case 3:  return "SYN_SENT";
        case 4:  return "SYN_RCVD";
        case 5:  return "ESTAB";
        case 6:  return "FIN_WAIT1";
        case 7:  return "FIN_WAIT2";
        case 8:  return "CLOSE_WAIT";
        case 9:  return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE_TCB";
        default: return "???";
    }
}

/* Scan SPI buffer for a process name by PID */
static const WCHAR* FindProcName(PVOID pSpiBuffer, DWORD pid)
{
    if (!pSpiBuffer) return NULL;
    PMY_SPI pProc = (PMY_SPI)pSpiBuffer;
    while (1) {
        if ((DWORD)(ULONG_PTR)pProc->UniqueProcessId == pid) {
            if (pProc->ImageName.Buffer && pProc->ImageName.Length > 0)
                return pProc->ImageName.Buffer;
            return NULL;
        }
        if (pProc->NextEntryOffset == 0) break;
        pProc = (PMY_SPI)((PBYTE)pProc + pProc->NextEntryOffset);
    }
    return NULL;
}

/* Get all process info in one NtQuerySystemInformation call */
static PVOID GetProcessInfo(void)
{
    ULONG bufSize = 512 * 1024;
    PVOID pBuf = NULL;
    ULONG retLen = 0;

    for (int attempt = 0; attempt < 3; attempt++) {
        pBuf = intAlloc(bufSize);
        if (!pBuf) return NULL;

        NTSTATUS status = NTDLL$NtQuerySystemInformation(
            SystemProcessInformation, pBuf, bufSize, &retLen);

        if (NT_SUCCESS(status)) return pBuf;

        intFree(pBuf);
        pBuf = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufSize = retLen + 0x10000;
        else
            break;
    }
    return NULL;
}

/* ================================================================
 *  TCP / UDP table printing
 * ================================================================ */

static void PrintTcpTable(PVOID pSpiBuffer)
{
    DWORD dwSize = 0;
    DWORD ret = IPHLPAPI$GetExtendedTcpTable(
        NULL, &dwSize, FALSE, MY_AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (ret != ERROR_INSUFFICIENT_BUFFER || dwSize == 0) {
        internal_printf("  [!] TCP table query failed: %lu\n", ret);
        return;
    }

    MY_TCPTABLE_PID* pTable = (MY_TCPTABLE_PID*)intAlloc(dwSize);
    if (!pTable) return;

    ret = IPHLPAPI$GetExtendedTcpTable(
        pTable, &dwSize, TRUE, MY_AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (ret != NO_ERROR) {
        internal_printf("  [!] TCP table read failed: %lu\n", ret);
        intFree(pTable);
        return;
    }

    for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
        MY_TCPROW_PID* r = &pTable->table[i];
        PBYTE la = (PBYTE)&r->dwLocalAddr;
        PBYTE ra = (PBYTE)&r->dwRemoteAddr;
        USHORT lp = SWAP16((USHORT)r->dwLocalPort);
        USHORT rp = SWAP16((USHORT)r->dwRemotePort);

        char* procName = NULL;
        const WCHAR* wName = FindProcName(pSpiBuffer, r->dwOwningPid);
        if (wName) procName = Utf16ToUtf8(wName);

        internal_printf(
            "  TCP  %u.%u.%u.%u:%-5u  %u.%u.%u.%u:%-5u  %-12s %5lu  %s\n",
            la[0], la[1], la[2], la[3], lp,
            ra[0], ra[1], ra[2], ra[3], rp,
            TcpStateStr(r->dwState),
            r->dwOwningPid,
            procName ? procName : "");

        if (procName) intFree(procName);
    }

    intFree(pTable);
}

static void PrintUdpTable(PVOID pSpiBuffer)
{
    DWORD dwSize = 0;
    DWORD ret = IPHLPAPI$GetExtendedUdpTable(
        NULL, &dwSize, FALSE, MY_AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (ret != ERROR_INSUFFICIENT_BUFFER || dwSize == 0) {
        internal_printf("  [!] UDP table query failed: %lu\n", ret);
        return;
    }

    MY_UDPTABLE_PID* pTable = (MY_UDPTABLE_PID*)intAlloc(dwSize);
    if (!pTable) return;

    ret = IPHLPAPI$GetExtendedUdpTable(
        pTable, &dwSize, TRUE, MY_AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (ret != NO_ERROR) {
        internal_printf("  [!] UDP table read failed: %lu\n", ret);
        intFree(pTable);
        return;
    }

    for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
        MY_UDPROW_PID* r = &pTable->table[i];
        PBYTE la = (PBYTE)&r->dwLocalAddr;
        USHORT lp = SWAP16((USHORT)r->dwLocalPort);

        char* procName = NULL;
        const WCHAR* wName = FindProcName(pSpiBuffer, r->dwOwningPid);
        if (wName) procName = Utf16ToUtf8(wName);

        internal_printf(
            "  UDP  %u.%u.%u.%u:%-5u  *:*            %-12s %5lu  %s\n",
            la[0], la[1], la[2], la[3], lp,
            "",
            r->dwOwningPid,
            procName ? procName : "");

        if (procName) intFree(procName);
    }

    intFree(pTable);
}

/* ================================================================
 *  Entry
 * ================================================================ */

static void NetstatRecon(void)
{
    internal_printf("\n[*] Network Connections\n");
    internal_printf("========================\n\n");
    internal_printf("  %-5s %-22s %-22s %-12s %5s  %s\n",
        "Proto", "Local Address", "Remote Address", "State", "PID", "Process");
    internal_printf("  %-5s %-22s %-22s %-12s %5s  %s\n",
        "-----", "-------------", "--------------", "-----", "---", "-------");

    /* Single NtQSI call for all process names */
    PVOID pSpiBuffer = GetProcessInfo();

    PrintTcpTable(pSpiBuffer);
    PrintUdpTable(pSpiBuffer);

    if (pSpiBuffer) intFree(pSpiBuffer);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    NetstatRecon();
    printoutput(TRUE);
}
#else
int main()
{
    NetstatRecon();
    return 0;
}
#endif
