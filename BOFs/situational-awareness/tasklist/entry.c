#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * stealthy_tasklist - Process enumeration via NtQuerySystemInformation
 *
 * Single syscall (NtQuerySystemInformation with SystemProcessInformation)
 * replaces the entire WMI/COM stack or CreateToolhelp32Snapshot approach.
 * No per-process OpenProcess calls needed.
 */

#define SystemProcessInformation 5

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* NtQuerySystemInformation - not in bofdefs.h */
#ifdef BOF
DECLSPEC_IMPORT NTSTATUS NTDLL$NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);
#else
__declspec(dllimport) NTSTATUS WINAPI NtQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);
#define NTDLL$NtQuerySystemInformation NtQuerySystemInformation
#endif

/*
 * SYSTEM_PROCESS_INFORMATION layout - fields up to WorkingSetSize.
 * Compiler handles alignment/padding for both x86 and x64.
 */
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
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
} MY_SPI, *PMY_SPI;

static void EnumProcesses(void)
{
    ULONG bufSize = 1024 * 1024;
    PVOID pBuf = NULL;
    ULONG retLen = 0;
    NTSTATUS status;

    /* Query with retry on buffer too small */
    for (int attempt = 0; attempt < 3; attempt++) {
        pBuf = intAlloc(bufSize);
        if (!pBuf) {
            internal_printf("[!] Allocation failed (%lu bytes)\n", bufSize);
            return;
        }

        status = NTDLL$NtQuerySystemInformation(
            SystemProcessInformation, pBuf, bufSize, &retLen);

        if (NT_SUCCESS(status)) break;

        intFree(pBuf);
        pBuf = NULL;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufSize = retLen + 0x10000;
        else {
            internal_printf("[!] NtQuerySystemInformation failed: 0x%08lX\n",
                (ULONG)status);
            return;
        }
    }

    if (!pBuf) {
        internal_printf("[!] Failed to query process information\n");
        return;
    }

    internal_printf("\n[*] Process List (NtQuerySystemInformation)\n");
    internal_printf("=============================================\n\n");
    internal_printf("  %-8s %-8s %-6s %-8s %-10s %-4s %s\n",
        "PID", "PPID", "Thds", "Hndls", "WS (KB)", "Sess", "Name");
    internal_printf("  %-8s %-8s %-6s %-8s %-10s %-4s %s\n",
        "---", "----", "----", "-----", "-------", "----", "----");

    PMY_SPI pProc = (PMY_SPI)pBuf;
    DWORD count = 0;

    while (1) {
        char* name = NULL;
        if (pProc->ImageName.Buffer && pProc->ImageName.Length > 0)
            name = Utf16ToUtf8(pProc->ImageName.Buffer);

        DWORD pid  = (DWORD)(ULONG_PTR)pProc->UniqueProcessId;
        DWORD ppid = (DWORD)(ULONG_PTR)pProc->InheritedFromUniqueProcessId;

        internal_printf("  %-8lu %-8lu %-6lu %-8lu %-10lu %-4lu %s\n",
            pid, ppid,
            pProc->NumberOfThreads,
            pProc->HandleCount,
            (ULONG)(pProc->WorkingSetSize / 1024),
            pProc->SessionId,
            name ? name : (pid == 0 ? "[Idle]" : "[System]"));

        if (name) intFree(name);
        count++;

        if (pProc->NextEntryOffset == 0) break;
        pProc = (PMY_SPI)((PBYTE)pProc + pProc->NextEntryOffset);
        if (count > 2000) break;
    }

    internal_printf("\n  Total: %lu processes\n", count);
    intFree(pBuf);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    EnumProcesses();
    printoutput(TRUE);
}
#else
int main()
{
    EnumProcesses();
    return 0;
}
#endif
