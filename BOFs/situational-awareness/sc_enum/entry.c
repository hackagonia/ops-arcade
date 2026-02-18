#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * stealthy_sc_enum - Detailed service enumeration via Nt registry APIs
 *
 * Walks \Registry\Machine\SYSTEM\CurrentControlSet\Services
 * using NtOpenKey / NtEnumerateKey / NtQueryValueKey.
 *
 * Bypasses SCM entirely (no OpenSCManagerW, no EnumServicesStatusExW).
 * All calls go through ntdll, avoiding advapi32 SCM hooks.
 *
 * STATE/PID determined via NtQuerySystemInformation process matching.
 * Output format mirrors sc query + sc qc combined.
 */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define STATUS_BUFFER_OVERFLOW      ((NTSTATUS)0x80000005L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemProcessInformation    5

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) \
    do { \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
        (p)->RootDirectory = (r); \
        (p)->Attributes = (a); \
        (p)->ObjectName = (n); \
        (p)->SecurityDescriptor = (s); \
        (p)->SecurityQualityOfService = NULL; \
    } while (0)
#endif

#define KeyBasicInformation         0
#define KeyValuePartialInformation  2

/* ================================================================
 *  NTDLL declarations not in bofdefs.h
 * ================================================================ */

#ifdef BOF

DECLSPEC_IMPORT NTSTATUS NTDLL$NtOpenKey(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtEnumerateKey(
    HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtQueryValueKey(
    HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT VOID NTDLL$RtlInitUnicodeString(
    PUNICODE_STRING, PCWSTR);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);

#else

__declspec(dllimport) NTSTATUS WINAPI NtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
__declspec(dllimport) NTSTATUS WINAPI NtEnumerateKey(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
__declspec(dllimport) NTSTATUS WINAPI NtQueryValueKey(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG);
__declspec(dllimport) VOID WINAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
__declspec(dllimport) NTSTATUS WINAPI NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

#define NTDLL$NtOpenKey            NtOpenKey
#define NTDLL$NtEnumerateKey       NtEnumerateKey
#define NTDLL$NtQueryValueKey      NtQueryValueKey
#define NTDLL$RtlInitUnicodeString RtlInitUnicodeString
#define NTDLL$NtQuerySystemInformation NtQuerySystemInformation

#endif

/* ================================================================
 *  Structures
 * ================================================================ */

typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} MY_KEY_BASIC_INFO;

typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} MY_KEY_VALUE_PARTIAL;

/* Minimal SPI for process matching */
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
 *  String helpers
 * ================================================================ */

static BOOL WStrIEqual(const WCHAR* a, const WCHAR* b)
{
    while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == *b);
}

static const char* TypeStr(ULONG type)
{
    ULONG base = type & 0xFF;
    switch (base) {
        case 0x01: return "KERNEL_DRIVER";
        case 0x02: return "FILE_SYSTEM_DRIVER";
        case 0x04: return "ADAPTER";
        case 0x10: return (type & 0x100) ?
            "WIN32_OWN_PROCESS (interactive)" : "WIN32_OWN_PROCESS";
        case 0x20: return (type & 0x100) ?
            "WIN32_SHARE_PROCESS (interactive)" : "WIN32_SHARE_PROCESS";
        default: return "UNKNOWN";
    }
}

static const char* StartTypeStr(ULONG s)
{
    switch (s) {
        case 0: return "BOOT_START";
        case 1: return "SYSTEM_START";
        case 2: return "AUTO_START";
        case 3: return "DEMAND_START";
        case 4: return "DISABLED";
        default: return "UNKNOWN";
    }
}

static const char* ErrorControlStr(ULONG ec)
{
    switch (ec) {
        case 0: return "IGNORE";
        case 1: return "NORMAL";
        case 2: return "SEVERE";
        case 3: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

/* ================================================================
 *  Registry query helpers
 * ================================================================ */

static BOOL QueryDword(HANDLE hKey, PCWSTR valueName, PULONG pResult)
{
    UNICODE_STRING usName;
    NTDLL$RtlInitUnicodeString(&usName, valueName);
    BYTE buf[64];
    ULONG resultLen;
    NTSTATUS status = NTDLL$NtQueryValueKey(
        hKey, &usName, KeyValuePartialInformation,
        buf, sizeof(buf), &resultLen);
    if (NT_SUCCESS(status)) {
        MY_KEY_VALUE_PARTIAL* p = (MY_KEY_VALUE_PARTIAL*)buf;
        if (p->Type == REG_DWORD && p->DataLength >= sizeof(ULONG)) {
            *pResult = *(PULONG)p->Data;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL QueryString(HANDLE hKey, PCWSTR valueName,
                         PWCHAR pResult, ULONG maxChars)
{
    UNICODE_STRING usName;
    NTDLL$RtlInitUnicodeString(&usName, valueName);
    ULONG bufSize = sizeof(MY_KEY_VALUE_PARTIAL) + (maxChars * sizeof(WCHAR));
    PBYTE buf = (PBYTE)intAlloc(bufSize);
    if (!buf) return FALSE;
    ULONG resultLen;
    NTSTATUS status = NTDLL$NtQueryValueKey(
        hKey, &usName, KeyValuePartialInformation,
        buf, bufSize, &resultLen);
    BOOL ok = FALSE;
    if (NT_SUCCESS(status)) {
        MY_KEY_VALUE_PARTIAL* p = (MY_KEY_VALUE_PARTIAL*)buf;
        if ((p->Type == REG_SZ || p->Type == REG_EXPAND_SZ) &&
            p->DataLength > 0) {
            PWCHAR src = (PWCHAR)p->Data;
            ULONG srcLen = p->DataLength / sizeof(WCHAR);
            if (srcLen > maxChars - 1) srcLen = maxChars - 1;
            for (ULONG i = 0; i < srcLen; i++)
                pResult[i] = src[i];
            pResult[srcLen] = L'\0';
            ok = TRUE;
        }
    }
    intFree(buf);
    return ok;
}

/* Print REG_MULTI_SZ dependencies, one per line */
static void PrintDependencies(HANDLE hKey)
{
    UNICODE_STRING usName;
    NTDLL$RtlInitUnicodeString(&usName, L"DependOnService");

    PBYTE buf = (PBYTE)intAlloc(2048);
    if (!buf) {
        internal_printf("\t%-32s: \n", "DEPENDENCIES");
        return;
    }

    ULONG resultLen;
    NTSTATUS status = NTDLL$NtQueryValueKey(
        hKey, &usName, KeyValuePartialInformation,
        buf, 2048, &resultLen);

    if (!NT_SUCCESS(status)) {
        internal_printf("\t%-32s: \n", "DEPENDENCIES");
        intFree(buf);
        return;
    }

    MY_KEY_VALUE_PARTIAL* p = (MY_KEY_VALUE_PARTIAL*)buf;
    if (p->Type != REG_MULTI_SZ || p->DataLength <= 2) {
        internal_printf("\t%-32s: \n", "DEPENDENCIES");
        intFree(buf);
        return;
    }

    PWCHAR str = (PWCHAR)p->Data;
    BOOL first = TRUE;

    while (*str) {
        char* utf8 = Utf16ToUtf8(str);
        if (utf8) {
            if (first) {
                internal_printf("\t%-32s: %s\n", "DEPENDENCIES", utf8);
                first = FALSE;
            } else {
                internal_printf("\t%-32s: %s\n", "", utf8);
            }
            intFree(utf8);
        }
        while (*str) str++;
        str++;
    }

    if (first)
        internal_printf("\t%-32s: \n", "DEPENDENCIES");

    intFree(buf);
}

/* ================================================================
 *  Process matching for STATE / PID
 * ================================================================ */

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
        else break;
    }
    return NULL;
}

/* Extract exe filename from ImagePath like:
 *   "C:\foo\bar.exe" --args   or   \SystemRoot\system32\svc.exe -k grp */
static void ExtractExeName(const WCHAR* path, WCHAR* out, ULONG maxChars)
{
    const WCHAR* p = path;
    const WCHAR* lastSlash = NULL;
    BOOL inQuotes = (*p == L'"');
    if (inQuotes) p++;

    const WCHAR* start = p;
    while (*p) {
        if (inQuotes && *p == L'"') break;
        if (!inQuotes && *p == L' ') break;
        if (*p == L'\\') lastSlash = p;
        p++;
    }

    const WCHAR* nameStart = lastSlash ? lastSlash + 1 : start;
    ULONG i = 0;
    while (nameStart < p && i < maxChars - 1)
        out[i++] = *nameStart++;
    out[i] = L'\0';
}

/* Find first process matching exe name, return PID */
static DWORD FindServicePid(PVOID pSpiBuffer, const WCHAR* exeName)
{
    if (!pSpiBuffer || !exeName || !exeName[0]) return 0;
    PMY_SPI pProc = (PMY_SPI)pSpiBuffer;
    while (1) {
        if (pProc->ImageName.Buffer && pProc->ImageName.Length > 0) {
            if (WStrIEqual(pProc->ImageName.Buffer, exeName))
                return (DWORD)(ULONG_PTR)pProc->UniqueProcessId;
        }
        if (pProc->NextEntryOffset == 0) break;
        pProc = (PMY_SPI)((PBYTE)pProc + pProc->NextEntryOffset);
    }
    return 0;
}

/* ================================================================
 *  Per-service detail output
 *  All WCHAR buffers heap-allocated to avoid __chkstk_ms in BOF
 * ================================================================ */

typedef struct {
    WCHAR displayName[256];
    WCHAR imagePath[400];
    WCHAR objectName[256];
    WCHAR group[128];
    WCHAR failCmd[128];
    WCHAR description[256];
    WCHAR exeName[128];
} SVC_STRINGS;

static BOOL PrintServiceDetail(HANDLE hServices, WCHAR* subkeyName,
                                PVOID pSpiBuffer)
{
    UNICODE_STRING subkeyStr;
    NTDLL$RtlInitUnicodeString(&subkeyStr, subkeyName);
    OBJECT_ATTRIBUTES subOa;
    InitializeObjectAttributes(&subOa, &subkeyStr,
        OBJ_CASE_INSENSITIVE, hServices, NULL);

    HANDLE hSubkey = NULL;
    NTSTATUS status = NTDLL$NtOpenKey(&hSubkey, KEY_READ, &subOa);
    if (!NT_SUCCESS(status)) return FALSE;

    /* Must have Type to be a real service */
    ULONG serviceType = 0;
    if (!QueryDword(hSubkey, L"Type", &serviceType)) {
        NTDLL$NtClose(hSubkey);
        return FALSE;
    }

    /* Heap-allocate string buffers (avoids >4KB stack frame) */
    SVC_STRINGS* s = (SVC_STRINGS*)intAlloc(sizeof(SVC_STRINGS));
    if (!s) {
        NTDLL$NtClose(hSubkey);
        return FALSE;
    }

    /* Read all config values */
    ULONG startType = 0, errorControl = 0, tag = 0;
    QueryDword(hSubkey, L"Start", &startType);
    QueryDword(hSubkey, L"ErrorControl", &errorControl);
    QueryDword(hSubkey, L"Tag", &tag);

    s->displayName[0] = L'\0';
    s->imagePath[0]   = L'\0';
    s->objectName[0]  = L'\0';
    s->group[0]       = L'\0';
    s->failCmd[0]     = L'\0';
    s->description[0] = L'\0';

    QueryString(hSubkey, L"DisplayName",    s->displayName, 256);
    QueryString(hSubkey, L"ImagePath",      s->imagePath, 400);
    QueryString(hSubkey, L"ObjectName",     s->objectName, 256);
    QueryString(hSubkey, L"Group",          s->group, 128);
    QueryString(hSubkey, L"FailureCommand", s->failCmd, 128);
    QueryString(hSubkey, L"Description",    s->description, 256);

    /* FailureActions: first DWORD is reset period (seconds) */
    ULONG resetPeriod = 0;
    {
        UNICODE_STRING usFA;
        NTDLL$RtlInitUnicodeString(&usFA, L"FailureActions");
        BYTE faBuf[64];
        ULONG faLen;
        NTSTATUS faStatus = NTDLL$NtQueryValueKey(
            hSubkey, &usFA, KeyValuePartialInformation,
            faBuf, sizeof(faBuf), &faLen);
        if (NT_SUCCESS(faStatus)) {
            MY_KEY_VALUE_PARTIAL* pFA = (MY_KEY_VALUE_PARTIAL*)faBuf;
            if (pFA->Type == REG_BINARY && pFA->DataLength >= sizeof(ULONG))
                resetPeriod = *(PULONG)pFA->Data;
        }
    }

    /* Process matching for STATE / PID */
    DWORD pid = 0;
    DWORD state = 1; /* STOPPED */
    BOOL isDriver = ((serviceType & 0xFF) <= 0x02);

    if (!isDriver && s->imagePath[0]) {
        ExtractExeName(s->imagePath, s->exeName, 128);
        pid = FindServicePid(pSpiBuffer, s->exeName);
        if (pid > 0) state = 4; /* RUNNING */
    }

    /* === Print output === */
    char* svcName  = Utf16ToUtf8(subkeyName);
    char* dispName = s->displayName[0] ? Utf16ToUtf8(s->displayName) : NULL;

    internal_printf("\nSERVICE_NAME: %s\n", svcName ? svcName : "");
    internal_printf("DISPLAY_NAME: %s\n",
        dispName ? dispName : (svcName ? svcName : ""));

    /* TYPE (hex, matching sc.exe format) */
    internal_printf("\t%-32s: %lx  %s\n",
        "TYPE", serviceType, TypeStr(serviceType));

    /* STATE */
    if (isDriver) {
        internal_printf("\t%-32s: (driver - state via registry only)\n",
            "STATE");
    } else {
        internal_printf("\t%-32s: %lu  %s\n", "STATE", state,
            state == 4 ? "RUNNING" : "STOPPED");
    }

    internal_printf("\t%-32s: 0\n", "WIN32_EXIT_CODE");
    internal_printf("\t%-32s: 0\n", "SERVICE_EXIT_CODE");
    internal_printf("\t%-32s: 0\n", "CHECKPOINT");
    internal_printf("\t%-32s: 0\n", "WAIT_HINT");
    internal_printf("\t%-32s: %lu\n", "PID", pid);
    internal_printf("\t%-32s: 0\n", "FLAGS");

    /* Config section */
    internal_printf("\t%-32s: %lu  %s\n",
        "START_TYPE", startType, StartTypeStr(startType));
    internal_printf("\t%-32s: %lu  %s\n",
        "ERROR_CONTROL", errorControl, ErrorControlStr(errorControl));

    char* imgPath = s->imagePath[0] ? Utf16ToUtf8(s->imagePath) : NULL;
    internal_printf("\t%-32s: %s\n",
        "BINARY_PATH_NAME", imgPath ? imgPath : "");

    char* grp = s->group[0] ? Utf16ToUtf8(s->group) : NULL;
    internal_printf("\t%-32s: %s\n",
        "LOAD_ORDER_GROUP", grp ? grp : "");

    internal_printf("\t%-32s: %lu\n", "TAG", tag);
    internal_printf("\t%-32s: %s\n", "DISPLAY_NAME",
        dispName ? dispName : (svcName ? svcName : ""));

    /* Dependencies (REG_MULTI_SZ) */
    PrintDependencies(hSubkey);

    char* objName = s->objectName[0] ? Utf16ToUtf8(s->objectName) : NULL;
    internal_printf("\t%-32s: %s\n",
        "SERVICE_START_NAME", objName ? objName : "");

    internal_printf("\t%-32s: %lu\n",
        "RESET_PERIOD (in seconds)", resetPeriod);

    internal_printf("\t%-32s: \n", "REBOOT_MESSAGE");

    char* fCmd = s->failCmd[0] ? Utf16ToUtf8(s->failCmd) : NULL;
    internal_printf("\t%-32s: %s\n",
        "COMMAND_LINE", fCmd ? fCmd : "");

    /* Bonus: description (not in sc output but useful for SA) */
    char* desc = s->description[0] ? Utf16ToUtf8(s->description) : NULL;
    if (desc)
        internal_printf("\t%-32s: %s\n", "DESCRIPTION", desc);

    /* Cleanup */
    if (svcName)  intFree(svcName);
    if (dispName) intFree(dispName);
    if (imgPath)  intFree(imgPath);
    if (grp)      intFree(grp);
    if (objName)  intFree(objName);
    if (fCmd)     intFree(fCmd);
    if (desc)     intFree(desc);
    intFree(s);

    NTDLL$NtClose(hSubkey);
    return TRUE;
}

/* ================================================================
 *  Main enumeration
 * ================================================================ */

static void EnumServices(void)
{
    /* Get process list for STATE/PID matching */
    PVOID pSpiBuffer = GetProcessInfo();

    UNICODE_STRING servicesPath;
    NTDLL$RtlInitUnicodeString(&servicesPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &servicesPath,
        OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hServices = NULL;
    NTSTATUS status = NTDLL$NtOpenKey(&hServices, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        internal_printf("[!] Failed to open Services key: 0x%08lX\n",
            (ULONG)status);
        if (pSpiBuffer) intFree(pSpiBuffer);
        return;
    }

    internal_printf("\n[*] Service Enumeration (Registry + Process Matching)\n");
    internal_printf("======================================================\n");

    BYTE keyInfoBuf[600];
    DWORD total = 0;
    DWORD displayed = 0;

    for (ULONG idx = 0; ; idx++) {
        ULONG resultLen;
        status = NTDLL$NtEnumerateKey(
            hServices, idx, KeyBasicInformation,
            keyInfoBuf, sizeof(keyInfoBuf), &resultLen);

        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
            continue;

        MY_KEY_BASIC_INFO* pKeyInfo = (MY_KEY_BASIC_INFO*)keyInfoBuf;
        ULONG nameLen = pKeyInfo->NameLength / sizeof(WCHAR);

        WCHAR subkeyName[256];
        if (nameLen > 255) nameLen = 255;
        for (ULONG j = 0; j < nameLen; j++)
            subkeyName[j] = pKeyInfo->Name[j];
        subkeyName[nameLen] = L'\0';

        if (PrintServiceDetail(hServices, subkeyName, pSpiBuffer))
            displayed++;

        total++;
        if (total > 2000) break;
    }

    NTDLL$NtClose(hServices);
    if (pSpiBuffer) intFree(pSpiBuffer);

    internal_printf("\n\n[*] Enumerated: %lu services (%lu registry entries)\n",
        displayed, total);
    internal_printf("[*] STATE/PID from process name matching (best-effort)\n");
    internal_printf("[*] Shared-process services (svchost) may show first PID\n");
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    EnumServices();
    printoutput(TRUE);
}
#else
int main()
{
    EnumServices();
    return 0;
}
#endif
