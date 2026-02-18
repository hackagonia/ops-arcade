#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * peb_whoami - Extended PEB situational awareness BOF
 *
 * Extracts identity, process info, OS version, loaded modules,
 * and debugger detection entirely from the PEB. Zero security-
 * relevant API calls (no GetUserNameEx, OpenProcessToken, etc.).
 *
 * Only MSVCRT/Kernel32 calls used are for output formatting.
 */

/* ================================================================
 *  Architecture-specific offsets for fields not in MinGW headers
 * ================================================================ */

#ifdef _WIN64

/* PEB fields not exposed in MinGW's winternl.h */
#define PEB_IMAGE_BASE          0x10
#define PEB_NT_GLOBAL_FLAG      0xBC
#define PEB_NUM_PROCESSORS      0xB8
#define PEB_OS_MAJOR            0x118
#define PEB_OS_MINOR            0x11C
#define PEB_OS_BUILD            0x120

/* RTL_USER_PROCESS_PARAMETERS: CurrentDir and Environment not in header */
#define PARAMS_CURDIR           0x38
#define PARAMS_ENV              0x80

/* LDR_DATA_TABLE_ENTRY: BaseDllName and SizeOfImage not in header */
#define LDR_SIZE_OF_IMAGE       0x40
#define LDR_BASE_DLL_NAME       0x58

#else /* x86 */

#define PEB_IMAGE_BASE          0x08
#define PEB_NT_GLOBAL_FLAG      0x68
#define PEB_NUM_PROCESSORS      0x64
#define PEB_OS_MAJOR            0xA4
#define PEB_OS_MINOR            0xA8
#define PEB_OS_BUILD            0xAC

#define PARAMS_CURDIR           0x24
#define PARAMS_ENV              0x48

#define LDR_SIZE_OF_IMAGE       0x20
#define LDR_BASE_DLL_NAME       0x2C

#endif

/* NtGlobalFlag bits that indicate debugger-controlled heap */
#define FLG_HEAP_TAIL_CHECK      0x10
#define FLG_HEAP_FREE_CHECK      0x20
#define FLG_HEAP_VALIDATE_PARAMS 0x40

/* ================================================================
 *  Helper functions
 * ================================================================ */

/* Read PEB directly from TEB segment register - GCC inline asm */
static __inline__ PPEB GetPeb(void)
{
    PPEB pPeb;
#ifdef _WIN64
    __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(pPeb));
#else
    __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(pPeb));
#endif
    return pPeb;
}

/* Case-insensitive wide-char string comparison (no API calls) */
static BOOL WStrIEqual(const WCHAR* a, const WCHAR* b)
{
    while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return FALSE;
        a++;
        b++;
    }
    return (*a == *b);
}

/* Case-sensitive prefix match for env key lookup */
static BOOL EnvKeyMatch(const WCHAR* entry, const WCHAR* prefix)
{
    while (*prefix) {
        if (*entry != *prefix) return FALSE;
        entry++;
        prefix++;
    }
    return TRUE;
}

/* Print a UNICODE_STRING field with label */
static void PrintUStr(const char* label, PUNICODE_STRING pStr)
{
    if (pStr && pStr->Buffer && pStr->Length > 0) {
        char* utf8 = Utf16ToUtf8(pStr->Buffer);
        if (utf8) {
            internal_printf("  %-20s %s\n", label, utf8);
            intFree(utf8);
        }
    }
}

/* Find env variable value in the PEB environment block */
static const WCHAR* FindEnvVar(PWSTR pEnv, const WCHAR* key)
{
    if (!pEnv) return NULL;
    while (*pEnv) {
        if (EnvKeyMatch(pEnv, key)) {
            const WCHAR* p = pEnv;
            while (*p && *p != L'=') p++;
            if (*p == L'=') return p + 1;
        }
        while (*pEnv) pEnv++;
        pEnv++;
    }
    return NULL;
}

/* Print an env variable if found */
static void PrintEnvEntry(const char* label, PWSTR pEnv, const WCHAR* key)
{
    const WCHAR* val = FindEnvVar(pEnv, key);
    if (val) {
        char* utf8 = Utf16ToUtf8(val);
        if (utf8) {
            internal_printf("  %-20s %s\n", label, utf8);
            intFree(utf8);
        }
    }
}

/* Tag known security/debugging DLLs for operator awareness */
static const char* CheckKnownDll(const WCHAR* name)
{
    if (!name) return "";

    /* AV / EDR */
    if (WStrIEqual(name, L"amsi.dll"))      return " [AMSI]";
    if (WStrIEqual(name, L"MpClient.dll"))  return " [Defender]";
    if (WStrIEqual(name, L"MpOav.dll"))     return " [Defender]";
    if (WStrIEqual(name, L"mpoav.dll"))     return " [Defender]";

    /* .NET / CLR */
    if (WStrIEqual(name, L"clr.dll"))       return " [.NET CLR]";
    if (WStrIEqual(name, L"clrjit.dll"))    return " [.NET JIT]";
    if (WStrIEqual(name, L"coreclr.dll"))   return " [.NET Core]";
    if (WStrIEqual(name, L"mscorwks.dll"))  return " [.NET 2.0]";

    /* Debug / Analysis */
    if (WStrIEqual(name, L"dbghelp.dll"))   return " [Debug]";
    if (WStrIEqual(name, L"dbgcore.dll"))   return " [Debug]";

    /* Sandbox */
    if (WStrIEqual(name, L"SbieDll.dll"))   return " [Sandboxie]";
    if (WStrIEqual(name, L"sbiedll.dll"))   return " [Sandboxie]";

    /* AV products */
    if (WStrIEqual(name, L"snxhk.dll"))     return " [Avast]";
    if (WStrIEqual(name, L"snxhk64.dll"))   return " [Avast]";
    if (WStrIEqual(name, L"cmdvrt32.dll"))  return " [Comodo]";
    if (WStrIEqual(name, L"cmdvrt64.dll"))  return " [Comodo]";
    if (WStrIEqual(name, L"hmpalert.dll"))  return " [HitmanPro]";

    /* Monitoring */
    if (WStrIEqual(name, L"wpcap.dll"))     return " [WinPcap]";
    if (WStrIEqual(name, L"npcap.dll"))     return " [Npcap]";

    return "";
}

/* ================================================================
 *  Output sections
 * ================================================================ */

static void PrintIdentity(PPEB pPeb)
{
    PRTL_USER_PROCESS_PARAMETERS pParams = pPeb->ProcessParameters;
    PWSTR pEnv = *(PWSTR*)((PBYTE)pParams + PARAMS_ENV);

    internal_printf("[*] Identity (PEB Environment)\n");
    internal_printf("================================\n\n");

    if (!pEnv) {
        internal_printf("  [!] Environment block not readable\n");
        return;
    }

    const WCHAR* username   = FindEnvVar(pEnv, L"USERNAME=");
    const WCHAR* userdomain = FindEnvVar(pEnv, L"USERDOMAIN=");

    if (userdomain && username) {
        char* sDomain = Utf16ToUtf8(userdomain);
        char* sUser   = Utf16ToUtf8(username);
        if (sDomain && sUser)
            internal_printf("  %-20s %s\\%s\n", "User:", sDomain, sUser);
        if (sDomain) intFree(sDomain);
        if (sUser)   intFree(sUser);
    } else {
        PrintEnvEntry("Username:",  pEnv, L"USERNAME=");
        PrintEnvEntry("Domain:",    pEnv, L"USERDOMAIN=");
    }

    PrintEnvEntry("Computer:",     pEnv, L"COMPUTERNAME=");
    PrintEnvEntry("DNS Domain:",   pEnv, L"USERDNSDOMAIN=");
    PrintEnvEntry("Logon Server:", pEnv, L"LOGONSERVER=");
    PrintEnvEntry("User Profile:", pEnv, L"USERPROFILE=");
}

static void PrintProcessInfo(PPEB pPeb)
{
    PRTL_USER_PROCESS_PARAMETERS pParams = pPeb->ProcessParameters;
    PVOID imageBase = *(PVOID*)((PBYTE)pPeb + PEB_IMAGE_BASE);
    PUNICODE_STRING pCurDir = (PUNICODE_STRING)((PBYTE)pParams + PARAMS_CURDIR);

    internal_printf("\n[*] Process Information\n");
    internal_printf("========================\n\n");

    /* ImagePathName and CommandLine are in MinGW's winternl.h */
    PrintUStr("Image Path:", &pParams->ImagePathName);
    PrintUStr("Command Line:", &pParams->CommandLine);

    /* CurrentDirectory requires raw offset */
    PrintUStr("Current Dir:", pCurDir);

    internal_printf("  %-20s 0x%p\n", "Image Base:", imageBase);

#ifdef _WIN64
    internal_printf("  %-20s x64\n", "Architecture:");
#else
    internal_printf("  %-20s x86\n", "Architecture:");
#endif
}

static void PrintOsInfo(PPEB pPeb)
{
    PBYTE p = (PBYTE)pPeb;
    ULONG  osMajor = *(PULONG)(p + PEB_OS_MAJOR);
    ULONG  osMinor = *(PULONG)(p + PEB_OS_MINOR);
    USHORT osBuild = *(PUSHORT)(p + PEB_OS_BUILD);
    ULONG  nProcs  = *(PULONG)(p + PEB_NUM_PROCESSORS);

    internal_printf("\n[*] OS Information\n");
    internal_printf("====================\n\n");

    internal_printf("  %-20s %lu.%lu.%hu\n", "Version:", osMajor, osMinor, osBuild);

    /* Friendly name heuristic */
    if (osMajor == 10 && osBuild >= 22000)
        internal_printf("  %-20s Windows 11\n", "Product:");
    else if (osMajor == 10)
        internal_printf("  %-20s Windows 10\n", "Product:");
    else
        internal_printf("  %-20s Windows %lu.%lu\n", "Product:", osMajor, osMinor);

    internal_printf("  %-20s %lu\n", "Processors:", nProcs);
    internal_printf("  %-20s %lu\n", "Session ID:", pPeb->SessionId);
}

static void PrintSecurityChecks(PPEB pPeb)
{
    PBYTE p = (PBYTE)pPeb;
    BYTE  beingDebugged = pPeb->BeingDebugged;
    ULONG ntGlobalFlag  = *(PULONG)(p + PEB_NT_GLOBAL_FLAG);

    internal_printf("\n[*] Security / Debug Detection\n");
    internal_printf("================================\n\n");

    internal_printf("  %-20s %s\n", "BeingDebugged:",
        beingDebugged ? "TRUE  <-- Debugger attached!" : "FALSE");

    internal_printf("  %-20s 0x%08lX", "NtGlobalFlag:", ntGlobalFlag);
    if (ntGlobalFlag & (FLG_HEAP_TAIL_CHECK | FLG_HEAP_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMS))
        internal_printf("  <-- Debug heap flags (0x70)");
    internal_printf("\n");

    /* Decode individual flags if set */
    if (ntGlobalFlag & FLG_HEAP_TAIL_CHECK)
        internal_printf("  %-20s FLG_HEAP_ENABLE_TAIL_CHECK\n", "");
    if (ntGlobalFlag & FLG_HEAP_FREE_CHECK)
        internal_printf("  %-20s FLG_HEAP_ENABLE_FREE_CHECK\n", "");
    if (ntGlobalFlag & FLG_HEAP_VALIDATE_PARAMS)
        internal_printf("  %-20s FLG_HEAP_VALIDATE_PARAMETERS\n", "");
}

static void PrintLoadedModules(PPEB pPeb)
{
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) {
        internal_printf("\n[!] PEB->Ldr is NULL\n");
        return;
    }

    PLIST_ENTRY pHead  = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    DWORD count = 0;
    DWORD flagged = 0;

    internal_printf("\n[*] Loaded Modules (PEB->Ldr)\n");
    internal_printf("================================\n\n");
    internal_printf("  %-36s %-18s %-12s %s\n",
        "Module", "Base", "Size", "Notes");
    internal_printf("  %-36s %-18s %-12s %s\n",
        "------", "----", "----", "-----");

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(
            pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        /* BaseDllName not in MinGW header - use raw offset */
        PUNICODE_STRING pBaseName =
            (PUNICODE_STRING)((PBYTE)pMod + LDR_BASE_DLL_NAME);
        ULONG imageSize =
            *(PULONG)((PBYTE)pMod + LDR_SIZE_OF_IMAGE);

        if (pBaseName->Buffer && pBaseName->Length > 0) {
            char* name = Utf16ToUtf8(pBaseName->Buffer);
            if (name) {
                const char* tag = CheckKnownDll(pBaseName->Buffer);
                internal_printf("  %-36s 0x%-16p 0x%08lX %s\n",
                    name, pMod->DllBase, imageSize, tag);
                if (tag[0] != '\0') flagged++;
                intFree(name);
            }
        }

        count++;
        pEntry = pEntry->Flink;

        /* Prevent infinite loop on corrupted list */
        if (count > 500) break;
    }

    internal_printf("\n  Total: %lu modules", count);
    if (flagged > 0)
        internal_printf(" (%lu flagged)", flagged);
    internal_printf("\n");
}

/* ================================================================
 *  Entry points
 * ================================================================ */

int PebRecon(void)
{
    PPEB pPeb = GetPeb();
    if (!pPeb) {
        internal_printf("[!] Failed to read PEB\n");
        return 1;
    }

    if (!pPeb->ProcessParameters) {
        internal_printf("[!] PEB->ProcessParameters is NULL\n");
        return 1;
    }

    internal_printf("\n==========================================\n");
    internal_printf("  PEB Recon - Zero Security API Calls\n");
    internal_printf("==========================================\n\n");

    PrintIdentity(pPeb);
    PrintProcessInfo(pPeb);
    PrintOsInfo(pPeb);
    PrintSecurityChecks(pPeb);
    PrintLoadedModules(pPeb);

    internal_printf("\n");
    return 0;
}

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    if (!bofstart())
        return;
    PebRecon();
    printoutput(TRUE);
}
#else
int main()
{
    PebRecon();
    return 0;
}
#endif
