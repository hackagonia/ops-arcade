#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * stealthy_listmods - Enumerate loaded modules from PEB
 *
 * Walks PEB->Ldr->InMemoryOrderModuleList directly.
 * Zero security-relevant API calls - no CreateToolhelp32Snapshot,
 * no EnumProcessModules. Pure PEB memory reads.
 */

#ifdef _WIN64
#define LDR_SIZE_OF_IMAGE  0x40
#define LDR_FULL_DLL_NAME  0x48
#define LDR_BASE_DLL_NAME  0x58
#else
#define LDR_SIZE_OF_IMAGE  0x20
#define LDR_FULL_DLL_NAME  0x24
#define LDR_BASE_DLL_NAME  0x2C
#endif

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

/* Case-insensitive wide-char comparison */
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

/* Tag known security/analysis DLLs */
static const char* CheckKnownDll(const WCHAR* name)
{
    if (!name) return "";
    if (WStrIEqual(name, L"amsi.dll"))      return " [AMSI]";
    if (WStrIEqual(name, L"MpClient.dll"))  return " [Defender]";
    if (WStrIEqual(name, L"MpOav.dll"))     return " [Defender]";
    if (WStrIEqual(name, L"clr.dll"))       return " [.NET CLR]";
    if (WStrIEqual(name, L"clrjit.dll"))    return " [.NET JIT]";
    if (WStrIEqual(name, L"coreclr.dll"))   return " [.NET Core]";
    if (WStrIEqual(name, L"dbghelp.dll"))   return " [Debug]";
    if (WStrIEqual(name, L"dbgcore.dll"))   return " [Debug]";
    if (WStrIEqual(name, L"SbieDll.dll"))   return " [Sandboxie]";
    if (WStrIEqual(name, L"snxhk.dll"))     return " [Avast]";
    if (WStrIEqual(name, L"snxhk64.dll"))   return " [Avast]";
    if (WStrIEqual(name, L"cmdvrt32.dll"))  return " [Comodo]";
    if (WStrIEqual(name, L"cmdvrt64.dll"))  return " [Comodo]";
    if (WStrIEqual(name, L"hmpalert.dll"))  return " [HitmanPro]";
    return "";
}

static void ListModules(void)
{
    PPEB pPeb = GetPeb();
    if (!pPeb) {
        internal_printf("[!] Cannot read PEB\n");
        return;
    }

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) {
        internal_printf("[!] PEB->Ldr is NULL\n");
        return;
    }

    PLIST_ENTRY pHead  = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    DWORD count = 0;
    DWORD flagged = 0;

    internal_printf("\n[*] Loaded Modules (PEB->Ldr)\n");
    internal_printf("==============================\n\n");
    internal_printf("  %-32s %-18s %-12s %s\n",
        "Module", "Base", "Size", "Notes / Path");
    internal_printf("  %-32s %-18s %-12s %s\n",
        "------", "----", "----", "------------");

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(
            pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        PUNICODE_STRING pBaseName =
            (PUNICODE_STRING)((PBYTE)pMod + LDR_BASE_DLL_NAME);
        PUNICODE_STRING pFullName =
            (PUNICODE_STRING)((PBYTE)pMod + LDR_FULL_DLL_NAME);
        ULONG imageSize =
            *(PULONG)((PBYTE)pMod + LDR_SIZE_OF_IMAGE);

        char* baseName = NULL;
        char* fullName = NULL;

        if (pBaseName->Buffer && pBaseName->Length > 0)
            baseName = Utf16ToUtf8(pBaseName->Buffer);
        if (pFullName->Buffer && pFullName->Length > 0)
            fullName = Utf16ToUtf8(pFullName->Buffer);

        const char* tag = CheckKnownDll(
            pBaseName->Buffer && pBaseName->Length > 0 ?
            pBaseName->Buffer : NULL);

        if (tag[0] != '\0') {
            internal_printf("  %-32s 0x%-16p 0x%08lX %s\n",
                baseName ? baseName : "(unknown)",
                pMod->DllBase, imageSize, tag);
            flagged++;
        } else {
            internal_printf("  %-32s 0x%-16p 0x%08lX %s\n",
                baseName ? baseName : "(unknown)",
                pMod->DllBase, imageSize,
                fullName ? fullName : "");
        }

        if (baseName) intFree(baseName);
        if (fullName) intFree(fullName);

        count++;
        pEntry = pEntry->Flink;
        if (count > 500) break;
    }

    internal_printf("\n  Total: %lu modules", count);
    if (flagged > 0)
        internal_printf(" (%lu flagged)", flagged);
    internal_printf("\n");
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    ListModules();
    printoutput(TRUE);
}
#else
int main()
{
    ListModules();
    return 0;
}
#endif
