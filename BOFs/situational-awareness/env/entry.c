#include <windows.h>
#include "bofdefs.h"
#include "base.c"

/*
 * stealthy_env - Dump all environment variables from PEB
 *
 * Walks PEB->ProcessParameters->Environment directly.
 * Zero security-relevant API calls - pure memory reads.
 */

#ifdef _WIN64
#define PARAMS_ENV 0x80
#else
#define PARAMS_ENV 0x48
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

static void EnumEnvironment(void)
{
    PPEB pPeb = GetPeb();
    if (!pPeb || !pPeb->ProcessParameters) {
        internal_printf("[!] Cannot read PEB or ProcessParameters\n");
        return;
    }

    PWSTR pEnv = *(PWSTR*)((PBYTE)pPeb->ProcessParameters + PARAMS_ENV);
    if (!pEnv) {
        internal_printf("[!] Environment block not readable\n");
        return;
    }

    internal_printf("\n[*] Environment Variables (PEB)\n");
    internal_printf("================================\n\n");

    DWORD count = 0;
    while (*pEnv) {
        char* utf8 = Utf16ToUtf8(pEnv);
        if (utf8) {
            internal_printf("  %s\n", utf8);
            intFree(utf8);
        }
        /* Advance past this string's null terminator */
        while (*pEnv) pEnv++;
        pEnv++;
        count++;
        if (count > 1000) break;
    }

    internal_printf("\n  Total: %lu variables\n", count);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) return;
    EnumEnvironment();
    printoutput(TRUE);
}
#else
int main()
{
    EnumEnvironment();
    return 0;
}
#endif
