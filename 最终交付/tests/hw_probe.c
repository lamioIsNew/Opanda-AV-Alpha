/* hw_probe.c -- VM 内验证 scanner.dll 的硬件检测导出（仅测试用） */
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>

#define SCANNER_STATIC
#include "scanner_api.h"

typedef int (__cdecl *PFN_HW)(ScannerHardwareInfo *);

int wmain(int argc, wchar_t **argv) {
    const wchar_t *dll = (argc > 1) ? argv[1] : L"scanner.dll";
    HMODULE h = LoadLibraryW(dll);
    PFN_HW f;
    ScannerHardwareInfo info;
    int rc;

    if (!h) {
        wprintf(L"LoadLibraryW(%ls) failed: %lu\n", dll, GetLastError());
        return 1;
    }
    f = (PFN_HW)GetProcAddress(h, "scanner_get_hardware_info");
    if (!f) {
        wprintf(L"scanner_get_hardware_info export missing\n");
        FreeLibrary(h);
        return 2;
    }
    ZeroMemory(&info, sizeof(info));
    rc = f(&info);
    wprintf(L"rc=%d\n", rc);
    wprintf(L"SGX=%u\nPT=%u\nTPM20=%u\nTPM_VERSION=%u\nTPM_IFACE=%u\nHYPERVISOR=%u\n",
            info.sgx, info.pt, info.tpm20, info.tpm_version, info.tpm_interface, info.hypervisor);
    wprintf(L"DETAIL=%hs\n", info.detail);
    FreeLibrary(h);
    return rc;
}
