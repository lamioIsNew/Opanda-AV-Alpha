/* qtn_tpm_test.cpp -- benign test for QTNA (AES-256-GCM + TPM) and legacy QTN1 */
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

#include "qtn_crypto.h"

static bool write_file(const std::wstring &p, const std::vector<unsigned char> &d) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    BOOL ok = WriteFile(h, d.data(), (DWORD)d.size(), &put, NULL);
    CloseHandle(h);
    return ok && put == d.size();
}

static bool read_file(const std::wstring &p, std::vector<unsigned char> &d) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    GetFileSizeEx(h, &li);
    d.resize((size_t)li.QuadPart);
    DWORD got = 0;
    BOOL ok = d.empty() || ReadFile(h, d.data(), (DWORD)d.size(), &got, NULL);
    CloseHandle(h);
    return ok && got == d.size();
}

static bool same_file(const std::wstring &a, const std::wstring &b) {
    std::vector<unsigned char> x, y;
    if (!read_file(a, x) || !read_file(b, y)) return false;
    return x.size() == y.size() && (x.empty() || memcmp(x.data(), y.data(), x.size()) == 0);
}

int wmain(int argc, wchar_t **argv) {
    wchar_t tmp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tmp)) return 1;
    std::wstring src = std::wstring(tmp) + L"qtn_tpm_plain.bin";
    std::wstring enc = std::wstring(tmp) + L"qtn_tpm_test.qtn";
    std::wstring dec = std::wstring(tmp) + L"qtn_tpm_dec.bin";
    std::wstring err;

    size_t size = (argc > 1) ? (size_t)_wtoi(argv[1]) : 1024 * 1024;
    if (size == 0) size = 1024 * 1024;
    std::vector<unsigned char> plain(size);
    NTSTATUS st = BCryptGenRandom(NULL, plain.data(), (ULONG)plain.size(),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) { wprintf(L"BCryptGenRandom failed: 0x%08X\n", (unsigned)st); return 2; }
    if (!write_file(src, plain)) { wprintf(L"write plain failed\n"); return 2; }

    wprintf(L"sgx_cpu=%d sgx_available=%d set_sgx=%d mode=%d\n",
            qtn_sgx_cpu_support(), qtn_sgx_available(),
            qtn_set_key_mode(1), qtn_get_key_mode());
    qtn_set_key_mode(0);

    DeleteFileW(enc.c_str());
    DeleteFileW(dec.c_str());

    if (!qtn_encrypt_file(src, enc, err)) {
        wprintf(L"encrypt failed: %ls\n", err.c_str());
        return 3;
    }
    wprintf(L"encrypted: %ls (%zu -> ", enc.c_str(), plain.size());
    std::vector<unsigned char> e;
    read_file(enc, e);
    wprintf(L"%zu bytes)\n", e.size());
    if (e.size() < 4 || memcmp(e.data(), "QTNA", 4) != 0) {
        wprintf(L"bad magic\n");
        return 4;
    }
    if (!qtn_is_encrypted(enc)) { wprintf(L"qtn_is_encrypted failed\n"); return 5; }

    if (!qtn_decrypt_file(enc, dec, err)) {
        wprintf(L"decrypt failed: %ls\n", err.c_str());
        return 6;
    }
    if (!same_file(src, dec)) { wprintf(L"round-trip mismatch\n"); return 7; }
    wprintf(L"round-trip OK (TPM + AES-256-GCM)\n");

    /* legacy QTN1 (XOR 0x5A) compatibility */
    {
        std::vector<unsigned char> legacy(32 + plain.size());
        memcpy(legacy.data(), "QTN1", 4);
        unsigned int ver = 1, flags = 1;
        unsigned long long len = plain.size();
        memcpy(legacy.data() + 4, &ver, 4);
        memcpy(legacy.data() + 8, &flags, 4);
        memcpy(legacy.data() + 12, &len, 8);
        for (size_t i = 0; i < plain.size(); i++) legacy[32 + i] = plain[i] ^ 0x5A;
        std::wstring leg = std::wstring(tmp) + L"qtn_legacy.qtn";
        std::wstring legout = std::wstring(tmp) + L"qtn_legacy_out.bin";
        write_file(leg, legacy);
        if (!qtn_decrypt_file(leg, legout, err)) {
            wprintf(L"legacy decrypt failed: %ls\n", err.c_str());
            return 8;
        }
        if (!same_file(src, legout)) { wprintf(L"legacy mismatch\n"); return 9; }
        wprintf(L"legacy QTN1 OK\n");
        DeleteFileW(leg.c_str());
        DeleteFileW(legout.c_str());
    }

    DeleteFileW(src.c_str());
    DeleteFileW(enc.c_str());
    DeleteFileW(dec.c_str());
    wprintf(L"ALL OK\n");
    return 0;
}
