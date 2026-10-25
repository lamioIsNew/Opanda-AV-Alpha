/* qtn_crypto.cpp -- QTN 隔离文件加密实现
 *
 * 设计：
 *   · 每个文件随机生成 32 字节 AES-256 数据密钥 + 12 字节 GCM nonce；
 *   · 默认用 TPM 内持久化 RSA-2048 公钥做 RSA-OAEP(SHA-256) 封装；
 *   · 可选 SGX sealed key（默认关闭，需 CPU + SDK + enclave DLL）；
 *   · 封装后的密钥写入 QTN 头；TPM 私钥不出芯片；
 *   · 文件载荷用 AES-256-GCM 加密，GCM tag 校验完整性；
 *   · 旧 QTN1（XOR 0x5A）仍可解密。
 *
 * TPM 键名：OpandaQtnKey（Microsoft Platform Crypto Provider）。
 * 如果 TPM 被清除/键被删除，已有隔离文件将无法恢复——这是 TPM 绑定的预期代价。
 */
#include "qtn_crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

namespace {

const unsigned char kAesMagic[4] = {'Q', 'T', 'N', 'A'};
const unsigned char kXorMagic[4] = {'Q', 'T', 'N', '1'};
const unsigned kAesVersion = 2;
const unsigned kFlagAes = 1;           /* bit0=AES-256-GCM */
const unsigned kFlagTpm = 2;           /* bit1=TPM RSA-OAEP */
const unsigned kFlagSgx = 4;           /* bit2=SGX sealed key */
const size_t kNonceLen = 12;
const size_t kTagLen = 16;
const size_t kAesHeader = 56;
const unsigned long long kMaxPlain = 512ull * 1024ull * 1024ull;
const wchar_t *kKeyName = L"OpandaQtnKey";

std::mutex g_tpm_lock;
NCRYPT_PROV_HANDLE g_tpm_prov = 0;
NCRYPT_KEY_HANDLE g_tpm_key = 0;
std::atomic<int> g_key_mode{0};   /* 0=TPM, 1=SGX */
std::atomic<int> g_sgx_state{-1}; /* -1=未检测, 0=不可用, 1=可用 */

#ifdef OPANDA_WITH_SGX
typedef HRESULT (WINAPI *PFN_SGX_SEAL)(const BYTE *, DWORD, BYTE *, DWORD *);
typedef HRESULT (WINAPI *PFN_SGX_UNSEAL)(const BYTE *, DWORD, BYTE *, DWORD *);
std::mutex g_sgx_lock;
HMODULE g_sgx_mod = NULL;
PFN_SGX_SEAL g_sgx_seal = NULL;
PFN_SGX_UNSEAL g_sgx_unseal = NULL;
#endif

std::wstring win32_error(DWORD e) {
    wchar_t *buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, e, 0, (LPWSTR)&buf, 0, NULL);
    if (n && buf) {
        std::wstring s(buf, n);
        while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' ')) s.pop_back();
        LocalFree(buf);
        return s;
    }
    wchar_t b[64];
    swprintf(b, 64, L"错误码 %lu", (unsigned long)e);
    return b;
}

std::wstring nt_error(const wchar_t *what, LONG st) {
    wchar_t b[192];
    swprintf(b, 192, L"%ls 失败（0x%08X）", what, (unsigned)st);
    return b;
}

bool read_all(const std::wstring &path, std::vector<unsigned char> &out,
              std::wstring &err, unsigned long long cap) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"打开文件失败：" + win32_error(GetLastError());
        return false;
    }
    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li)) {
        err = L"读取文件大小失败：" + win32_error(GetLastError());
        CloseHandle(h);
        return false;
    }
    if (li.QuadPart < 0 || (unsigned long long)li.QuadPart > cap) {
        err = L"文件超过隔离加密上限（512 MB）";
        CloseHandle(h);
        return false;
    }
    try {
        out.resize((size_t)li.QuadPart);
    } catch (...) {
        err = L"内存不足，无法读取隔离文件";
        CloseHandle(h);
        return false;
    }
    size_t done = 0;
    while (done < out.size()) {
        DWORD want = (DWORD)std::min<size_t>(out.size() - done, 1u << 20);
        DWORD got = 0;
        if (!ReadFile(h, out.data() + done, want, &got, NULL) || got == 0) {
            err = L"读取文件失败：" + win32_error(GetLastError());
            CloseHandle(h);
            return false;
        }
        done += got;
    }
    CloseHandle(h);
    return true;
}

bool write_exact(HANDLE h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    while (len) {
        DWORD want = (DWORD)std::min<size_t>(len, 1u << 20);
        DWORD put = 0;
        if (!WriteFile(h, p, want, &put, NULL) || put == 0) return false;
        p += put;
        len -= put;
    }
    return true;
}

bool write_file(const std::wstring &path, const unsigned char *data, size_t len,
                std::wstring &err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"创建文件失败：" + win32_error(GetLastError());
        return false;
    }
    bool ok = write_exact(h, data, len);
    if (ok) FlushFileBuffers(h);
    else err = L"写入文件失败：" + win32_error(GetLastError());
    CloseHandle(h);
    if (!ok) DeleteFileW(path.c_str());
    return ok;
}

int qtn_magic(const std::wstring &path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    unsigned char m[4] = {0};
    DWORD got = 0;
    BOOL ok = ReadFile(h, m, 4, &got, NULL);
    CloseHandle(h);
    if (!ok || got != 4) return 0;
    if (memcmp(m, kXorMagic, 4) == 0) return 1;
    if (memcmp(m, kAesMagic, 4) == 0) return 2;
    return 0;
}

/* ---------------- TPM: 持久化 RSA 键 + RSA-OAEP 包装 ---------------- */

bool tpm_open_locked(std::wstring &err) {
    if (g_tpm_key) return true;
    if (!g_tpm_prov) {
        SECURITY_STATUS st = NCryptOpenStorageProvider(&g_tpm_prov,
                                                       MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
        if (st != ERROR_SUCCESS || !g_tpm_prov) {
            err = L"TPM 2.0 不可用（Microsoft Platform Crypto Provider 打开失败）：" +
                  nt_error(L"NCryptOpenStorageProvider", st);
            return false;
        }
    }

    SECURITY_STATUS st = NCryptOpenKey(g_tpm_prov, &g_tpm_key, kKeyName, 0, 0);
    if (st == ERROR_SUCCESS && g_tpm_key) return true;

    /* 键不存在：在 TPM 中创建持久化 RSA-2048。 */
    NCRYPT_KEY_HANDLE key = 0;
    st = NCryptCreatePersistedKey(g_tpm_prov, &key, NCRYPT_RSA_ALGORITHM,
                                  kKeyName, 0, 0);
    if (st == ERROR_SUCCESS && key) {
        DWORD bits = 2048;
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
        st = NCryptFinalizeKey(key, 0);
        if (st == ERROR_SUCCESS) {
            g_tpm_key = key;
            return true;
        }
        NCryptFreeObject(key);
    }

    /* 可能是并发创建/权限问题，再打开一次。 */
    st = NCryptOpenKey(g_tpm_prov, &g_tpm_key, kKeyName, 0, 0);
    if (st == ERROR_SUCCESS && g_tpm_key) return true;

    err = L"无法创建/打开 TPM 隔离密钥 OpandaQtnKey：" +
          nt_error(L"NCryptCreatePersistedKey", st);
    return false;
}

bool tpm_wrap(const unsigned char *aes_key, DWORD aes_len,
              std::vector<unsigned char> &wrapped, std::wstring &err) {
    std::lock_guard<std::mutex> lk(g_tpm_lock);
    if (!tpm_open_locked(err)) return false;

    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    DWORD out_len = 0;
    SECURITY_STATUS st = NCryptEncrypt(g_tpm_key, (PBYTE)aes_key, aes_len, &oaep,
                                       NULL, 0, &out_len, NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || out_len == 0) {
        err = L"TPM 封装 AES 密钥失败：" + nt_error(L"NCryptEncrypt", st);
        return false;
    }
    try {
        wrapped.resize(out_len);
    } catch (...) {
        err = L"内存不足（TPM 封装密钥）";
        return false;
    }
    st = NCryptEncrypt(g_tpm_key, (PBYTE)aes_key, aes_len, &oaep,
                       wrapped.data(), out_len, &out_len, NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS) {
        err = L"TPM 封装 AES 密钥失败：" + nt_error(L"NCryptEncrypt", st);
        return false;
    }
    wrapped.resize(out_len);
    return true;
}

bool tpm_unwrap(const unsigned char *wrapped, DWORD wrapped_len,
                std::vector<unsigned char> &aes_key, std::wstring &err) {
    std::lock_guard<std::mutex> lk(g_tpm_lock);
    if (!tpm_open_locked(err)) return false;

    BCRYPT_OAEP_PADDING_INFO oaep = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    DWORD out_len = 0;
    SECURITY_STATUS st = NCryptDecrypt(g_tpm_key, (PBYTE)wrapped, wrapped_len, &oaep,
                                       NULL, 0, &out_len, NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || out_len == 0) {
        err = L"TPM 解封 AES 密钥失败：" + nt_error(L"NCryptDecrypt", st);
        return false;
    }
    /* 第一次调用返回的是 RSA 输出缓冲区大小（通常 256），不是明文长度。 */
    try {
        aes_key.resize(out_len);
    } catch (...) {
        err = L"内存不足（TPM 解封密钥）";
        return false;
    }
    st = NCryptDecrypt(g_tpm_key, (PBYTE)wrapped, wrapped_len, &oaep,
                       aes_key.data(), out_len, &out_len, NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || out_len != 32) {
        wchar_t b[64];
        swprintf(b, 64, L"（返回 %lu 字节）", (unsigned long)out_len);
        err = L"TPM 解封 AES 密钥失败：" + nt_error(L"NCryptDecrypt", st) + b;
        return false;
    }
    aes_key.resize(out_len);
    return true;
}

/* ---------------- SGX 可选后端 ----------------
 *
 * 默认不启用。只有同时满足：
 *   1. CPUID.(EAX=7,ECX=0):EBX[2] = 1；
 *   2. 构建时定义 OPANDA_WITH_SGX；
 *   3. 同目录存在 qtn_sgx_enclave.dll，且导出 QtnSgxSeal/QtnSgxUnseal；
 * 才会把“SGX”选项视为可用。
 *
 * enclave DLL 的 ABI：
 *   HRESULT QtnSgxSeal(const BYTE* key, DWORD keyLen, BYTE* sealed, DWORD* sealedLen);
 *   HRESULT QtnSgxUnseal(const BYTE* sealed, DWORD sealedLen, BYTE* key, DWORD* keyLen);
 * 第一次调用传 sealed=NULL / *sealedLen=0 获取所需长度。
 */
bool sgx_cpu_support_impl(void) {
    int r[4];
    __cpuid(r, 0);
    if ((unsigned)r[0] < 7) return false;
    __cpuidex(r, 7, 0);
    return (((unsigned)r[1] >> 2) & 1u) != 0;
}

bool sgx_load_backend(void) {
#ifdef OPANDA_WITH_SGX
    std::lock_guard<std::mutex> lk(g_sgx_lock);
    if (g_sgx_mod) return g_sgx_seal && g_sgx_unseal;
    HMODULE m = LoadLibraryW(L"qtn_sgx_enclave.dll");
    if (!m) return false;
    g_sgx_seal = (PFN_SGX_SEAL)GetProcAddress(m, "QtnSgxSeal");
    g_sgx_unseal = (PFN_SGX_UNSEAL)GetProcAddress(m, "QtnSgxUnseal");
    if (!g_sgx_seal || !g_sgx_unseal) {
        FreeLibrary(m);
        g_sgx_seal = NULL;
        g_sgx_unseal = NULL;
        return false;
    }
    g_sgx_mod = m;
    return true;
#else
    return false;
#endif
}

bool sgx_seal_key(const unsigned char *key, DWORD key_len,
                  std::vector<unsigned char> &sealed, std::wstring &err) {
    if (!qtn_sgx_available()) {
        err = L"SGX 不可用：CPU 不支持、未编译 SGX 后端，或缺少 qtn_sgx_enclave.dll";
        return false;
    }
#ifdef OPANDA_WITH_SGX
    std::lock_guard<std::mutex> lk(g_sgx_lock);
    if (!g_sgx_seal) { err = L"SGX enclave 未加载"; return false; }
    DWORD out_len = 0;
    HRESULT hr = g_sgx_seal(key, key_len, NULL, &out_len);
    if (FAILED(hr) || out_len == 0) {
        wchar_t b[64]; swprintf(b, 64, L"0x%08X", (unsigned)hr);
        err = L"SGX 封装密钥失败（" + std::wstring(b) + L"）";
        return false;
    }
    sealed.resize(out_len);
    hr = g_sgx_seal(key, key_len, sealed.data(), &out_len);
    if (FAILED(hr)) {
        wchar_t b[64]; swprintf(b, 64, L"0x%08X", (unsigned)hr);
        err = L"SGX 封装密钥失败（" + std::wstring(b) + L"）";
        return false;
    }
    sealed.resize(out_len);
    return true;
#else
    err = L"SGX 后端未编译：需要 Intel SGX SDK、enclave 与 qtn_sgx_enclave.dll";
    return false;
#endif
}

bool sgx_unseal_key(const unsigned char *sealed, DWORD sealed_len,
                    std::vector<unsigned char> &key, std::wstring &err) {
    if (!qtn_sgx_available()) {
        err = L"SGX 不可用：CPU 不支持、未编译 SGX 后端，或缺少 qtn_sgx_enclave.dll";
        return false;
    }
#ifdef OPANDA_WITH_SGX
    std::lock_guard<std::mutex> lk(g_sgx_lock);
    if (!g_sgx_unseal) { err = L"SGX enclave 未加载"; return false; }
    DWORD out_len = 0;
    HRESULT hr = g_sgx_unseal(sealed, sealed_len, NULL, &out_len);
    if (FAILED(hr) || out_len != 32) {
        wchar_t b[64]; swprintf(b, 64, L"0x%08X", (unsigned)hr);
        err = L"SGX 解封密钥失败（" + std::wstring(b) + L"）";
        return false;
    }
    key.resize(out_len);
    hr = g_sgx_unseal(sealed, sealed_len, key.data(), &out_len);
    if (FAILED(hr) || out_len != 32) {
        wchar_t b[64]; swprintf(b, 64, L"0x%08X", (unsigned)hr);
        err = L"SGX 解封密钥失败（" + std::wstring(b) + L"）";
        return false;
    }
    key.resize(out_len);
    return true;
#else
    err = L"SGX 后端未编译：需要 Intel SGX SDK、enclave 与 qtn_sgx_enclave.dll";
    return false;
#endif
}

/* ---------------- AES-256-GCM ---------------- */

bool aes_gcm(bool encrypt, const unsigned char *aes_key,
             const unsigned char *nonce, const unsigned char *aad, size_t aad_len,
             const unsigned char *in, size_t in_len,
             unsigned char *out, size_t out_cap, size_t &out_len,
             unsigned char *tag, std::wstring &err) {
    BCRYPT_ALG_HANDLE prov = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    bool ok = false;

    if (in_len > 0xFFFFFFFFull) { err = L"AES-GCM 输入过大"; return false; }

    NTSTATUS st = BCryptOpenAlgorithmProvider(&prov, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0 || !prov) { err = nt_error(L"BCryptOpenAlgorithmProvider", st); return false; }

    st = BCryptSetProperty(prov, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) { err = nt_error(L"BCryptSetProperty(GCM)", st); goto done; }

    st = BCryptGenerateSymmetricKey(prov, &key, NULL, 0,
                                    (PUCHAR)aes_key, 32, 0);
    if (st != 0 || !key) { err = nt_error(L"BCryptGenerateSymmetricKey", st); goto done; }

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = (PUCHAR)nonce;
        auth.cbNonce = (ULONG)kNonceLen;
        auth.pbAuthData = (PUCHAR)aad;
        auth.cbAuthData = (ULONG)aad_len;
        auth.pbTag = (PUCHAR)tag;
        auth.cbTag = (ULONG)kTagLen;

        ULONG produced = 0;
        if (encrypt) {
            st = BCryptEncrypt(key, (PUCHAR)in, (ULONG)in_len, &auth,
                               NULL, 0, out, (ULONG)out_cap, &produced, 0);
        } else {
            st = BCryptDecrypt(key, (PUCHAR)in, (ULONG)in_len, &auth,
                               NULL, 0, out, (ULONG)out_cap, &produced, 0);
        }
        if (st != 0) {
            if (st == (NTSTATUS)0xC000A002L)
                err = L"AES-GCM 认证失败：TPM 密钥不匹配或文件被篡改";
            else
                err = nt_error(encrypt ? L"BCryptEncrypt" : L"BCryptDecrypt", st);
            goto done;
        }
        out_len = produced;
    }
    ok = true;

done:
    if (key) BCryptDestroyKey(key);
    if (prov) BCryptCloseAlgorithmProvider(prov, 0);
    return ok;
}

void secure_zero(void *p, size_t n) {
    if (p && n) SecureZeroMemory(p, n);
}

/* ---------------- 文件格式 ---------------- */

bool encrypt_qtn(const std::vector<unsigned char> &plain,
                 const std::wstring &dst, std::wstring &err) {
    unsigned char aes_key[32];
    unsigned char nonce[kNonceLen];
    unsigned char tag[kTagLen];

    NTSTATUS st = BCryptGenRandom(NULL, aes_key, sizeof(aes_key),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) { err = nt_error(L"BCryptGenRandom(AES key)", st); return false; }
    st = BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) { secure_zero(aes_key, sizeof(aes_key)); err = nt_error(L"BCryptGenRandom(nonce)", st); return false; }

    std::vector<unsigned char> wrapped;
    const unsigned backend = (g_key_mode.load() == 1) ? kFlagSgx : kFlagTpm;
    bool wrapped_ok = (backend == kFlagSgx)
                          ? sgx_seal_key(aes_key, sizeof(aes_key), wrapped, err)
                          : tpm_wrap(aes_key, sizeof(aes_key), wrapped, err);
    if (!wrapped_ok) {
        secure_zero(aes_key, sizeof(aes_key));
        return false;
    }
    if (wrapped.size() > 1024) {
        secure_zero(aes_key, sizeof(aes_key));
        err = L"TPM 封装密钥长度异常";
        return false;
    }

    const uint32_t version = kAesVersion;
    const uint32_t flags = kFlagAes | backend;
    const uint64_t plain_len = (uint64_t)plain.size();
    const uint32_t wrapped_len = (uint32_t)wrapped.size();
    const uint32_t reserved = 0;

    std::vector<unsigned char> header(kAesHeader + wrapped.size(), 0);
    memcpy(header.data(), kAesMagic, 4);
    memcpy(header.data() + 4, &version, 4);
    memcpy(header.data() + 8, &flags, 4);
    memcpy(header.data() + 12, nonce, kNonceLen);
    /* tag at 24 remains zero for AAD */
    memcpy(header.data() + 40, &plain_len, 8);
    memcpy(header.data() + 48, &wrapped_len, 4);
    memcpy(header.data() + 52, &reserved, 4);
    memcpy(header.data() + kAesHeader, wrapped.data(), wrapped.size());

    std::vector<unsigned char> cipher(plain.size());
    size_t cipher_len = 0;
    bool ok = aes_gcm(true, aes_key, nonce, header.data(), header.size(),
                      plain.data(), plain.size(), cipher.data(), cipher.size(),
                      cipher_len, tag, err);
    secure_zero(aes_key, sizeof(aes_key));
    if (!ok) return false;
    if (cipher_len != plain.size()) { err = L"AES-GCM 输出长度异常"; return false; }

    memcpy(header.data() + 24, tag, kTagLen);

    HANDLE h = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        err = L"创建隔离文件失败：" + win32_error(GetLastError());
        return false;
    }
    bool write_ok = write_exact(h, header.data(), header.size()) &&
                    write_exact(h, cipher.data(), cipher.size());
    if (write_ok) FlushFileBuffers(h);
    else err = L"写入隔离文件失败：" + win32_error(GetLastError());
    CloseHandle(h);
    if (!write_ok) {
        DeleteFileW(dst.c_str());
        return false;
    }
    return true;
}

bool decrypt_qtn_aes(const std::vector<unsigned char> &blob,
                     const std::wstring &dst, std::wstring &err) {
    if (blob.size() < kAesHeader) { err = L"QTNA 文件头不完整"; return false; }
    uint32_t version = 0, flags = 0, wrapped_len = 0, reserved = 0;
    uint64_t plain_len = 0;
    memcpy(&version, blob.data() + 4, 4);
    memcpy(&flags, blob.data() + 8, 4);
    memcpy(&plain_len, blob.data() + 40, 8);
    memcpy(&wrapped_len, blob.data() + 48, 4);
    memcpy(&reserved, blob.data() + 52, 4);
    (void)reserved;
    if (version != kAesVersion) { err = L"不支持的 QTNA 版本"; return false; }
    if ((flags & kFlagAes) == 0) { err = L"QTNA 不是 AES-GCM 格式"; return false; }
    bool use_tpm = (flags & kFlagTpm) != 0;
    bool use_sgx = (flags & kFlagSgx) != 0;
    if (use_tpm == use_sgx) { err = L"QTNA 密钥后端标志无效"; return false; }
    if (wrapped_len == 0 || wrapped_len > 1024) { err = L"QTNA 封装密钥长度异常"; return false; }
    if (blob.size() != kAesHeader + (size_t)wrapped_len + (size_t)plain_len) {
        err = L"QTNA 文件长度与头部不一致";
        return false;
    }

    std::vector<unsigned char> wrapped(blob.begin() + kAesHeader,
                                       blob.begin() + kAesHeader + wrapped_len);
    std::vector<unsigned char> aes_key;
    bool key_ok = use_sgx
                      ? sgx_unseal_key(wrapped.data(), wrapped_len, aes_key, err)
                      : tpm_unwrap(wrapped.data(), wrapped_len, aes_key, err);
    if (!key_ok) return false;

    std::vector<unsigned char> header(blob.begin(), blob.begin() + kAesHeader + wrapped_len);
    unsigned char tag[kTagLen];
    memcpy(tag, header.data() + 24, kTagLen);
    memset(header.data() + 24, 0, kTagLen);   /* AAD 中 tag 为 0 */

    const unsigned char *cipher = blob.data() + kAesHeader + wrapped_len;
    std::vector<unsigned char> plain((size_t)plain_len);
    size_t out_len = 0;
    bool ok = aes_gcm(false, aes_key.data(), header.data() + 12,
                      header.data(), header.size(),
                      cipher, (size_t)plain_len,
                      plain.data(), plain.size(), out_len, tag, err);
    secure_zero(aes_key.data(), aes_key.size());
    if (!ok) return false;
    if (out_len != plain_len) { err = L"AES-GCM 解密长度异常"; return false; }

    return write_file(dst, plain.data(), plain.size(), err);
}

bool decrypt_qtn_legacy(const std::vector<unsigned char> &blob,
                        const std::wstring &dst, std::wstring &err) {
    if (blob.size() < 32) { err = L"QTN1 文件头不完整"; return false; }
    uint32_t version = 0, flags = 0;
    uint64_t plain_len = 0;
    memcpy(&version, blob.data() + 4, 4);
    memcpy(&flags, blob.data() + 8, 4);
    memcpy(&plain_len, blob.data() + 12, 8);
    if (version != 1 || flags != 1) { err = L"不支持的 QTN1 版本/标志"; return false; }
    if (blob.size() != 32 + (size_t)plain_len) { err = L"QTN1 文件长度不一致"; return false; }

    std::vector<unsigned char> plain((size_t)plain_len);
    const unsigned char key = 0x5A;
    for (size_t i = 0; i < plain.size(); i++) plain[i] = blob[32 + i] ^ key;
    return write_file(dst, plain.data(), plain.size(), err);
}

} // namespace

bool qtn_sgx_cpu_support(void) {
    return sgx_cpu_support_impl();
}

bool qtn_sgx_available(void) {
    int s = g_sgx_state.load();
    if (s >= 0) return s != 0;
    bool ok = sgx_cpu_support_impl() && sgx_load_backend();
    g_sgx_state.store(ok ? 1 : 0);
    return ok;
}

bool qtn_set_key_mode(int mode) {
    if (mode != 0 && mode != 1) return false;
    if (mode == 1 && !qtn_sgx_available()) return false;
    g_key_mode.store(mode);
    return true;
}

int qtn_get_key_mode(void) {
    return g_key_mode.load();
}

bool qtn_is_encrypted(const std::wstring &path) {
    return qtn_magic(path) != 0;
}

bool qtn_encrypt_file(const std::wstring &src, const std::wstring &dst,
                      std::wstring &err) {
    std::vector<unsigned char> plain;
    if (!read_all(src, plain, err, kMaxPlain)) return false;
    return encrypt_qtn(plain, dst, err);
}

bool qtn_decrypt_file(const std::wstring &src, const std::wstring &dst,
                      std::wstring &err) {
    std::vector<unsigned char> blob;
    if (!read_all(src, blob, err, kMaxPlain + 64ull * 1024ull)) return false;
    int m = qtn_magic(src);
    if (m == 2) return decrypt_qtn_aes(blob, dst, err);
    if (m == 1) return decrypt_qtn_legacy(blob, dst, err);
    err = L"不是 QTNA/QTN1 隔离文件";
    return false;
}

bool qtn_quarantine_file(const std::wstring &src, const std::wstring &stored,
                         std::wstring &err) {
    std::wstring tmp = stored + L".tmp";
    DeleteFileW(tmp.c_str());
    if (!qtn_encrypt_file(src, tmp, err)) return false;

    if (!MoveFileExW(tmp.c_str(), stored.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err = L"写入隔离文件失败：" + win32_error(GetLastError());
        DeleteFileW(tmp.c_str());
        DeleteFileW(stored.c_str());
        return false;
    }

    if (!DeleteFileW(src.c_str())) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            SetFileAttributesW(src.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileW(src.c_str())) return true;
            e = GetLastError();
        }
        err = L"删除原文件失败：" + win32_error(e);
        DeleteFileW(stored.c_str());
        return false;
    }
    return true;
}

bool qtn_restore_file(const std::wstring &stored, const std::wstring &original,
                      std::wstring &err) {
    int m = qtn_magic(stored);
    if (m == 0) {
        if (!MoveFileExW(stored.c_str(), original.c_str(), MOVEFILE_COPY_ALLOWED)) {
            err = L"恢复文件失败：" + win32_error(GetLastError());
            return false;
        }
        return true;
    }

    std::wstring tmp = original + L".qtn_restore";
    DeleteFileW(tmp.c_str());
    if (!qtn_decrypt_file(stored, tmp, err)) return false;

    if (!MoveFileExW(tmp.c_str(), original.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err = L"恢复文件失败：" + win32_error(GetLastError());
        DeleteFileW(tmp.c_str());
        return false;
    }
    DeleteFileW(stored.c_str());
    return true;
}
