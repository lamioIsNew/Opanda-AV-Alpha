/* qtn_crypto.cpp -- QTN 隔离文件加密实现
 *
 * 设计：
 *   · 每个文件随机生成 32 字节 AES-256 数据密钥 + 8 字节 nonce 盐；
 *     随机数优先由 TPM 2.0 RNG 产生，不可用时回退系统 CSPRNG（留痕）；
 *   · 默认用 TPM 内持久化 RSA-2048 公钥做 RSA-OAEP(SHA-256) 封装；
 *     无 TPM 时自动降级 DPAPI（当前用户作用域，flags bit3）；
 *   · 可选 SGX sealed key（默认关闭，需 CPU + SDK + enclave DLL）；
 *   · 封装后的密钥写入 QTN 头；TPM 私钥不出芯片；
 *   · v3 载荷按 64 KB 分块，每块独立 nonce（盐 || 块序号）与独立 16 字节
 *     GCM tag；块序号与块明文长度进 AAD，整段恒定为 64 KB 内存；
 *   · v2（单 nonce 一次性 GCM）与旧 QTN1（XOR 0x5A）只读兼容。
 *
 * 内存安全：
 *   · 明文 AES 密钥、CNG 密钥对象（展开后的密钥调度表）都放在
 *     SecureRegion 里：VirtualAlloc 提交 -> VirtualLock 锁页 -> 析构时
 *     SecureZeroMemory -> VirtualUnlock -> VirtualFree；
 *   · 明文密钥交给 BCryptGenerateSymmetricKey 后立刻清零，进程内不再有
 *     第二份明文；
 *   · 所有明文分块缓冲在写盘后立即清零。
 *
 * TPM 键名：OpandaQtnKey（Microsoft Platform Crypto Provider）。
 * 如果 TPM 被清除/键被删除，已有隔离文件将无法恢复——这是 TPM 绑定的预期代价。
 *
 * 注意：VirtualLock 是尽力而为。工作集配额不足时锁页会失败，但清零一定会
 * 执行；因此敏感数据的生命周期仍然被压到"解封 -> 生成 CNG 密钥 -> 清零"。
 */
#include "qtn_crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <intrin.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace {

const unsigned char kAesMagic[4] = {'Q', 'T', 'N', 'A'};
const unsigned char kXorMagic[4] = {'Q', 'T', 'N', '1'};

const unsigned kLegacyAesVersion = 2;   /* v2：单 nonce 一次性 GCM（只读兼容） */
const unsigned kStreamAesVersion = 3;   /* v3：64 KB 分块，每块独立 nonce+tag */

const unsigned kFlagAes = 1;            /* bit0=AES-256-GCM */
const unsigned kFlagTpm = 2;            /* bit1=TPM RSA-OAEP */
const unsigned kFlagSgx = 4;            /* bit2=SGX sealed key */
const unsigned kFlagDpapi = 8;          /* bit3=DPAPI（无 TPM 时自动降级，当前用户作用域） */

const size_t kNonceLen = 12;
const size_t kTagLen = 16;
const size_t kSaltLen = 8;              /* v3：nonce 的随机前缀 */
const size_t kAesHeader = 56;
const size_t kChunkSize = 64 * 1024;    /* 恒定 64 KB 流式块 */
const size_t kMaxWrapped = 1024;
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

/* ---------------- 基础工具 ---------------- */

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

void put_u32(unsigned char *p, uint32_t v) {
    memcpy(p, &v, 4);
}

void put_u64(unsigned char *p, uint64_t v) {
    memcpy(p, &v, 8);
}

uint32_t get_u32(const unsigned char *p) {
    uint32_t v = 0;
    memcpy(&v, p, 4);
    return v;
}

uint64_t get_u64(const unsigned char *p) {
    uint64_t v = 0;
    memcpy(&v, p, 8);
    return v;
}

/* 大端 32 位：nonce 计数器与 AAD 块序号 */
void put_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

bool read_exact(HANDLE h, void *data, size_t len) {
    unsigned char *p = (unsigned char *)data;
    while (len) {
        DWORD want = (DWORD)std::min<size_t>(len, 1u << 20);
        DWORD got = 0;
        if (!ReadFile(h, p, want, &got, NULL) || got == 0) return false;
        p += got;
        len -= got;
    }
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

/* ---------------- 敏感内存：锁页 + 强制清零 ---------------- */

/* 申请一块专门存放密钥/密钥调度表的区域：
 *   VirtualAlloc(MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
 *   VirtualLock  -> 尽力阻止这些页被换出到 pagefile.sys
 *   reset()      -> SecureZeroMemory 后 VirtualUnlock + VirtualFree
 * 拷贝构造被禁用，避免密钥被隐式复制到不受控的堆内存。 */
class SecureRegion {
public:
    SecureRegion() : p_(nullptr), n_(0), locked_(false) {}
    ~SecureRegion() { reset(); }

    SecureRegion(const SecureRegion &) = delete;
    SecureRegion &operator=(const SecureRegion &) = delete;

    bool alloc(size_t n) {
        reset();
        if (n == 0) return false;
        void *p = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p) return false;
        p_ = p;
        n_ = n;
        locked_ = VirtualLock(p_, n_) != FALSE;
        return true;
    }

    void reset() {
        if (!p_) return;
        SecureZeroMemory(p_, n_);
        if (locked_) VirtualUnlock(p_, n_);
        VirtualFree(p_, 0, MEM_RELEASE);
        p_ = nullptr;
        n_ = 0;
        locked_ = false;
    }

    unsigned char *data() { return (unsigned char *)p_; }
    const unsigned char *data() const { return (const unsigned char *)p_; }
    size_t size() const { return n_; }
    bool ok() const { return p_ != nullptr; }

private:
    void *p_;
    size_t n_;
    bool locked_;
};

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
    } catch (const std::bad_alloc &) {
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

/* 解封结果直接落在 SecureRegion 中；失败路径上该区域也会被 SecureZeroMemory。 */
bool tpm_unwrap(const unsigned char *wrapped, DWORD wrapped_len,
                SecureRegion &aes_key, size_t &aes_len, std::wstring &err) {
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
    if (!aes_key.alloc(out_len)) {
        err = L"内存不足（TPM 解封密钥）";
        return false;
    }
    DWORD produced = 0;
    st = NCryptDecrypt(g_tpm_key, (PBYTE)wrapped, wrapped_len, &oaep,
                       aes_key.data(), out_len, &produced, NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || produced != 32) {
        wchar_t b[64];
        swprintf(b, 64, L"（返回 %lu 字节）", (unsigned long)produced);
        err = L"TPM 解封 AES 密钥失败：" + nt_error(L"NCryptDecrypt", st) + b;
        aes_key.reset();   /* 残缺/异常明文立即清零 */
        return false;
    }
    aes_len = produced;
    return true;
}

/* ---------------- 随机数：TPM 2.0 RNG 优先，系统 RNG 兜底 ----------------
 *
 * Microsoft Platform Crypto Provider 暴露 BCRYPT_RNG_ALGORITHM 时，随机数
 * 由 TPM 2.0 产生；无 TPM、TPM 被禁用或 Provider 不支持 RNG 时回退到
 * BCRYPT_USE_SYSTEM_PREFERRED_RNG（Windows 内核 CSPRNG）。
 * 回退原因写入 diag，调用方在成功路径上也能留痕。
 */
bool fill_random(unsigned char *buf, size_t len, bool &used_tpm_rng,
                 std::wstring &diag) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st;
    wchar_t why[192];

    used_tpm_rng = false;
    if (len > 0xFFFFFFFFull) {
        diag += L"随机数请求过大；";
        return false;
    }

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM,
                                     MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st == 0 && alg) {
        st = BCryptGenRandom(alg, buf, (ULONG)len, 0);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (st == 0) {
            used_tpm_rng = true;
            return true;
        }
        swprintf(why, 192, L"TPM RNG 调用失败（0x%08X）", (unsigned)st);
    } else {
        swprintf(why, 192, L"TPM RNG Provider 不可用（0x%08X）", (unsigned)st);
    }

    st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {
        diag += L"系统 RNG 也失败（0x";
        wchar_t b[32];
        swprintf(b, 32, L"%08X", (unsigned)st);
        diag += b;
        diag += L"）；";
        return false;
    }
    diag += why;
    diag += L"，已回退到系统 RNG；";
    return true;
}

/* ---------------- DPAPI 后端：无 TPM 时自动降级 ----------------
 *
 * 作用域：当前用户（不传 CRYPTPROTECT_LOCAL_MACHINE）。同一台机器上的
 * 其他账户无法解封；用户配置被删除后隔离文件同样无法恢复，与 TPM 绑定
 * 的预期代价一致。DPAPI blob 只封装 32 字节 AES 密钥，大小远小于
 * kMaxWrapped；封装/解封都以 CRYPTPROTECT_UI_FORBIDDEN 运行，不弹 UI。
 */
void free_dpapi_blob(DATA_BLOB &b) {
    if (b.pbData) {
        SecureZeroMemory(b.pbData, b.cbData);
        LocalFree(b.pbData);
    }
    b.pbData = nullptr;
    b.cbData = 0;
}

bool dpapi_wrap(const unsigned char *aes_key, DWORD aes_len,
                std::vector<unsigned char> &wrapped, std::wstring &err) {
    DATA_BLOB in;
    DATA_BLOB out = {0, nullptr};

    in.pbData = (BYTE *)aes_key;
    in.cbData = aes_len;
    if (!CryptProtectData(&in, L"Opanda QTN AES key", NULL, NULL, NULL,
                          CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        err = L"DPAPI 封装 AES 密钥失败：" + win32_error(GetLastError());
        return false;
    }
    if (out.cbData == 0 || !out.pbData) {
        free_dpapi_blob(out);
        err = L"DPAPI 封装返回空 blob";
        return false;
    }
    try {
        wrapped.assign(out.pbData, out.pbData + out.cbData);
    } catch (const std::bad_alloc &) {
        free_dpapi_blob(out);
        err = L"内存不足（DPAPI 封装密钥）";
        return false;
    }
    free_dpapi_blob(out);
    return true;
}

bool dpapi_unwrap(const unsigned char *wrapped, DWORD wrapped_len,
                  SecureRegion &aes_key, size_t &aes_len, std::wstring &err) {
    DATA_BLOB in;
    DATA_BLOB out = {0, nullptr};

    in.pbData = (BYTE *)wrapped;
    in.cbData = wrapped_len;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        err = L"DPAPI 解封 AES 密钥失败：" + win32_error(GetLastError());
        return false;
    }
    if (out.cbData != 32 || !out.pbData) {
        wchar_t b[64];
        swprintf(b, 64, L"（返回 %lu 字节）", (unsigned long)out.cbData);
        free_dpapi_blob(out);
        err = L"DPAPI 解封的 AES 密钥长度异常" + std::wstring(b);
        return false;
    }
    if (!aes_key.alloc(out.cbData)) {
        free_dpapi_blob(out);
        err = L"内存不足（DPAPI 解封密钥）";
        return false;
    }
    memcpy(aes_key.data(), out.pbData, out.cbData);
    aes_len = out.cbData;
    free_dpapi_blob(out);   /* DPAPI 分配的明文副本立即清零并释放 */
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
    (void)key;
    (void)key_len;
    (void)sealed;
    err = L"SGX 后端未编译：需要 Intel SGX SDK、enclave 与 qtn_sgx_enclave.dll";
    return false;
#endif
}

bool sgx_unseal_key(const unsigned char *sealed, DWORD sealed_len,
                    SecureRegion &key, size_t &key_len, std::wstring &err) {
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
    if (!key.alloc(out_len)) {
        err = L"内存不足（SGX 解封密钥）";
        return false;
    }
    hr = g_sgx_unseal(sealed, sealed_len, key.data(), &out_len);
    if (FAILED(hr) || out_len != 32) {
        wchar_t b[64]; swprintf(b, 64, L"0x%08X", (unsigned)hr);
        err = L"SGX 解封密钥失败（" + std::wstring(b) + L"）";
        key.reset();
        return false;
    }
    key_len = out_len;
    return true;
#else
    (void)sealed;
    (void)sealed_len;
    (void)key;
    (void)key_len;
    err = L"SGX 后端未编译：需要 Intel SGX SDK、enclave 与 qtn_sgx_enclave.dll";
    return false;
#endif
}

/* ---------------- AES-256-GCM（单块，CNG） ---------------- */

/* 密钥对象缓冲区由我们提供并锁页，BCryptDestroyKey 之后可被清零，
 * 避免展开后的 AES 密钥调度表长期留在 CNG 自己分配的堆里。 */
class AesGcmKey {
public:
    AesGcmKey() : prov_(nullptr), key_(nullptr) {}
    ~AesGcmKey() { reset(); }

    AesGcmKey(const AesGcmKey &) = delete;
    AesGcmKey &operator=(const AesGcmKey &) = delete;

    bool init(const unsigned char *key32, size_t key_len, std::wstring &err) {
        reset();
        if (key_len != 32) {
            err = L"AES 密钥长度不是 32 字节";
            return false;
        }
        NTSTATUS st = BCryptOpenAlgorithmProvider(&prov_, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (st != 0 || !prov_) {
            prov_ = nullptr;
            err = nt_error(L"BCryptOpenAlgorithmProvider", st);
            return false;
        }
        st = BCryptSetProperty(prov_, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (st != 0) {
            err = nt_error(L"BCryptSetProperty(GCM)", st);
            reset();
            return false;
        }

        DWORD obj_len = 0;
        ULONG got = 0;
        st = BCryptGetProperty(prov_, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len,
                               (ULONG)sizeof(obj_len), &got, 0);
        if (st != 0 || obj_len == 0) {
            err = nt_error(L"BCryptGetProperty(OBJECT_LENGTH)", st);
            reset();
            return false;
        }
        if (!obj_.alloc(obj_len)) {
            err = L"内存不足（AES 密钥对象）";
            reset();
            return false;
        }

        st = BCryptGenerateSymmetricKey(prov_, &key_, obj_.data(), (ULONG)obj_.size(),
                                        (PUCHAR)key32, (ULONG)key_len, 0);
        if (st != 0 || !key_) {
            key_ = nullptr;
            err = nt_error(L"BCryptGenerateSymmetricKey", st);
            reset();
            return false;
        }
        return true;
    }

    void reset() {
        if (key_) {
            BCryptDestroyKey(key_);
            key_ = nullptr;
        }
        obj_.reset();   /* 展开的密钥调度表清零 */
        if (prov_) {
            BCryptCloseAlgorithmProvider(prov_, 0);
            prov_ = nullptr;
        }
    }

    bool ready() const { return key_ != nullptr; }

    bool crypt(bool encrypt, const unsigned char *nonce,
               const unsigned char *aad, size_t aad_len,
               const unsigned char *in, size_t in_len,
               unsigned char *out, size_t out_cap, size_t &out_len,
               unsigned char *tag, std::wstring &err) {
        if (!key_) { err = L"AES 密钥未初始化"; return false; }
        if (in_len > 0xFFFFFFFFull || aad_len > 0xFFFFFFFFull || out_cap > 0xFFFFFFFFull) {
            err = L"AES-GCM 单块输入过大";
            return false;
        }

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = (PUCHAR)nonce;
        auth.cbNonce = (ULONG)kNonceLen;
        auth.pbAuthData = (PUCHAR)aad;
        auth.cbAuthData = (ULONG)aad_len;
        auth.pbTag = tag;
        auth.cbTag = (ULONG)kTagLen;

        ULONG produced = 0;
        NTSTATUS st;
        if (encrypt) {
            st = BCryptEncrypt(key_, (PUCHAR)in, (ULONG)in_len, &auth,
                               NULL, 0, out, (ULONG)out_cap, &produced, 0);
        } else {
            st = BCryptDecrypt(key_, (PUCHAR)in, (ULONG)in_len, &auth,
                               NULL, 0, out, (ULONG)out_cap, &produced, 0);
        }
        if (st != 0) {
            if (st == (NTSTATUS)0xC000A002L)
                err = L"AES-GCM 认证失败：密钥不匹配（TPM/DPAPI/SGX）或文件被篡改";
            else
                err = nt_error(encrypt ? L"BCryptEncrypt" : L"BCryptDecrypt", st);
            return false;
        }
        out_len = produced;
        return true;
    }

private:
    BCRYPT_ALG_HANDLE prov_;
    BCRYPT_KEY_HANDLE key_;
    SecureRegion obj_;
};

/* ---------------- v3 分块参数 ---------------- */

/* nonce = 8 字节随机盐 || 32 位大端块序号。
 * 对同一文件、同一密钥，块序号单调递增 => nonce 永不重复；
 * 不同文件之间另有独立随机 AES 密钥，因此跨文件 nonce 碰撞不构成风险。 */
void make_chunk_nonce(const unsigned char *salt, uint32_t index,
                      unsigned char *nonce) {
    memcpy(nonce, salt, kSaltLen);
    put_be32(nonce + kSaltLen, index);
}

/* AAD = 头部(56B) || 封装密钥 || 块序号(4B) || 本块明文长度(4B)。
 * 绑定块序号可阻止重排/重放，绑定块长度可阻止截断尾部。 */
void build_chunk_aad(const std::vector<unsigned char> &prefix, uint32_t index,
                     uint32_t plain_len, std::vector<unsigned char> &aad) {
    aad.resize(prefix.size() + 8);
    if (!prefix.empty()) memcpy(aad.data(), prefix.data(), prefix.size());
    put_be32(aad.data() + prefix.size(), index);
    put_be32(aad.data() + prefix.size() + 4, plain_len);
}

void build_v3_header(unsigned char *hdr, const unsigned char *salt, uint32_t flags,
                     uint64_t plain_len, uint32_t wrapped_len) {
    memset(hdr, 0, kAesHeader);
    memcpy(hdr, kAesMagic, 4);
    put_u32(hdr + 4, (uint32_t)kStreamAesVersion);
    put_u32(hdr + 8, flags);
    memcpy(hdr + 12, salt, kSaltLen);         /* 12..19 盐；20..23 保留 0 */
    put_u64(hdr + 40, plain_len);             /* 24..39 保留 0（v2 这里是单 tag） */
    put_u32(hdr + 48, wrapped_len);
    put_u32(hdr + 52, (uint32_t)kChunkSize);
}

/* ---------------- v3 加密：恒定 64 KB 内存 ---------------- */

bool encrypt_qtn_stream(const std::wstring &src, const std::wstring &dst,
                        std::wstring &err) {
    HANDLE in = CreateFileW(src.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (in == INVALID_HANDLE_VALUE) {
        err = L"打开文件失败：" + win32_error(GetLastError());
        return false;
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(in, &li) || li.QuadPart < 0) {
        err = L"读取文件大小失败：" + win32_error(GetLastError());
        CloseHandle(in);
        return false;
    }
    const uint64_t plain_len = (uint64_t)li.QuadPart;
    if (plain_len > kMaxPlain) {
        err = L"文件超过隔离加密上限（512 MB）";
        CloseHandle(in);
        return false;
    }

    SecureRegion aes_key;
    if (!aes_key.alloc(32)) {
        err = L"内存不足（AES 密钥）";
        CloseHandle(in);
        return false;
    }
    /* 成功路径上的诊断（RNG 回退 / DPAPI 降级）也写回 err，调用方只在
     * 返回 false 时展示；正常情况 diag 为空，err 被清空。 */
    std::wstring diag;
    bool used_tpm_rng = false;
    unsigned char salt[kSaltLen] = {0};
    if (!fill_random(aes_key.data(), aes_key.size(), used_tpm_rng, diag)) {
        err = L"生成 AES 密钥失败：" + diag;
        CloseHandle(in);
        return false;   /* aes_key 由 SecureRegion 析构清零 */
    }
    if (!fill_random(salt, sizeof(salt), used_tpm_rng, diag)) {
        err = L"生成 nonce 盐失败：" + diag;
        CloseHandle(in);
        return false;
    }

    std::vector<unsigned char> wrapped;
    unsigned backend = 0;
    if (g_key_mode.load() == 1) {
        if (!sgx_seal_key(aes_key.data(), 32, wrapped, err)) {
            CloseHandle(in);
            return false;
        }
        backend = kFlagSgx;
    } else {
        if (tpm_wrap(aes_key.data(), 32, wrapped, err)) {
            backend = kFlagTpm;
        } else {
            /* 无 TPM / TPM 键不可用：自动降级 DPAPI（当前用户作用域）。
             * 原始 TPM 失败原因保留在 diag 里，便于排查。 */
            std::wstring tpm_reason = err;
            err.clear();
            if (!dpapi_wrap(aes_key.data(), 32, wrapped, err)) {
                err = L"TPM 与 DPAPI 均无法封装 AES 密钥：" +
                      tpm_reason + L"；" + err;
                CloseHandle(in);
                return false;
            }
            backend = kFlagDpapi;
            diag += L"TPM 不可用，已降级 DPAPI（";
            diag += tpm_reason;
            diag += L"）；";
        }
    }
    if (wrapped.empty() || wrapped.size() > kMaxWrapped) {
        err = L"封装密钥长度异常";
        CloseHandle(in);
        return false;
    }

    const uint32_t wrapped_len = (uint32_t)wrapped.size();
    unsigned char hdr[kAesHeader];
    build_v3_header(hdr, salt, kFlagAes | backend, plain_len, wrapped_len);

    /* 明文密钥只需要活到生成 CNG 句柄为止。 */
    AesGcmKey aes;
    if (!aes.init(aes_key.data(), aes_key.size(), err)) {
        CloseHandle(in);
        return false;
    }
    aes_key.reset();

    /* AAD 前缀：头部 + 封装密钥（与 v2 的绑定范围一致）。 */
    std::vector<unsigned char> aad_prefix(kAesHeader + wrapped_len);
    memcpy(aad_prefix.data(), hdr, kAesHeader);
    memcpy(aad_prefix.data() + kAesHeader, wrapped.data(), wrapped_len);
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plain;
    std::vector<unsigned char> cipher;
    try {
        aad.resize(aad_prefix.size() + 8);
        plain.resize(kChunkSize);
        cipher.resize(kChunkSize);
    } catch (const std::bad_alloc &) {
        err = L"内存不足（流式分块缓冲）";
        CloseHandle(in);
        return false;
    }

    HANDLE out = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        err = L"创建隔离文件失败：" + win32_error(GetLastError());
        CloseHandle(in);
        return false;
    }

    bool ok = write_exact(out, hdr, kAesHeader) &&
              write_exact(out, wrapped.data(), wrapped_len);

    uint64_t off = 0;
    uint32_t index = 0;
    while (ok && off < plain_len) {
        const size_t want = (size_t)std::min<uint64_t>(kChunkSize, plain_len - off);
        if (!read_exact(in, plain.data(), want)) {
            err = L"读取文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }

        unsigned char nonce[kNonceLen];
        make_chunk_nonce(salt, index, nonce);
        build_chunk_aad(aad_prefix, index, (uint32_t)want, aad);

        size_t produced = 0;
        unsigned char tag[kTagLen] = {0};
        if (!aes.crypt(true, nonce, aad.data(), aad.size(),
                       plain.data(), want, cipher.data(), cipher.size(),
                       produced, tag, err)) {
            ok = false;
            break;
        }
        if (produced != want) {
            err = L"AES-GCM 输出长度异常";
            ok = false;
            break;
        }
        if (!write_exact(out, cipher.data(), produced) ||
            !write_exact(out, tag, sizeof(tag))) {
            err = L"写入隔离文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }

        SecureZeroMemory(plain.data(), plain.size());   /* 明文块不留在堆里 */
        off += want;
        index++;
    }
    if (!plain.empty()) SecureZeroMemory(plain.data(), plain.size());

    if (ok && !FlushFileBuffers(out)) {
        err = L"刷新隔离文件失败：" + win32_error(GetLastError());
        ok = false;
    }
    CloseHandle(out);
    CloseHandle(in);
    if (!ok) {
        DeleteFileW(dst.c_str());
        return false;
    }
    err = diag;   /* 成功时可能带 RNG/后端降级说明；为空则清空 */
    return true;
}

/* ---------------- 解密 ---------------- */

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

bool seek_begin(HANDLE h, uint64_t off) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)off;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) != FALSE;
}

/* v3：逐块读密文+tag -> 解密 -> 认证通过才写盘。认证失败删除半成品。 */
bool decrypt_qtn_stream(HANDLE in, uint64_t file_size, const unsigned char *hdr,
                        const std::wstring &dst, std::wstring &err) {
    const uint32_t version = get_u32(hdr + 4);
    const uint32_t flags = get_u32(hdr + 8);
    const uint64_t plain_len = get_u64(hdr + 40);
    const uint32_t wrapped_len = get_u32(hdr + 48);
    const uint32_t chunk_size = get_u32(hdr + 52);

    if (version != kStreamAesVersion) { err = L"不支持的 QTNA 版本"; return false; }
    if ((flags & kFlagAes) == 0) { err = L"QTNA 不是 AES-GCM 格式"; return false; }
    const bool use_tpm = (flags & kFlagTpm) != 0;
    const bool use_sgx = (flags & kFlagSgx) != 0;
    const bool use_dpapi = (flags & kFlagDpapi) != 0;
    if ((int)use_tpm + (int)use_sgx + (int)use_dpapi != 1) {
        err = L"QTNA 密钥后端标志无效";
        return false;
    }
    if (wrapped_len == 0 || wrapped_len > kMaxWrapped) {
        err = L"QTNA 封装密钥长度异常";
        return false;
    }
    if (chunk_size != (uint32_t)kChunkSize) { err = L"QTNA 分块大小异常"; return false; }
    if (plain_len > kMaxPlain) {
        err = L"隔离文件超过可解密上限（512 MB）";
        return false;
    }

    /* plain_len 已被 kMaxPlain 夹住，下面的算术不会在 64 位上溢出。 */
    const uint64_t chunks = plain_len
                                ? ((plain_len + (uint64_t)kChunkSize - 1) / (uint64_t)kChunkSize)
                                : 0;
    const uint64_t expect = (uint64_t)kAesHeader + (uint64_t)wrapped_len +
                            plain_len + chunks * (uint64_t)kTagLen;
    if (file_size != expect) {
        err = L"QTNA 文件长度与头部不一致";
        return false;
    }

    if (!seek_begin(in, kAesHeader)) {
        err = L"定位隔离文件失败：" + win32_error(GetLastError());
        return false;
    }
    std::vector<unsigned char> wrapped(wrapped_len);
    if (!read_exact(in, wrapped.data(), wrapped.size())) {
        err = L"读取封装密钥失败：" + win32_error(GetLastError());
        return false;
    }

    SecureRegion aes_key;
    size_t key_len = 0;
    const bool key_ok =
        use_sgx ? sgx_unseal_key(wrapped.data(), wrapped_len, aes_key, key_len, err)
        : use_dpapi ? dpapi_unwrap(wrapped.data(), wrapped_len, aes_key, key_len, err)
                    : tpm_unwrap(wrapped.data(), wrapped_len, aes_key, key_len, err);
    if (!key_ok) return false;

    AesGcmKey aes;
    if (!aes.init(aes_key.data(), key_len, err)) return false;
    aes_key.reset();

    std::vector<unsigned char> aad_prefix(kAesHeader + wrapped_len);
    memcpy(aad_prefix.data(), hdr, kAesHeader);
    memcpy(aad_prefix.data() + kAesHeader, wrapped.data(), wrapped_len);
    std::vector<unsigned char> aad;
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> plain;
    try {
        aad.resize(aad_prefix.size() + 8);
        cipher.resize(kChunkSize);
        plain.resize(kChunkSize);
    } catch (const std::bad_alloc &) {
        err = L"内存不足（流式分块缓冲）";
        return false;
    }

    HANDLE out = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        err = L"创建输出文件失败：" + win32_error(GetLastError());
        return false;
    }

    bool ok = true;
    uint64_t off = 0;
    uint32_t index = 0;
    while (off < plain_len) {
        const size_t want = (size_t)std::min<uint64_t>(kChunkSize, plain_len - off);
        unsigned char tag[kTagLen] = {0};
        if (!read_exact(in, cipher.data(), want) ||
            !read_exact(in, tag, sizeof(tag))) {
            err = L"读取隔离文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }

        unsigned char nonce[kNonceLen];
        make_chunk_nonce(hdr + 12, index, nonce);
        build_chunk_aad(aad_prefix, index, (uint32_t)want, aad);

        size_t produced = 0;
        if (!aes.crypt(false, nonce, aad.data(), aad.size(),
                       cipher.data(), want, plain.data(), plain.size(),
                       produced, tag, err)) {
            ok = false;
            break;
        }
        if (produced != want) {
            err = L"AES-GCM 解密长度异常";
            ok = false;
            break;
        }
        if (!write_exact(out, plain.data(), produced)) {
            err = L"写入输出文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }

        SecureZeroMemory(plain.data(), plain.size());
        off += want;
        index++;
    }
    if (!plain.empty()) SecureZeroMemory(plain.data(), plain.size());

    if (ok && !FlushFileBuffers(out)) {
        err = L"刷新输出文件失败：" + win32_error(GetLastError());
        ok = false;
    }
    CloseHandle(out);
    if (!ok) {
        DeleteFileW(dst.c_str());   /* 认证失败不留半成品明文 */
        return false;
    }
    return true;
}

/* v2（旧格式，只读兼容）：单 nonce 一次性 GCM，tag 覆盖整段密文。
 * 必须整段读入才能校验 tag；上限 512 MB，并用 try/catch 兜住 bad_alloc。 */
bool decrypt_qtn_v2(HANDLE in, uint64_t file_size, const unsigned char *hdr,
                    const std::wstring &dst, std::wstring &err) {
    const uint32_t flags = get_u32(hdr + 8);
    const uint64_t plain_len = get_u64(hdr + 40);
    const uint32_t wrapped_len = get_u32(hdr + 48);

    if ((flags & kFlagAes) == 0) { err = L"QTNA 不是 AES-GCM 格式"; return false; }
    const bool use_tpm = (flags & kFlagTpm) != 0;
    const bool use_sgx = (flags & kFlagSgx) != 0;
    const bool use_dpapi = (flags & kFlagDpapi) != 0;
    if ((int)use_tpm + (int)use_sgx + (int)use_dpapi != 1) {
        err = L"QTNA 密钥后端标志无效";
        return false;
    }
    if (wrapped_len == 0 || wrapped_len > kMaxWrapped) {
        err = L"QTNA 封装密钥长度异常";
        return false;
    }
    if (plain_len > kMaxPlain) {
        err = L"旧版 QTNA 文件超过可解密上限（512 MB）";
        return false;
    }
    if (file_size != (uint64_t)kAesHeader + (uint64_t)wrapped_len + plain_len) {
        err = L"QTNA 文件长度与头部不一致";
        return false;
    }

    if (!seek_begin(in, kAesHeader)) {
        err = L"定位隔离文件失败：" + win32_error(GetLastError());
        return false;
    }
    std::vector<unsigned char> prefix(kAesHeader + wrapped_len);
    memcpy(prefix.data(), hdr, kAesHeader);
    if (!read_exact(in, prefix.data() + kAesHeader, wrapped_len)) {
        err = L"读取封装密钥失败：" + win32_error(GetLastError());
        return false;
    }
    unsigned char tag[kTagLen];
    memcpy(tag, prefix.data() + 24, kTagLen);
    memset(prefix.data() + 24, 0, kTagLen);   /* v2 的 AAD 中 tag 为 0 */

    SecureRegion aes_key;
    size_t key_len = 0;
    const bool key_ok =
        use_sgx ? sgx_unseal_key(prefix.data() + kAesHeader, wrapped_len,
                                 aes_key, key_len, err)
        : use_dpapi ? dpapi_unwrap(prefix.data() + kAesHeader, wrapped_len,
                                   aes_key, key_len, err)
                    : tpm_unwrap(prefix.data() + kAesHeader, wrapped_len,
                                 aes_key, key_len, err);
    if (!key_ok) return false;

    AesGcmKey aes;
    if (!aes.init(aes_key.data(), key_len, err)) return false;
    aes_key.reset();

    std::vector<unsigned char> cipher;
    std::vector<unsigned char> plain;
    try {
        cipher.resize((size_t)plain_len);
        plain.resize((size_t)plain_len);
    } catch (const std::bad_alloc &) {
        err = L"内存不足（旧版 QTNA 一次性解密）";
        return false;
    }
    if (!read_exact(in, cipher.data(), cipher.size())) {
        err = L"读取隔离文件失败：" + win32_error(GetLastError());
        return false;
    }

    size_t produced = 0;
    if (!aes.crypt(false, prefix.data() + 12, prefix.data(), prefix.size(),
                   cipher.data(), cipher.size(), plain.data(), plain.size(),
                   produced, tag, err)) {
        return false;
    }
    if (produced != plain_len) {
        SecureZeroMemory(plain.data(), plain.size());
        err = L"AES-GCM 解密长度异常";
        return false;
    }
    const bool ok = write_file(dst, plain.data(), plain.size(), err);
    SecureZeroMemory(plain.data(), plain.size());
    return ok;
}

/* 旧 QTN1（XOR 0x5A）：同样流式，避免整文件进内存。 */
bool decrypt_qtn_legacy(HANDLE in, uint64_t file_size, const unsigned char *hdr,
                        const std::wstring &dst, std::wstring &err) {
    const uint32_t version = get_u32(hdr + 4);
    const uint32_t flags = get_u32(hdr + 8);
    const uint64_t plain_len = get_u64(hdr + 12);
    if (version != 1 || flags != 1) { err = L"不支持的 QTN1 版本/标志"; return false; }
    if (plain_len > kMaxPlain) {
        err = L"旧版 QTN1 文件超过可解密上限（512 MB）";
        return false;
    }
    if (file_size != 32ull + plain_len) { err = L"QTN1 文件长度不一致"; return false; }
    if (!seek_begin(in, 32)) {
        err = L"定位 QTN1 文件失败：" + win32_error(GetLastError());
        return false;
    }

    HANDLE out = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        err = L"创建输出文件失败：" + win32_error(GetLastError());
        return false;
    }

    std::vector<unsigned char> buf;
    try {
        buf.resize(kChunkSize);
    } catch (const std::bad_alloc &) {
        err = L"内存不足（QTN1 分块缓冲）";
        CloseHandle(out);
        DeleteFileW(dst.c_str());
        return false;
    }

    const unsigned char key = 0x5A;
    bool ok = true;
    uint64_t off = 0;
    while (off < plain_len) {
        const size_t want = (size_t)std::min<uint64_t>(kChunkSize, plain_len - off);
        if (!read_exact(in, buf.data(), want)) {
            err = L"读取 QTN1 文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }
        for (size_t i = 0; i < want; i++) buf[i] ^= key;
        if (!write_exact(out, buf.data(), want)) {
            err = L"写入输出文件失败：" + win32_error(GetLastError());
            ok = false;
            break;
        }
        SecureZeroMemory(buf.data(), buf.size());
        off += want;
    }
    SecureZeroMemory(buf.data(), buf.size());

    if (ok && !FlushFileBuffers(out)) {
        err = L"刷新输出文件失败：" + win32_error(GetLastError());
        ok = false;
    }
    CloseHandle(out);
    if (!ok) {
        DeleteFileW(dst.c_str());
        return false;
    }
    return true;
}

/* 读文件头并分派到 v3 / v2 / QTN1。 */
bool decrypt_any(const std::wstring &src, const std::wstring &dst,
                 std::wstring &err) {
    HANDLE in = CreateFileW(src.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (in == INVALID_HANDLE_VALUE) {
        err = L"打开隔离文件失败：" + win32_error(GetLastError());
        return false;
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(in, &li) || li.QuadPart < 0) {
        err = L"读取文件大小失败：" + win32_error(GetLastError());
        CloseHandle(in);
        return false;
    }
    const uint64_t file_size = (uint64_t)li.QuadPart;

    unsigned char hdr[kAesHeader];
    memset(hdr, 0, sizeof(hdr));
    const size_t hdr_len = (size_t)std::min<uint64_t>(file_size, (uint64_t)kAesHeader);
    if (hdr_len < 4 || !read_exact(in, hdr, hdr_len)) {
        err = L"隔离文件头不完整";
        CloseHandle(in);
        return false;
    }

    bool ok = false;
    if (memcmp(hdr, kXorMagic, 4) == 0) {
        if (hdr_len < 32) {
            err = L"QTN1 文件头不完整";
        } else {
            ok = decrypt_qtn_legacy(in, file_size, hdr, dst, err);
        }
    } else if (memcmp(hdr, kAesMagic, 4) == 0) {
        if (hdr_len < kAesHeader) {
            err = L"QTNA 文件头不完整";
        } else {
            const uint32_t version = get_u32(hdr + 4);
            if (version == kStreamAesVersion) {
                ok = decrypt_qtn_stream(in, file_size, hdr, dst, err);
            } else if (version == kLegacyAesVersion) {
                ok = decrypt_qtn_v2(in, file_size, hdr, dst, err);
            } else {
                err = L"不支持的 QTNA 版本";
            }
        }
    } else {
        err = L"不是 QTNA/QTN1 隔离文件";
    }

    CloseHandle(in);
    return ok;
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
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    unsigned char m[4] = {0};
    DWORD got = 0;
    BOOL ok = ReadFile(h, m, 4, &got, NULL);
    CloseHandle(h);
    if (!ok || got != 4) return false;
    return memcmp(m, kXorMagic, 4) == 0 || memcmp(m, kAesMagic, 4) == 0;
}

bool qtn_encrypt_file(const std::wstring &src, const std::wstring &dst,
                      std::wstring &err) {
    return encrypt_qtn_stream(src, dst, err);
}

bool qtn_decrypt_file(const std::wstring &src, const std::wstring &dst,
                      std::wstring &err) {
    return decrypt_any(src, dst, err);
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
    if (!qtn_is_encrypted(stored)) {
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
