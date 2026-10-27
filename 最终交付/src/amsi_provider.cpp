/* amsi_provider.cpp -- Opanda AV 的 AMSI 反恶意软件提供程序（DLL）
 *
 * 作用：
 *   宿主（PowerShell / VBScript / JScript / Office VBA 等）在执行脚本块前，
 *   把内容写入 IAmsiStream，并调用已注册 provider 的 Scan()。
 *   返回 AMSI_RESULT_DETECTED 即阻断执行；否则放行。
 *
 * 检测来源（按优先级）：
 *   1. ac_engine + db\signatures.db（与 CLI/GUI 同一份 53 条特征库）；
 *   2. 库找不到时退化为内置高置信度脚本规则（保证 DLL 独立可用）。
 *
 * 工程约束：
 *   · Scan() 内绝不起外部进程，全部在本进程内完成；
 *   · 最多读取 4 MB，时间预算 100 ms，超时按"未检出"收手，避免卡住宿主；
 *   · 只在初始化时读库，之后 ac_scan 只读，可被多线程并发调用；
 *   · 本 DLL 未签名，注册前必须自行签名并在测试机验证（见 register_amsi.reg）。
 *
 * 构建（MSVC x64）：
 *   cl /nologo /LD /O2 /W3 /MT /utf-8 /EHsc /std:c++17 ^
 *      /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS ^
 *      /I"src" src\amsi_provider.cpp src\ac_engine.c ^
 *      /link /DEF:src\amsi_provider.def /OUT:bin\amsi_provider.dll
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <amsi.h>
#include <olectl.h>
#include <strsafe.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "ac_engine.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

/* 与 进阶能力\AMSI提供程序 的 CLSID 保持一致，避免同一台机器出现两个 provider。 */
/* {7F3C1A20-9B4E-4C6D-A1F2-5E8D3B0C7A91} */
const CLSID kProviderClsid =
    {0x7f3c1a20, 0x9b4e, 0x4c6d, {0xa1, 0xf2, 0x5e, 0x8d, 0x3b, 0x0c, 0x7a, 0x91}};
/* 本地定义，避免链接 amsi.lib；值与 SDK 的 IID_IAntimalwareProvider 一致。 */
const IID kIID_AntimalwareProvider =
    {0xb2cabfe3, 0xfe04, 0x42b1, {0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25}};
const wchar_t *kProviderName = L"Opanda AV 静态查杀引擎";

const size_t kMaxContent = 4u * 1024u * 1024u;   /* 单次最多审 4 MB */
const ULONGLONG kTimeBudgetMs = 100;             /* 超时按未检出收手 */
const size_t kReadChunk = 64u * 1024u;

/* ---------------- 内置兜底规则（db 缺失时使用） ---------------- */

struct BuiltinRule {
    const char *needle;
    int severity;      /* >=80 才返回 DETECTED */
    const char *name;
};

const BuiltinRule kBuiltinRules[] = {
    {"vssadmin delete shadows",             100, "Ransom.Script.Generic"},
    {"sekurlsa::logonpasswords",            100, "HackTool.Win32.Mimikatz"},
    {"mimikatz",                            100, "HackTool.Win32.Mimikatz"},
    {"powershell -enc",                      90, "Trojan.Script.Downloader"},
    {"-encodedcommand",                      90, "Trojan.Script.Downloader"},
    {"meterpreter",                          90, "Backdoor.Win32.Meterpreter"},
    {"amsiutils",                            85, "Trojan.Script.AmsiBypass"},
    {"amsi.dll",                             85, "Trojan.Script.AmsiBypass"},
    {"downloadstring",                       80, "Trojan.Script.Downloader"},
    {"frombase64string",                     80, "Trojan.Script.Downloader"},
    {"invoke-expression",                    70, "Trojan.Script.Generic"},
    {"net.webclient",                        65, "Trojan.Script.Generic"},
    {"downloadfile",                         65, "Trojan.Script.Generic"},
};

unsigned char lower_ascii(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

/* 大小写不敏感（仅 ASCII）子串匹配，与脚本场景一致。 */
int find_builtin_rule(const unsigned char *buf, size_t len, char *out_name,
                      size_t name_cap) {
    for (size_t r = 0; r < sizeof(kBuiltinRules) / sizeof(kBuiltinRules[0]); r++) {
        const char *needle = kBuiltinRules[r].needle;
        size_t n = strlen(needle);
        if (n == 0 || n > len) continue;
        for (size_t i = 0; i + n <= len; i++) {
            size_t k = 0;
            while (k < n &&
                   lower_ascii(buf[i + k]) == lower_ascii((unsigned char)needle[k]))
                k++;
            if (k == n) {
                if (out_name && name_cap) {
                    strncpy_s(out_name, name_cap, kBuiltinRules[r].name, _TRUNCATE);
                }
                return kBuiltinRules[r].severity;
            }
        }
    }
    return 0;
}

/* ---------------- 特征库初始化（进程内一次） ---------------- */

extern "C" IMAGE_DOS_HEADER __ImageBase;

HMODULE this_module() {
    return reinterpret_cast<HMODULE>(&__ImageBase);
}

std::wstring module_dir() {
    wchar_t path[MAX_PATH * 2] = {0};
    DWORD n = GetModuleFileNameW(this_module(), path, _countof(path));
    if (n == 0 || n >= _countof(path)) return std::wstring();
    std::wstring s(path, n);
    size_t p = s.find_last_of(L"\\/");
    if (p != std::wstring::npos) s.resize(p);
    return s;
}

bool file_exists(const std::wstring &path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring join_path(const std::wstring &dir, const wchar_t *leaf) {
    std::wstring s = dir;
    if (!s.empty() && s.back() != L'\\' && s.back() != L'/') s.push_back(L'\\');
    s += leaf;
    return s;
}

std::wstring full_path(const std::wstring &path) {
    wchar_t full[MAX_PATH * 2] = {0};
    DWORD n = GetFullPathNameW(path.c_str(), _countof(full), full, nullptr);
    if (n == 0 || n >= _countof(full)) return std::wstring();
    return std::wstring(full, n);
}

bool try_init_ac() {
    std::vector<std::wstring> candidates;

    wchar_t env[MAX_PATH * 2] = {0};
    DWORD n = GetEnvironmentVariableW(L"OPANDA_SIGDB", env, _countof(env));
    if (n > 0 && n < _countof(env)) candidates.push_back(env);

    std::wstring dir = module_dir();
    if (!dir.empty()) {
        candidates.push_back(join_path(dir, L"signatures.db"));
        candidates.push_back(join_path(dir, L"..\\db\\signatures.db"));
        candidates.push_back(join_path(dir, L"..\\..\\db\\signatures.db"));
    }

    for (size_t i = 0; i < candidates.size(); i++) {
        std::wstring p = full_path(candidates[i]);
        if (p.empty() || !file_exists(p)) continue;
        if (ac_init_w(p.c_str()) == 0 && ac_pattern_count() > 0) return true;
    }
    return false;
}

INIT_ONCE g_ac_once = INIT_ONCE_STATIC_INIT;
std::atomic<int> g_ac_ready{0};

BOOL CALLBACK init_ac_once(PINIT_ONCE, PVOID, PVOID *) {
    g_ac_ready.store(try_init_ac() ? 1 : 0);
    return TRUE;
}

/* ---------------- IAntimalwareProvider ---------------- */

class AmsiProvider final : public IAntimalwareProvider {
public:
    AmsiProvider() : m_ref(1) {}

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, kIID_AntimalwareProvider)) {
            *ppv = static_cast<IAntimalwareProvider *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return (ULONG)InterlockedIncrement(&m_ref);
    }

    STDMETHODIMP_(ULONG) Release() override {
        LONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return (ULONG)c;
    }

    STDMETHODIMP Scan(IAmsiStream *stream, AMSI_RESULT *result) override {
        if (!stream || !result) return E_INVALIDARG;
        *result = AMSI_RESULT_NOT_DETECTED;

        ULONGLONG total = 0;
        ULONG attr = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE,
                                        (ULONG)sizeof(total),
                                        reinterpret_cast<PBYTE>(&total), &attr)) ||
            total == 0) {
            return S_OK;
        }

        const size_t want =
            (size_t)std::min<ULONGLONG>(total, (ULONGLONG)kMaxContent);
        std::vector<unsigned char> buf;
        try {
            buf.resize(want + 1);
        } catch (const std::bad_alloc &) {
            return E_OUTOFMEMORY;
        }

        size_t got = 0;
        const ULONGLONG t0 = GetTickCount64();
        while (got < want) {
            if (GetTickCount64() - t0 > kTimeBudgetMs) {
                OutputDebugStringA("[OpandaAMSI] time budget exceeded\n");
                break;
            }
            ULONG read = 0;
            ULONG chunk = (ULONG)std::min<size_t>(kReadChunk, want - got);
            HRESULT hr = stream->Read((ULONGLONG)got, chunk,
                                      buf.data() + got, &read);
            if (FAILED(hr) || read == 0) break;
            if (read > chunk) read = chunk;
            got += read;
        }
        buf[got] = 0;

        char name[128] = {0};
        char caro[128] = {0};
        int severity = 0;

        InitOnceExecuteOnce(&g_ac_once, init_ac_once, nullptr, nullptr);
        if (g_ac_ready.load() != 0) {
            int idx = -1;
            if (ac_scan_first_match(buf.data(), got, &idx)) {
                const char *n = ac_pattern_name(idx);
                const char *c = ac_pattern_caro(idx);
                if (n) strncpy_s(name, sizeof(name), n, _TRUNCATE);
                if (c) strncpy_s(caro, sizeof(caro), c, _TRUNCATE);
                severity = ac_pattern_severity(idx);
            }
        } else {
            severity = find_builtin_rule(buf.data(), got, caro, sizeof(caro));
            strncpy_s(name, sizeof(name), "BuiltinScriptRule", _TRUNCATE);
        }

        if (severity >= 80) {
            *result = AMSI_RESULT_DETECTED;
            char msg[384];
            sprintf_s(msg, sizeof(msg),
                      "[OpandaAMSI] DETECTED sev=%d name=%s caro=%s\n",
                      severity, name[0] ? name : "-", caro[0] ? caro : "-");
            OutputDebugStringA(msg);
        } else if (severity > 0) {
            char msg[384];
            sprintf_s(msg, sizeof(msg),
                      "[OpandaAMSI] suspicious sev=%d name=%s (not blocked)\n",
                      severity, name[0] ? name : "-");
            OutputDebugStringA(msg);
        }

        SecureZeroMemory(buf.data(), buf.size());
        return S_OK;
    }

    STDMETHODIMP_(void) CloseSession(ULONGLONG session) override {
        UNREFERENCED_PARAMETER(session);
    }

    STDMETHODIMP DisplayName(LPWSTR *displayName) override {
        if (!displayName) return E_POINTER;
        *displayName = nullptr;
        size_t cb = (wcslen(kProviderName) + 1) * sizeof(wchar_t);
        *displayName = (LPWSTR)CoTaskMemAlloc(cb);
        if (!*displayName) return E_OUTOFMEMORY;
        memcpy(*displayName, kProviderName, cb);
        return S_OK;
    }

private:
    ~AmsiProvider() {}
    LONG m_ref;
};

class ProviderFactory final : public IClassFactory {
public:
    ProviderFactory() : m_ref(1) {}
    ~ProviderFactory() = default;

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) ||
            IsEqualIID(riid, IID_IClassFactory)) {
            *ppv = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return (ULONG)InterlockedIncrement(&m_ref);
    }

    STDMETHODIMP_(ULONG) Release() override {
        /* 全局静态工厂不销毁；DllCanUnloadNow 恒为 S_FALSE。 */
        return (ULONG)InterlockedDecrement(&m_ref);
    }

    STDMETHODIMP CreateInstance(IUnknown *outer, REFIID riid, void **ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        AmsiProvider *p = new (std::nothrow) AmsiProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL) override { return S_OK; }

private:
    LONG m_ref;
};

ProviderFactory g_factory;

/* ---------------- 注册辅助 ---------------- */

LONG reg_write(HKEY root, const wchar_t *subkey, const wchar_t *name,
               const wchar_t *value) {
    HKEY hk = nullptr;
    LONG r = RegCreateKeyExW(root, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                             KEY_WRITE | KEY_WOW64_64KEY, nullptr, &hk, nullptr);
    if (r != ERROR_SUCCESS) return r;
    const DWORD cb = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
    r = RegSetValueExW(hk, name, 0, REG_SZ, (const BYTE *)value, cb);
    RegCloseKey(hk);
    return r;
}

} // namespace

/* ---------------- COM 导出 ---------------- */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(inst);
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, kProviderClsid)) return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow(void) {
    return S_FALSE;   /* 静态工厂 + 进程内自动机，DLL 常驻到宿主退出 */
}

STDAPI DllRegisterServer(void) {
    wchar_t dll[MAX_PATH * 2] = {0};
    if (GetModuleFileNameW(this_module(), dll, _countof(dll)) == 0)
        return SELFREG_E_CLASS;

    wchar_t clsid[64] = {0};
    if (StringFromGUID2(kProviderClsid, clsid, _countof(clsid)) == 0)
        return SELFREG_E_CLASS;

    wchar_t key[512] = {0};
    if (FAILED(StringCchPrintfW(key, _countof(key),
                                L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s",
                                clsid)))
        return SELFREG_E_CLASS;
    if (reg_write(HKEY_LOCAL_MACHINE, key, nullptr, L"Opanda AV") != ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    if (FAILED(StringCchPrintfW(key, _countof(key),
                                L"SOFTWARE\\Classes\\CLSID\\%s", clsid)))
        return SELFREG_E_CLASS;
    if (reg_write(HKEY_LOCAL_MACHINE, key, nullptr,
                  L"Opanda AV AMSI Provider") != ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    if (FAILED(StringCchPrintfW(key, _countof(key),
                                L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32",
                                clsid)))
        return SELFREG_E_CLASS;
    if (reg_write(HKEY_LOCAL_MACHINE, key, nullptr, dll) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    if (reg_write(HKEY_LOCAL_MACHINE, key, L"ThreadingModel", L"Both") !=
        ERROR_SUCCESS)
        return SELFREG_E_CLASS;

    return S_OK;
}

STDAPI DllUnregisterServer(void) {
    wchar_t clsid[64] = {0};
    if (StringFromGUID2(kProviderClsid, clsid, _countof(clsid)) == 0)
        return SELFREG_E_CLASS;

    wchar_t key[512] = {0};
    if (SUCCEEDED(StringCchPrintfW(key, _countof(key),
                                   L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s",
                                   clsid)))
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, key);

    if (SUCCEEDED(StringCchPrintfW(key, _countof(key),
                                   L"SOFTWARE\\Classes\\CLSID\\%s", clsid)))
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, key);

    return S_OK;
}
