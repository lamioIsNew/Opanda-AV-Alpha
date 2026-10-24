/* ============================================================================
 *  amsi_provider.c —— 本项目自用的 AMSI 反恶意软件提供程序（骨架）
 * ----------------------------------------------------------------------------
 *  【状态】未编译、未注册、未实测。原因见 ..\..\进阶能力说明.md 第五节：
 *          需要数字签名证书才能被 AMSI 宿主接受，且组件崩溃会拖死宿主进程。
 *          这里给的是"可直接接着写"的完整骨架 + 关键工程点注释。
 *
 *  【编译环境】需要 Windows SDK（提供 amsi.h）与 MSVC：
 *      cl /LD /EHsc /DUNICODE /D_UNICODE amsi_provider.c ole32.lib oleaut32.lib
 *      （mingw 的 amsi.h 不完整，本骨架按 SDK 头文件编写）
 *
 *  【AMSI 的工作方式】
 *      宿主（PowerShell/VBScript/Office VBA/JScript…）在**执行前**把待执行内容
 *      Write 进一个 IAmsiStream，然后调用已注册 provider 的 Scan()。
 *      返回 AMSI_RESULT_DETECTED 就当场阻断执行 —— 这才叫"事前拦截"。
 *
 *  【生产化的两个硬要求】
 *      1. Scan() 里绝不能起外部进程（起 scan.exe 会慢到不可用），
 *         必须把特征匹配/规则判断编译进本 DLL（可直接复用本项目的
 *         signature_scan.c / script_scan.c 里的纯匹配函数）。
 *      2. Scan() 必须有硬超时（示例给的是 5ms 预算），超时按"未检出"返回，
 *         避免卡住宿主。
 * ==========================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>          /* Windows SDK 提供 IAntimalwareProvider / IAmsiStream */
#include <strsafe.h>

/* 本项目自用的 CLSID（可自行更换）。注册脚本里的 GUID 必须与此一致。 */
/* {7F3C1A20-9B4E-4C6D-A1F2-5E8D3B0C7A91} */
static const CLSID CLSID_OurAmsiProvider =
    { 0x7f3c1a20, 0x9b4e, 0x4c6d, { 0xa1, 0xf2, 0x5e, 0x8d, 0x3b, 0x0c, 0x7a, 0x91 } };

/* 统计用，仅便于调试观察 */
static volatile LONG g_scanCount = 0;

/* ---------- 内置的最小规则集（示例：真实项目里换成完整特征库） ---------- */
typedef struct { const char *needle; int sev; const char *name; } AmasRule;

static const AmasRule g_rules[] = {
    { "vssadmin delete shadows",     100, "Ransom.Script.Generic"   },
    { "powershell -enc",              95, "Trojan.Script.Downloader"},
    { "-encodedcommand",              95, "Trojan.Script.Downloader"},
    { "downloadstring",               80, "Trojan.Script.Downloader"},
    { "downloadfile",                 80, "Trojan.Script.Downloader"},
    { "frombase64string",             70, "Trojan.Script.Generic"   },
    { "net.webclient",                65, "Trojan.Script.Generic"   },
    { "tregsvr",                      90, "Trojan.Win32.Loader"     },
    { ".bpl",                         60, "Trojan.Win32.Loader"     },
    { "mierpreter",                   95, "Backdoor.Win32.Meterpreter" },
    { "mimikatz",                     95, "HackTool.Win32.Mimikatz" },
    { NULL, 0, NULL }
};

/* 朴素子串查找（大小写敏感，与本项目扫描器口径一致）。
 * 直接使用 strstr，是因为脚本块文本是原始大小写；如需忽略大小写，
 * 生产版应先把内容折叠成小写再匹配（见 script_scan.c 的 make_folded）。 */
static int FindRule(const char *text, int len, const char **outName)
{
    for (int i = 0; g_rules[i].needle; i++) {
        const char *p = text;
        const char *end = text + len;
        size_t nl = strlen(g_rules[i].needle);
        while (p < end) {
            const char *q = p;
            size_t k = 0;
            while (k < nl && (q + k) < end && q[k] == g_rules[i].needle[k]) k++;
            if (k == nl) { *outName = g_rules[i].name; return g_rules[i].sev; }
            p++;
        }
    }
    return 0;
}

/* ============================ IAntimalwareProvider ========================== */

class OurAmsiProvider : public IAntimalwareProvider
{
public:
    /* --- IUnknown --- */
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IAntimalwareProvider)) {
            *ppv = static_cast<IAntimalwareProvider *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override  { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        LONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }

    /* --- IAntimalwareProvider --- */
    STDMETHODIMP Scan(IAmsiStream *stream, AMSI_RESULT *result) override
    {
        if (!stream || !result) return E_INVALIDARG;
        *result = AMSI_RESULT_NOT_DETECTED;
        InterlockedIncrement(&g_scanCount);

        DWORD t0 = GetTickCount();

        /* 关键工程点 1：按 AMSI 规范分块读取内容，绝不无限读 */
        ULONGLONG total = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(total), (PBYTE)&total, NULL)) || total == 0)
            return S_OK;

        /* 只审前 1MB —— 超过这个量的脚本块少见，审它划不来 */
        ULONGLONG want = total > (1ULL << 20) ? (1ULL << 20) : total;
        PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)want + 1);
        if (!buf) return E_OUTOFMEMORY;

        ULONGLONG got = 0;
        BYTE chunk[8192];
        while (got < want) {
            /* 关键工程点 2：每块读完检查时间预算，超时立刻按"未检出"收工 */
            if (GetTickCount() - t0 > 5) { HeapFree(GetProcessHeap(), 0, buf); return S_OK; }

            ULONG read = 0;
            if (FAILED(stream->Read((ULONG)got, sizeof(chunk), chunk, &read)) || read == 0) break;
            ULONG take = read;
            if (got + take > want) take = (ULONG)(want - got);
            memcpy(buf + got, chunk, take);
            got += take;
        }
        buf[got] = 0;

        const char *name = NULL;
        int sev = FindRule((const char *)buf, (int)got, &name);
        if (sev >= 80) {
            *result = AMSI_RESULT_DETECTED;
            /* 真实项目里这里通过 ETW/日志把检测名吐出去；骨架只写调试输出 */
            OutputDebugStringA("[AMSI] DETECTED: ");
            OutputDebugStringA(name ? name : "(rule)");
            OutputDebugStringA("\n");
        } else if (sev > 0) {
            *result = AMSI_RESULT_SUSPICIOUS;   /* 让宿主弹"是否继续" */
        }

        HeapFree(GetProcessHeap(), 0, buf);
        return S_OK;
    }

    STDMETHODIMP_(void) CloseSession(ULONGLONG session) override { UNREFERENCED_PARAMETER(session); }

    STDMETHODIMP DisplayName(LPWSTR *displayName) override
    {
        /* 必须返回一个可供宿主显示的字符串，分配方式：CoTaskMemAlloc */
        if (!displayName) return E_POINTER;
        const wchar_t *n = L"自建静态查杀引擎(本项目)";
        size_t cb = (wcslen(n) + 1) * sizeof(wchar_t);
        *displayName = (LPWSTR)CoTaskMemAlloc(cb);
        if (!*displayName) return E_OUTOFMEMORY;
        memcpy(*displayName, n, cb);
        return S_OK;
    }

    OurAmsiProvider() : m_ref(1) {}
private:
    ~OurAmsiProvider() {}
    LONG m_ref;
};

/* ============================== 类工厂 & 导出 ============================== */

/* 注意：真实实现还要实现 IAntimalwareProvider2（全消息通知），
 * 以及可选 IClassFactory2。这里给出最小可用集合。 */

class OurClassFactory : public IClassFactory
{
public:
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = NULL;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
            *ppv = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override  { return 2; }
    STDMETHODIMP_(ULONG) Release() override { return 1; }

    STDMETHODIMP CreateInstance(IUnknown *outer, REFIID riid, void **ppv) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        OurAmsiProvider *p = new (std::nothrow) OurAmsiProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL lock) override { UNREFERENCED_PARAMETER(lock); return S_OK; }
};

static OurClassFactory g_factory;

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    /* 生产化建议：不要在 DllMain 里调用可能加载其它 DLL 的 API */
    if (reason == DLL_PROCESS_ATTACH) {
        OutputDebugStringA("[AMSI] our provider loaded\n");
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    if (!ppv) return E_POINTER;
    if (!IsEqualCLSID(rclsid, CLSID_OurAmsiProvider)) return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow(void) { return S_FALSE; }

/* --- 注册/注销由脚本做（见 ..\注册AMSI提供程序.ps1），
 *     这里也提供 DllRegisterServer 以便 regsvr32 方式注册 --- */
STDAPI DllRegisterServer(void)
{
    wchar_t dll[MAX_PATH];
    HMODULE hm = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCWSTR)&DllRegisterServer, &hm);
    if (!GetModuleFileNameW(hm, dll, MAX_PATH)) return SELFREG_E_CLASS;

    wchar_t clsid[64];
    StringFromGUID2(CLSID_OurAmsiProvider, clsid, 64);

    wchar_t key[512];
    /* 1) AMSI 的 provider 列表 */
    StringCchPrintfW(key, 512, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsid);
    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    RegCloseKey(hk);

    /* 2) COM 的 InprocServer32（AMSI 通过 COM 创建这个对象） */
    StringCchPrintfW(key, 512, L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return SELFREG_E_CLASS;
    RegSetValueExW(hk, NULL, 0, REG_SZ, (const BYTE *)dll, (DWORD)((wcslen(dll) + 1) * sizeof(wchar_t)));
    RegSetValueExW(hk, L"ThreadingModel", 0, REG_SZ, (const BYTE *)L"Both", 10 * sizeof(wchar_t));
    RegCloseKey(hk);
    return S_OK;
}

STDAPI DllUnregisterServer(void)
{
    wchar_t clsid[64];
    StringFromGUID2(CLSID_OurAmsiProvider, clsid, 64);
    wchar_t key[512];
    StringCchPrintfW(key, 512, L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", clsid);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
    StringCchPrintfW(key, 512, L"SOFTWARE\\Classes\\CLSID\\%s", clsid);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, key);
    return S_OK;
}
