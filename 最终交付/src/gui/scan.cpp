/* scan.cpp -- DLL 加载、扫描线程、历史/隔离区/设置/驱动状态 */
#include "app.h"
#include "qtn_crypto.h"

#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

#ifndef FIND_FIRST_EX_LARGE_FETCH
#define FIND_FIRST_EX_LARGE_FETCH 2
#endif

/* ---------------- DLL 入口 ---------------- */
typedef int (__cdecl *PFN_SCAN_W)(const wchar_t *, ScannerResult *);
typedef int (__cdecl *PFN_LEVEL)(const ScannerResult *);
typedef const char *(__cdecl *PFN_VERSION)(void);
typedef unsigned int (__cdecl *PFN_ABI)(void);
typedef int (__cdecl *PFN_DBCOUNT)(void);
typedef int (__cdecl *PFN_RELOAD)(void);
typedef int (__cdecl *PFN_HWINFO)(ScannerHardwareInfo *);

static HMODULE g_dll = nullptr;
static PFN_SCAN_W p_scan_w = nullptr;
static PFN_LEVEL p_level = nullptr;
static PFN_VERSION p_version = nullptr;
static PFN_ABI p_abi = nullptr;
static PFN_DBCOUNT p_dbcount = nullptr;
static PFN_RELOAD p_reload = nullptr;
static PFN_HWINFO p_hwinfo = nullptr;

/* ---------------- 基础工具 ---------------- */
static std::wstring exe_dir() {
    wchar_t path[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(NULL, path, (DWORD)(sizeof(path) / sizeof(path[0])));
    if (n == 0) return L".";
    std::wstring s(path, n);
    size_t p = s.find_last_of(L"\\/");
    if (p != std::wstring::npos) s.resize(p);
    return s;
}

static std::wstring join_path(const std::wstring &a, const std::wstring &b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    wchar_t last = a[a.size() - 1];
    if (last == L'\\' || last == L'/') return a + b;
    return a + L"\\" + b;
}

static bool file_exists(const std::wstring &p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool dir_exists(const std::wstring &p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static void ensure_dir(const std::wstring &p) {
    if (p.empty()) return;
    std::wstring cur;
    for (size_t i = 0; i < p.size(); i++) {
        cur += p[i];
        if ((p[i] == L'\\' || p[i] == L'/') && cur.size() > 3) CreateDirectoryW(cur.c_str(), NULL);
    }
    CreateDirectoryW(p.c_str(), NULL);
}

static std::wstring file_name_of(const std::wstring &p) {
    size_t x = p.find_last_of(L"\\/");
    return (x == std::wstring::npos) ? p : p.substr(x + 1);
}

static std::string w2u(const std::wstring &w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring u2w(const std::string &s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring now_text() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t b[64];
    swprintf(b, 64, L"%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::wstring(b);
}

static std::wstring compact_time() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t b[32];
    swprintf(b, 32, L"%04d%02d%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::wstring(b);
}

static std::string read_utf8(const std::wstring &path) {
    std::string out;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return out;
    char buf[8192];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) out.append(buf, got);
    CloseHandle(h);
    if (out.size() >= 3 && (unsigned char)out[0] == 0xEF &&
        (unsigned char)out[1] == 0xBB && (unsigned char)out[2] == 0xBF)
        out.erase(0, 3);
    return out;
}

static void write_utf8(const std::wstring &path, const std::string &data, bool append) {
    ensure_dir([&]() {
        size_t p = path.find_last_of(L"\\/");
        return (p == std::wstring::npos) ? std::wstring() : path.substr(0, p);
    }());
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, append ? OPEN_ALWAYS : CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    if (append) {
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        SetFilePointerEx(h, zero, NULL, FILE_END);
        LARGE_INTEGER size;
        GetFileSizeEx(h, &size);
        if (size.QuadPart == 0) {
            const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
            DWORD w = 0;
            WriteFile(h, bom, 3, &w, NULL);
        }
    } else {
        const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
        DWORD w = 0;
        WriteFile(h, bom, 3, &w, NULL);
    }
    DWORD w = 0;
    if (!data.empty()) WriteFile(h, data.data(), (DWORD)data.size(), &w, NULL);
    CloseHandle(h);
}

static std::vector<std::wstring> split_tabs(const std::wstring &line) {
    std::vector<std::wstring> out;
    size_t start = 0;
    while (true) {
        size_t p = line.find(L'\t', start);
        if (p == std::wstring::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

static void split_lines(const std::wstring &all, std::vector<std::wstring> &lines) {
    size_t start = 0;
    while (start < all.size()) {
        size_t p = all.find(L'\n', start);
        std::wstring line = (p == std::wstring::npos) ? all.substr(start) : all.substr(start, p - start);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty()) lines.push_back(line);
        if (p == std::wstring::npos) break;
        start = p + 1;
    }
}

static std::wstring error_text(DWORD err) {
    wchar_t *buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    std::wstring s;
    if (n && buf) {
        s.assign(buf, n);
        while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' ')) s.pop_back();
    } else {
        wchar_t b[64];
        swprintf(b, 64, L"错误码 %lu", (unsigned long)err);
        s = b;
    }
    if (buf) LocalFree(buf);
    return s;
}

/* ---------------- 路径 / 设置 ---------------- */
std::wstring scanner_data_dir() {
    static std::wstring d = exe_dir();
    return d;
}

std::wstring scanner_db_display_path() {
    std::wstring base = scanner_data_dir();
    const wchar_t *rels[] = {
        L"signatures.db", L"db\\signatures.db", L"..\\db\\signatures.db",
        L"..\\..\\db\\signatures.db", L"config\\signatures.db",
        L"..\\config\\signatures.db"
    };
    for (const wchar_t *r : rels) {
        std::wstring p = join_path(base, r);
        if (file_exists(p)) {
            wchar_t full[MAX_PATH * 2];
            DWORD n = GetFullPathNameW(p.c_str(), (DWORD)(sizeof(full) / sizeof(full[0])), full, NULL);
            return n > 0 && n < (DWORD)(sizeof(full) / sizeof(full[0])) ? std::wstring(full) : p;
        }
    }
    return L"";
}

static std::wstring settings_path() {
    return join_path(join_path(scanner_data_dir(), L"config"), L"settings.ini");
}

void scanner_load_settings() {
    std::wstring ini = settings_path();
    g_app.settings.theme = (int)GetPrivateProfileIntW(L"ui", L"theme", 0, ini.c_str());
    g_app.settings.maxMb = (int)GetPrivateProfileIntW(L"scan", L"max_mb", 256, ini.c_str());
    g_app.settings.animations = (int)GetPrivateProfileIntW(L"ui", L"animations", 1, ini.c_str());
    g_app.settings.autoQuarantine = (int)GetPrivateProfileIntW(L"scan", L"auto_quarantine", 0, ini.c_str());
    g_app.settings.minimizeToTray = (int)GetPrivateProfileIntW(L"ui", L"minimize_to_tray", 0, ini.c_str());
    g_app.settings.keyMode = (int)GetPrivateProfileIntW(L"crypto", L"key_mode", 0, ini.c_str());
    if (g_app.settings.keyMode != 0 && g_app.settings.keyMode != 1) g_app.settings.keyMode = 0;
    if (!qtn_set_key_mode(g_app.settings.keyMode)) {
        /* SGX 在无 SGX 的机器/未编译 enclave 时不可用：安全回退 TPM。 */
        g_app.settings.keyMode = 0;
        qtn_set_key_mode(0);
    }
    if (g_app.settings.theme < 0 || g_app.settings.theme > 2) g_app.settings.theme = 0;
    if (g_app.settings.maxMb < 16) g_app.settings.maxMb = 16;
    if (g_app.settings.maxMb > 4096) g_app.settings.maxMb = 4096;
    if (g_app.settings.animations < 0) g_app.settings.animations = 0;
    g_app.themeMode = (ThemeMode)g_app.settings.theme;
}

void scanner_save_settings() {
    std::wstring ini = settings_path();
    ensure_dir([&]() {
        size_t p = ini.find_last_of(L"\\/");
        return (p == std::wstring::npos) ? std::wstring() : ini.substr(0, p);
    }());
    wchar_t b[32];
    swprintf(b, 32, L"%d", g_app.settings.theme);
    WritePrivateProfileStringW(L"ui", L"theme", b, ini.c_str());
    swprintf(b, 32, L"%d", g_app.settings.maxMb);
    WritePrivateProfileStringW(L"scan", L"max_mb", b, ini.c_str());
    swprintf(b, 32, L"%d", g_app.settings.animations);
    WritePrivateProfileStringW(L"ui", L"animations", b, ini.c_str());
    swprintf(b, 32, L"%d", g_app.settings.autoQuarantine);
    WritePrivateProfileStringW(L"scan", L"auto_quarantine", b, ini.c_str());
    swprintf(b, 32, L"%d", g_app.settings.minimizeToTray);
    WritePrivateProfileStringW(L"ui", L"minimize_to_tray", b, ini.c_str());
    swprintf(b, 32, L"%d", g_app.settings.keyMode);
    WritePrivateProfileStringW(L"crypto", L"key_mode", b, ini.c_str());
}

void open_data_dir() {
    std::wstring d = scanner_data_dir();
    ShellExecuteW(NULL, L"open", d.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

/* ---------------- DLL ---------------- */
bool scanner_runtime_init() {
    std::wstring dll = join_path(scanner_data_dir(), L"scanner.dll");
    g_dll = LoadLibraryW(dll.c_str());
    if (!g_dll) {
        std::wstring msg = L"无法加载扫描引擎：\n" + dll + L"\n\n" + error_text(GetLastError());
        MessageBoxW(NULL, msg.c_str(), L"恶意软件扫描器", MB_OK | MB_ICONERROR);
        return false;
    }
    p_scan_w = (PFN_SCAN_W)GetProcAddress(g_dll, "scanner_scan_file_w");
    p_level = (PFN_LEVEL)GetProcAddress(g_dll, "scanner_result_level");
    p_version = (PFN_VERSION)GetProcAddress(g_dll, "scanner_version");
    p_abi = (PFN_ABI)GetProcAddress(g_dll, "scanner_abi_version");
    p_dbcount = (PFN_DBCOUNT)GetProcAddress(g_dll, "scanner_signature_db_count");
    p_reload = (PFN_RELOAD)GetProcAddress(g_dll, "scanner_reload_signature_db");
    p_hwinfo = (PFN_HWINFO)GetProcAddress(g_dll, "scanner_get_hardware_info");

    if (!p_scan_w || !p_level) {
        MessageBoxW(NULL, L"scanner.dll 缺少导出函数（scanner_scan_file_w / scanner_result_level）。",
                    L"恶意软件扫描器", MB_OK | MB_ICONERROR);
        FreeLibrary(g_dll);
        g_dll = nullptr;
        return false;
    }
    g_app.abiVersion = p_abi ? (int)p_abi() : 0;
    if (g_app.abiVersion != 1) {
        MessageBoxW(NULL, L"scanner.dll 的 ABI 版本不匹配。", L"恶意软件扫描器", MB_OK | MB_ICONERROR);
        FreeLibrary(g_dll);
        g_dll = nullptr;
        return false;
    }
    if (p_version) g_app.engineVersion = u2w(std::string(p_version()));
    g_app.engineReady = true;
    scanner_db_count();
    scanner_refresh_hardware();
    return true;
}

void scanner_runtime_shutdown() {
    if (g_app.scanThread) {
        g_app.cancelRequested.store(true);
        DWORD wr = WaitForSingleObject(g_app.scanThread, 30000);
        if (wr != WAIT_OBJECT_0)
            return; /* 扫描线程仍在 DLL 内，绝不能在此时卸载代码 */
        CloseHandle(g_app.scanThread);
        g_app.scanThread = nullptr;
    }
    if (g_dll) {
        FreeLibrary(g_dll);
        g_dll = nullptr;
    }
    p_scan_w = nullptr;
    p_level = nullptr;
    p_version = nullptr;
    p_abi = nullptr;
    p_dbcount = nullptr;
    p_reload = nullptr;
    p_hwinfo = nullptr;
    g_app.engineReady = false;
}

int scanner_db_count() {
    if (p_dbcount) g_app.dbCount = p_dbcount();
    g_app.dbPath = scanner_db_display_path();
    return g_app.dbCount;
}

int scanner_db_reload() {
    if (!p_reload) return g_app.dbCount;
    g_app.dbCount = p_reload();
    g_app.dbPath = scanner_db_display_path();
    g_app.show_toast(L"特征库已重新加载：" + std::to_wstring(g_app.dbCount) + L" 条");
    return g_app.dbCount;
}

void scanner_refresh_hardware() {
    memset(&g_app.hw, 0, sizeof(g_app.hw));
    g_app.hwReady = false;
    if (p_hwinfo && p_hwinfo(&g_app.hw) == 0) {
        g_app.hwReady = true;
    } else {
        strncpy_s(g_app.hw.detail, sizeof(g_app.hw.detail),
                  "scanner.dll 未导出 hardware 查询，或查询失败", _TRUNCATE);
    }
    g_app.hwQueriedAt = GetTickCount64();
}

void scanner_clear_results() {
    if (g_app.scanning.load()) {
        g_app.show_toast(L"扫描进行中，先停止再清空");
        return;
    }
    g_app.results.clear();
    g_app.pending.clear();
    g_app.selectedResult = -1;
    g_app.scrollScan = 0.0f;
    g_app.stats = ScanStats();
    g_app.currentFile.clear();
    g_app.scanPath.clear();
    g_app.scanRootLabel.clear();
    g_app.scanFinished = false;
    g_app.scanCanceled = false;
    g_app.show_toast(L"结果列表已清空");
}

void open_log_dir() {
    std::wstring d = join_path(scanner_data_dir(), L"logs");
    ensure_dir(d);
    ShellExecuteW(NULL, L"open", d.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

/* ---------------- 历史 ---------------- */
void scanner_load_history() {
    g_app.history.clear();
    std::wstring all = u2w(read_utf8(join_path(join_path(scanner_data_dir(), L"logs"), L"history.tsv")));
    std::vector<std::wstring> lines;
    split_lines(all, lines);
    for (const auto &line : lines) {
        std::vector<std::wstring> f = split_tabs(line);
        if (f.size() < 7) continue;
        HistoryEntry h;
        h.time = f[0];
        h.path = f[1];
        h.bracket = f[2];
        h.caro = f[3];
        h.detail = f[4];
        h.score = wcstod(f[5].c_str(), NULL);
        h.level = (int)wcstol(f[6].c_str(), NULL, 10);
        g_app.history.push_back(h);
        if (g_app.history.size() >= 500) break;
    }
}

void scanner_save_history() {
    std::string out;
    for (const auto &h : g_app.history) {
        out += w2u(h.time); out += '\t';
        out += w2u(h.path); out += '\t';
        out += w2u(h.bracket); out += '\t';
        out += w2u(h.caro); out += '\t';
        out += w2u(h.detail); out += '\t';
        char b[64];
        snprintf(b, sizeof(b), "%.2f", h.score);
        out += b; out += '\t';
        out += std::to_string(h.level);
        out += '\n';
    }
    write_utf8(join_path(join_path(scanner_data_dir(), L"logs"), L"history.tsv"), out, false);
}

void scanner_clear_history() {
    g_app.history.clear();
    scanner_save_history();
    g_app.selectedLog = -1;
    g_app.scrollLog = 0;
    g_app.show_toast(L"扫描日志已清空");
}

/* ---------------- 隔离区 ---------------- */
static std::wstring quarantine_index() {
    return join_path(join_path(scanner_data_dir(), L"quarantine"), L"index.tsv");
}

void scanner_load_quarantine() {
    g_app.quarantine.clear();
    std::wstring all = u2w(read_utf8(quarantine_index()));
    std::vector<std::wstring> lines;
    split_lines(all, lines);
    for (const auto &line : lines) {
        std::vector<std::wstring> f = split_tabs(line);
        if (f.size() < 6) continue;
        QuarantineEntry q;
        q.time = f[0];
        q.original = f[1];
        q.stored = f[2];
        q.sha = f[3];
        q.bracket = f[4];
        q.caro = f[5];
        g_app.quarantine.push_back(q);
        if (g_app.quarantine.size() >= 1000) break;
    }
    g_app.selectedQuar = g_app.quarantine.empty() ? -1 : 0;
    g_app.scrollQuar = 0;
}

void scanner_save_quarantine() {
    std::string out;
    for (const auto &q : g_app.quarantine) {
        out += w2u(q.time); out += '\t';
        out += w2u(q.original); out += '\t';
        out += w2u(q.stored); out += '\t';
        out += w2u(q.sha); out += '\t';
        out += w2u(q.bracket); out += '\t';
        out += w2u(q.caro);
        out += '\n';
    }
    write_utf8(quarantine_index(), out, false);
}

void scanner_quarantine_selected() {
    if (g_app.selectedResult < 0 || g_app.selectedResult >= (int)g_app.results.size()) {
        g_app.show_toast(L"请先在结果列表中选择一个文件");
        return;
    }
    ScanEntry &e = g_app.results[(size_t)g_app.selectedResult];
    if (e.quarantined) {
        g_app.show_toast(L"该文件已在隔离区");
        return;
    }
    if (e.level < 2) {
        g_app.show_toast(L"只隔离疑似或高危项");
        return;
    }
    std::wstring qdir = join_path(scanner_data_dir(), L"quarantine");
    ensure_dir(qdir);
    std::wstring base = file_name_of(e.path);
    if (base.empty()) base = L"file";
    std::wstring stored = join_path(qdir, compact_time() + L"_" + base + L".qtn");
    for (int n = 2; file_exists(stored); n++) {
        wchar_t suffix[16];
        swprintf(suffix, 16, L"_%d", n);
        size_t dot = base.find_last_of(L'.');
        std::wstring named = dot == std::wstring::npos
                                 ? base + suffix
                                 : base.substr(0, dot) + suffix + base.substr(dot);
        stored = join_path(qdir, compact_time() + L"_" + named + L".qtn");
    }
    {
        std::wstring qerr;
        if (!qtn_quarantine_file(e.path, stored, qerr)) {
            g_app.show_toast(L"隔离失败：" + qerr);
            return;
        }
    }
    QuarantineEntry q;
    q.time = now_text();
    q.original = e.path;
    q.stored = stored;
    q.sha = u2w(std::string(e.r.sha));
    q.bracket = u2w(std::string(e.r.bracket));
    q.caro = u2w(std::string(e.r.caro));
    g_app.quarantine.insert(g_app.quarantine.begin(), q);
    if (g_app.quarantine.size() > 1000) g_app.quarantine.resize(1000);
    g_app.selectedQuar = 0;
    g_app.scrollQuar = 0;
    scanner_save_quarantine();
    e.quarantined = true;
    g_app.show_toast(L"已隔离：" + base);
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}

void scanner_restore_selected() {
    if (g_app.selectedQuar < 0 || g_app.selectedQuar >= (int)g_app.quarantine.size()) {
        g_app.show_toast(L"请先选择一个隔离项");
        return;
    }
    QuarantineEntry q = g_app.quarantine[(size_t)g_app.selectedQuar];
    if (!file_exists(q.stored)) {
        g_app.show_toast(L"隔离文件已不存在");
        return;
    }
    if (file_exists(q.original)) {
        g_app.show_toast(L"原位置已有同名文件，无法恢复");
        return;
    }
    size_t p = q.original.find_last_of(L"\\/");
    if (p != std::wstring::npos) ensure_dir(q.original.substr(0, p));
    {
        std::wstring qerr;
        if (!qtn_restore_file(q.stored, q.original, qerr)) {
            g_app.show_toast(L"恢复失败：" + qerr);
            return;
        }
    }
    g_app.quarantine.erase(g_app.quarantine.begin() + g_app.selectedQuar);
    g_app.selectedQuar = g_app.quarantine.empty() ? -1 : 0;
    g_app.scrollQuar = 0;
    scanner_save_quarantine();
    g_app.show_toast(L"已恢复文件");
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}

void scanner_delete_selected() {
    if (g_app.selectedQuar < 0 || g_app.selectedQuar >= (int)g_app.quarantine.size()) {
        g_app.show_toast(L"请先选择一个隔离项");
        return;
    }
    QuarantineEntry q = g_app.quarantine[(size_t)g_app.selectedQuar];
    std::wstring msg = L"永久删除隔离文件？\n\n" + q.original;
    if (MessageBoxW(g_app.hwnd, msg.c_str(), L"删除隔离项",
                    MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;
    if (file_exists(q.stored) && !DeleteFileW(q.stored.c_str())) {
        g_app.show_toast(L"删除失败：" + error_text(GetLastError()));
        return;
    }
    g_app.quarantine.erase(g_app.quarantine.begin() + g_app.selectedQuar);
    g_app.selectedQuar = g_app.quarantine.empty() ? -1 : 0;
    g_app.scrollQuar = 0;
    scanner_save_quarantine();
    g_app.show_toast(L"已永久删除");
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}

/* ---------------- 驱动状态 ---------------- */
void scanner_refresh_driver() {
    g_app.driverState = L"未安装";
    g_app.driverDetail = L"未检测到 MalwareScannerDrv 服务";
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        g_app.driverDetail = L"无法连接服务控制器：" + error_text(GetLastError());
        return;
    }
    SC_HANDLE svc = OpenServiceW(scm, L"MalwareScannerDrv", SERVICE_QUERY_STATUS);
    if (!svc) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_DOES_NOT_EXIST)
            g_app.driverDetail = L"查询服务失败：" + error_text(e);
        CloseServiceHandle(scm);
        return;
    }
    SERVICE_STATUS_PROCESS st;
    DWORD need = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&st, sizeof(st), &need)) {
        switch (st.dwCurrentState) {
            case SERVICE_RUNNING: g_app.driverState = L"运行中"; break;
            case SERVICE_STOPPED: g_app.driverState = L"已停止"; break;
            case SERVICE_START_PENDING: g_app.driverState = L"启动中"; break;
            case SERVICE_STOP_PENDING: g_app.driverState = L"停止中"; break;
            default: g_app.driverState = L"未知"; break;
        }
        wchar_t b[160];
        swprintf(b, 160, L"服务 MalwareScannerDrv · 进程 PID %lu", (unsigned long)st.dwProcessId);
        g_app.driverDetail = b;
    } else {
        g_app.driverDetail = L"读取服务状态失败：" + error_text(GetLastError());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

/* ---------------- 扫描线程 ---------------- */
struct ScanJob {
    std::vector<std::wstring> roots;
    std::vector<std::wstring> files;   /* 先枚举，再多线程扫描 */
    int maxMb = 256;
    std::atomic<ULONGLONG> lastPost{0};
    std::atomic<int> count{0};
};

static bool is_excluded_dir(const wchar_t *name) {
    static const wchar_t *list[] = {
        L"$Recycle.Bin", L"System Volume Information", L"WinSxS", L"Installer",
        L"SoftwareDistribution", L"servicing", L"assembly", L"Microsoft.NET",
        L"Windows Defender", L"CSC", L"Recovery", L"Boot", L"EFI", L"PerfLogs",
        L"$WinREAgent", L"Config.Msi", L"MSOCache", L"node_modules", L".git",
        L".svn", L"__pycache__"
    };
    for (const wchar_t *x : list) if (_wcsicmp(name, x) == 0) return true;
    return false;
}

static bool is_own_file(const wchar_t *name) {
    static const wchar_t *list[] = {
        L"scanner.dll", L"ScannerUI.exe", L"scan.exe", L"scan_test.exe",
        L"scanner_test.exe", L"sigdb_builder.exe", L"signatures.db", L"scaler.txt",
        L"history.tsv", L"index.tsv"
    };
    for (const wchar_t *x : list) if (_wcsicmp(name, x) == 0) return true;
    return false;
}

static void post_tick(ScanJob *job, bool force) {
    ULONGLONG now = GetTickCount64();
    ULONGLONG prev = job->lastPost.load();
    if (force || now - prev >= 70) {
        if (job->lastPost.compare_exchange_strong(prev, now)) {
            PostMessageW(g_app.hwnd, WM_APP_SCAN_TICK, 0, 0);
        }
    }
}

static int fallback_level(const ScannerResult &r) {
    if (strncmp(r.bracket, "[HIGH RISK", 10) == 0) return 3;
    if (strncmp(r.bracket, "[SUSPICIOUS", 11) == 0) return 2;
    if (strcmp(r.bracket, "[NORMAL]") == 0) return 1;
    if (strncmp(r.bracket, "[TRUSTED", 8) == 0) return 1;
    if (strncmp(r.bracket, "[PACKED", 7) == 0) return 4;
    if (strncmp(r.bracket, "[SKIP]", 6) == 0) return 5;
    return 0;
}

static void scan_one(ScanJob *job, const std::wstring &path) {
    if (g_app.cancelRequested.load()) return;
    ScannerResult r;
    memset(&r, 0, sizeof(r));
    int rc = p_scan_w ? p_scan_w(path.c_str(), &r) : 2;
    ScanEntry e;
    e.path = path;
    e.r = r;
    e.level = (rc == 0 && p_level) ? p_level(&r) : fallback_level(r);
    if (rc != 0) {
        e.level = 0;
        if (!e.r.bracket[0]) {
            strncpy(e.r.bracket, "[ERROR]", sizeof(e.r.bracket) - 1);
            if (!e.r.detail[0])
                snprintf(e.r.detail, sizeof(e.r.detail), "扫描失败（返回码 %d）", rc);
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_app.resultMutex);
        g_app.pending.push_back(e);
        g_app.currentFile = path;
    }
    int done = job->count.fetch_add(1) + 1;
    post_tick(job, e.level >= 3);
    if ((done & 0x3F) == 0) Sleep(0);
}

static void scan_dir(ScanJob *job, const std::wstring &root) {
    std::vector<std::wstring> stack;
    stack.push_back(root);
    const long long limit = (long long)job->maxMb * 1024LL * 1024LL;

    while (!stack.empty() && !g_app.cancelRequested.load()) {
        std::wstring dir = stack.back();
        stack.pop_back();
        std::wstring pattern = dir;
        if (!pattern.empty() && pattern.back() != L'\\' && pattern.back() != L'/') pattern += L'\\';
        pattern += L'*';

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                    FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) continue;

        do {
            if (g_app.cancelRequested.load()) break;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring path = join_path(dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                if (is_excluded_dir(fd.cFileName)) continue;
                if (stack.size() < 4096) stack.push_back(path);
            } else {
                if (is_own_file(fd.cFileName)) continue;
                LARGE_INTEGER sz;
                sz.LowPart = fd.nFileSizeLow;
                sz.HighPart = (LONG)fd.nFileSizeHigh;
                if (sz.QuadPart > limit) {
                    g_app.skippedCount.fetch_add(1);
                    post_tick(job, false);
                    continue;
                }
                g_app.bytesScanned.fetch_add(sz.QuadPart);
                job->files.push_back(path);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

/* 多线程扫描：CPU 是 i7-13700H（20 线程）；上限 16 个 worker。
 * 基准：500 个 System32 良性文件，1 线程 7.14s -> 16 线程 1.07s（约 6.7x），
 * 高危/疑似/正常计数完全一致。DLL 内部已改为读共享锁 + 线程局部结果。 */
static void scan_files_parallel(ScanJob *job) {
    if (job->files.empty()) return;

    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 4;
    if (hw > 16) hw = 16;   /* 16 线程在 i7-13700H 上比 12/20 更稳 */
    if (hw > job->files.size()) hw = (unsigned)job->files.size();

    std::atomic<size_t> next{0};
    std::vector<std::thread> pool;
    pool.reserve(hw);
    try {
        for (unsigned t = 0; t < hw; t++) {
            pool.emplace_back([job, &next]() {
                for (;;) {
                    if (g_app.cancelRequested.load()) break;
                    size_t i = next.fetch_add(1);
                    if (i >= job->files.size()) break;
                    scan_one(job, job->files[i]);
                }
            });
        }
    } catch (...) {
        /* 线程创建失败时，已创建的线程会继续处理；剩余任务由下面串行补齐。 */
    }
    for (auto &th : pool) th.join();

    /* 兜底：线程池创建失败或中途退出时，把剩下的文件串行跑完。 */
    for (;;) {
        if (g_app.cancelRequested.load()) break;
        size_t i = next.fetch_add(1);
        if (i >= job->files.size()) break;
        scan_one(job, job->files[i]);
    }
}

static DWORD WINAPI scan_thread(LPVOID param) {
    ScanJob *job = (ScanJob *)param;
    for (const auto &root : job->roots) {
        if (g_app.cancelRequested.load()) break;
        DWORD a = GetFileAttributesW(root.c_str());
        if (a == INVALID_FILE_ATTRIBUTES) {
            ScannerResult r;
            memset(&r, 0, sizeof(r));
            strncpy(r.bracket, "[ERROR]", sizeof(r.bracket) - 1);
            snprintf(r.detail, sizeof(r.detail), "路径不存在或无法访问");
            ScanEntry e;
            e.path = root;
            e.r = r;
            e.level = 0;
            std::lock_guard<std::mutex> lk(g_app.resultMutex);
            g_app.pending.push_back(e);
            continue;
        }
        if (a & FILE_ATTRIBUTE_DIRECTORY) scan_dir(job, root);
        else job->files.push_back(root);
    }
    scan_files_parallel(job);
    g_app.scanning.store(false);
    PostMessageW(g_app.hwnd, WM_APP_SCAN_DONE, 0, 0);
    delete job;
    return 0;
}

void scanner_start(const std::vector<std::wstring> &roots, int maxMb) {
    if (g_app.scanning.load()) {
        g_app.show_toast(L"扫描正在进行中");
        return;
    }
    if (roots.empty()) {
        g_app.show_toast(L"请先选择要扫描的文件或文件夹");
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_app.resultMutex);
        g_app.pending.clear();
        g_app.currentFile = L"正在准备…";
    }
    g_app.results.clear();
    g_app.stats = ScanStats();
    g_app.selectedResult = -1;
    g_app.scrollScan = 0;
    g_app.scanFinished = false;
    g_app.scanCanceled = false;
    g_app.scanStart = GetTickCount64();
    g_app.skippedCount.store(0);
    g_app.skippedApplied = 0;
    g_app.bytesScanned.store(0);
    g_app.cancelRequested.store(false);
    g_app.scanning.store(true);
    g_app.scanRootLabel = (roots.size() == 1) ? roots[0] : L"多个位置";
    if (roots.size() == 1) {
        g_app.scanPath = roots[0];
        DWORD a = GetFileAttributesW(roots[0].c_str());
        g_app.scanPathIsDir = (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY));
    }

    ScanJob *job = new ScanJob();
    job->roots = roots;
    job->maxMb = maxMb > 0 ? maxMb : 256;
    g_app.scanThread = CreateThread(NULL, 0, scan_thread, job, 0, NULL);
    if (!g_app.scanThread) {
        delete job;
        g_app.scanning.store(false);
        g_app.show_toast(L"无法创建扫描线程");
        return;
    }
    set_timer_for_animation();
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}

void scanner_cancel() {
    if (g_app.scanning.load()) {
        g_app.cancelRequested.store(true);
        g_app.scanCanceled = true;
        g_app.show_toast(L"正在停止扫描…");
        set_timer_for_animation();
    }
}

void scanner_join(DWORD ms) {
    if (g_app.scanThread) {
        DWORD wr = WaitForSingleObject(g_app.scanThread, ms);
        if (wr == WAIT_OBJECT_0) {
            CloseHandle(g_app.scanThread);
            g_app.scanThread = nullptr;
        }
    }
}

void scanner_apply_pending() {
    std::vector<ScanEntry> local;
    {
        std::lock_guard<std::mutex> lk(g_app.resultMutex);
        if (!g_app.pending.empty()) {
            local.swap(g_app.pending);
        }
    }

    int sc = g_app.skippedCount.load();
    if (sc > g_app.skippedApplied) {
        g_app.stats.skipped += sc - g_app.skippedApplied;
        g_app.skippedApplied = sc;
    }

    if (local.empty()) return;

    for (auto &e : local) {
        g_app.stats.files++;
        switch (e.level) {
            case 3: g_app.stats.high++; break;
            case 2: g_app.stats.suspicious++; break;
            case 1: g_app.stats.normal++; break;
            case 4: g_app.stats.packed++; break;
            case 5: g_app.stats.skipped++; break;
            default: g_app.stats.errors++; break;
        }
        if (g_app.results.size() < 5000 || e.level == 3)
            g_app.results.push_back(e);
    }
}

void scanner_on_done() {
    scanner_apply_pending();
    g_app.scanFinished = true;
    if (g_app.cancelRequested.load()) g_app.scanCanceled = true;
    if (!g_app.results.empty()) {
        int best = 0;
        for (int i = 0; i < (int)g_app.results.size(); i++) {
            if (g_app.results[(size_t)i].level > g_app.results[(size_t)best].level) best = i;
            if (g_app.results[(size_t)best].level >= 3) break;
        }
        g_app.selectedResult = best;
        g_app.scrollScan = best > 0 ? (float)(best - 1) * 56.0f : 0.0f;
    } else {
        g_app.selectedResult = -1;
    }
    const size_t before = g_app.history.size();
    std::vector<HistoryEntry> add;
    for (const auto &e : g_app.results) {
        if (e.level < 2) continue;
        HistoryEntry h;
        h.time = now_text();
        h.path = e.path;
        h.bracket = u2w(std::string(e.r.bracket));
        h.caro = u2w(std::string(e.r.caro));
        h.detail = u2w(std::string(e.r.detail));
        h.score = e.r.score;
        h.level = e.level;
        add.push_back(h);
        if (add.size() >= 100) break;
    }
    if (add.empty()) {
        HistoryEntry h;
        h.time = now_text();
        h.path = g_app.scanRootLabel;
        h.level = g_app.stats.errors > 0 ? 0 : 1;
        h.bracket = h.level == 0 ? L"[ERROR]" : L"[SCAN]";
        h.detail = g_app.scanCanceled
                       ? L"扫描已停止（用户取消）"
                       : (g_app.stats.errors > 0 ? L"扫描未完成，存在引擎错误"
                                                 : L"扫描完成，未发现需要记录的威胁");
        h.score = -1;
        add.push_back(h);
    }
    g_app.history.insert(g_app.history.begin(), add.begin(), add.end());
    if (g_app.history.size() > 500) g_app.history.resize(500);
    if (g_app.history.size() != before) scanner_save_history();

    if (g_app.scanCanceled)
        g_app.show_toast(L"扫描已停止：已扫描 " + std::to_wstring(g_app.stats.files) + L" 个文件", 3000);
    else if (g_app.stats.high > 0)
        g_app.show_toast(L"扫描完成：发现 " + std::to_wstring(g_app.stats.high) + L" 个高危文件", 3600);
    else if (g_app.stats.suspicious > 0)
        g_app.show_toast(L"扫描完成：" + std::to_wstring(g_app.stats.suspicious) + L" 个疑似文件", 3200);
    else if (g_app.stats.errors > 0 && g_app.stats.files == g_app.stats.errors)
        g_app.show_toast(L"扫描失败：" + (g_app.results.empty() ? L"引擎错误" : u2w(std::string(g_app.results[0].r.detail))), 4200);
    else
        g_app.show_toast(L"扫描完成：" + std::to_wstring(g_app.stats.files) + L" 个文件，未发现威胁", 2800);

    set_timer_for_animation();
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}

void scan_path_async(const std::wstring &path) {
    if (path.empty()) return;
    std::vector<std::wstring> roots;
    roots.push_back(path);
    scanner_start(roots, g_app.settings.maxMb);
}

void scan_quick() {
    std::vector<std::wstring> roots;
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n > 0) {
        std::wstring up(buf, n);
        std::wstring p = join_path(up, L"Desktop");
        if (dir_exists(p)) roots.push_back(p);
        p = join_path(up, L"Downloads");
        if (dir_exists(p)) roots.push_back(p);
        p = join_path(join_path(up, L"AppData\\Local"), L"Temp");
        if (dir_exists(p)) roots.push_back(p);
        p = join_path(join_path(up, L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"), L"");
        if (dir_exists(p)) roots.push_back(p);
    }
    n = GetEnvironmentVariableW(L"ProgramData", buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n > 0) {
        std::wstring p = join_path(std::wstring(buf, n),
                                   L"Microsoft\\Windows\\Start Menu\\Programs\\StartUp");
        if (dir_exists(p)) roots.push_back(p);
    }
    if (dir_exists(L"C:\\Users\\Public\\Desktop")) roots.push_back(L"C:\\Users\\Public\\Desktop");
    if (roots.empty()) {
        std::wstring up;
        n = GetEnvironmentVariableW(L"USERPROFILE", buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
        if (n > 0) up.assign(buf, n);
        if (!up.empty()) roots.push_back(up);
    }
    g_app.scanRootLabel = L"快速扫描";
    scanner_start(roots, g_app.settings.maxMb);
    g_app.scanRootLabel = L"快速扫描";
    g_app.scanPath = L"快速扫描：桌面、下载、临时目录、启动项";
    g_app.scanPathIsDir = true;
    InvalidateRect(g_app.hwnd, NULL, FALSE);
}
