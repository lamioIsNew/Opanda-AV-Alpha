/* scanner_api.c -- scanner.dll 的 C ABI 实现层
 *
 * 这一层不复制扫描逻辑，只做：
 *   路径编码转换 -> 串行化 -> 调用 scan_one_file() -> 拷贝结构化结果。
 * 这样 CLI（scan.exe）和 GUI 用的是同一套判定代码，不会出现两套结论。
 */
#include "scanner_api.h"
#include "scan_output.h"
#include "signature_scan.h"
#include "hardware.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SCANNER_VERSION_STRING "1.1.0-dll-20261024"

/* 来自 scan_main.c */
extern void scan_one_file(const char *path);
extern void scan_get_outcome(ScannerResult *out);
extern void scan_set_lib_mode(int on);

/* 读共享 / 重载独占：多线程扫描可以并行，reload 时短暂阻塞所有扫描。 */
static SRWLOCK g_scan_lock = SRWLOCK_INIT;
static INIT_ONCE g_sigdb_once = INIT_ONCE_STATIC_INIT;
static INIT_ONCE g_scaler_once = INIT_ONCE_STATIC_INIT;
static int g_db_loaded = 0;
static int g_db_count = 0;
static int g_scaler_loaded = 0;
static int g_scaler_tried = 0;

extern int load_scaler(const char *path);

/* 在 DLL 同级 / 上级目录找 scaler.txt；找不到时模型分支不可用 */
static BOOL CALLBACK scaler_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    HMODULE hm = NULL;
    char dir[1024];
    char cand[1200];
    char *p;
    (void)once; (void)param; (void)ctx;

    g_scaler_tried = 1;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(const void *)&scanner_abi_version, &hm))
        return TRUE;
    if (!GetModuleFileNameA(hm, dir, (DWORD)sizeof(dir))) return TRUE;
    p = strrchr(dir, '\\');
    if (!p) return TRUE;
    *p = '\0';

    static const char *const rel[] = {
        "\\scaler.txt", "\\config\\scaler.txt", "\\..\\scaler.txt", "\\..\\..\\scaler.txt",
        "\\..\\config\\scaler.txt", "\\..\\..\\config\\scaler.txt"
    };
    for (size_t i = 0; i < sizeof(rel) / sizeof(rel[0]); i++) {
        snprintf(cand, sizeof(cand), "%s%s", dir, rel[i]);
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            g_scaler_loaded = load_scaler(cand);
            break;
        }
    }
    return TRUE;
}

static void ensure_scaler(void) {
    InitOnceExecuteOnce(&g_scaler_once, scaler_init_once, NULL, NULL);
}

/* 首次扫描前自动找 DLL 同级 / ..\db / ..\..\db 下的 signatures.db。
 * 找不到就只用内置特征表，不影响任何现有结论。
 * 该函数在 reload 时由独占锁保护，其他时候由 InitOnce 保证只执行一次。 */
static void load_signature_db_now(void) {
    HMODULE hm = NULL;
    char dir[1024];
    char cand[1200];
    char *p;

    g_db_loaded = 1;
    g_db_count = 0;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(const void *)&scanner_abi_version, &hm))
        return;
    if (!GetModuleFileNameA(hm, dir, (DWORD)sizeof(dir))) return;
    p = strrchr(dir, '\\');
    if (!p) return;
    *p = '\0';

    static const char *const rel[] = {
        "\\signatures.db", "\\db\\signatures.db", "\\..\\db\\signatures.db",
        "\\..\\..\\db\\signatures.db", "\\config\\signatures.db", "\\..\\config\\signatures.db"
    };
    for (size_t i = 0; i < sizeof(rel) / sizeof(rel[0]); i++) {
        snprintf(cand, sizeof(cand), "%s%s", dir, rel[i]);
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            g_db_count = signature_db_load(cand);
            break;
        }
    }
}

static BOOL CALLBACK sigdb_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once; (void)param; (void)ctx;
    load_signature_db_now();
    return TRUE;
}

static void ensure_signature_db(void) {
    InitOnceExecuteOnce(&g_sigdb_once, sigdb_init_once, NULL, NULL);
}

static int run_ansi(const char *path, ScannerResult *out) {
    if (!path || !path[0] || !out) return 1;
    ensure_signature_db();
    ensure_scaler();
    memset(out, 0, sizeof(*out));
    if (!g_scaler_loaded) {
        snprintf(out->layer, sizeof(out->layer), "%s", "错误");
        snprintf(out->detail, sizeof(out->detail), "%s",
                 "缺少 scaler.txt（应与 scanner.dll 同目录或上级目录）");
        return 2;
    }

    AcquireSRWLockShared(&g_scan_lock);   /* 多线程扫描可并行；reload 时独占 */
    scan_one_file(path);
    scan_get_outcome(out);
    ReleaseSRWLockShared(&g_scan_lock);

    if (out->layer[0] && strcmp(out->layer, "错误") == 0) return 2;
    if (!out->bracket[0]) return 2;
    return 0;
}

unsigned int scanner_abi_version(void) {
    return SCANNER_ABI_VERSION;
}

const char *scanner_version(void) {
    return SCANNER_VERSION_STRING;
}

int scanner_scan_file_a(const char *path_ansi, ScannerResult *out) {
    return run_ansi(path_ansi, out);
}

int scanner_scan_file_w(const wchar_t *path, ScannerResult *out) {
    char a[65536];
    int n;
    if (!path || !path[0] || !out) return 1;
    n = WideCharToMultiByte(CP_ACP, 0, path, -1, a, (int)sizeof(a), NULL, NULL);
    if (n <= 0) return -1;
    return run_ansi(a, out);
}

int scanner_scan_file_u8(const char *path_utf8, ScannerResult *out) {
    wchar_t w[32768];
    char a[65536];
    int n;
    if (!path_utf8 || !path_utf8[0] || !out) return 1;
    n = MultiByteToWideChar(CP_UTF8, 0, path_utf8, -1, w, (int)(sizeof(w) / sizeof(w[0])));
    if (n <= 0) return -1;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, a, (int)sizeof(a), NULL, NULL);
    if (n <= 0) return -1;
    return run_ansi(a, out);
}

int scanner_result_level(const ScannerResult *r) {
    if (!r || !r->bracket[0]) return 0;
    if (strncmp(r->bracket, "[HIGH RISK", 10) == 0) return 3;
    if (strncmp(r->bracket, "[SUSPICIOUS", 11) == 0) return 2;
    if (strcmp(r->bracket, "[NORMAL]") == 0) return 1;
    if (strncmp(r->bracket, "[TRUSTED", 8) == 0) return 1;
    if (strncmp(r->bracket, "[PACKED", 7) == 0) return 4;
    if (strncmp(r->bracket, "[SKIP]", 6) == 0) return 5;
    return 0;
}

int scanner_signature_db_count(void) {
    int n;
    ensure_signature_db();
    AcquireSRWLockShared(&g_scan_lock);
    n = (g_db_count > 0) ? g_db_count : signature_db_count();
    ReleaseSRWLockShared(&g_scan_lock);
    return n;
}

int scanner_reload_signature_db(void) {
    int n;
    AcquireSRWLockExclusive(&g_scan_lock);
    signature_db_clear();
    load_signature_db_now();          /* 独占锁内强制重载 */
    n = g_db_count;
    ReleaseSRWLockExclusive(&g_scan_lock);
    return n;
}

int scanner_get_hardware_info(ScannerHardwareInfo *out) {
    return hardware_query(out);
}

/* DLL 加载时设置一次库模式：静默 + 关闭 pe_vm 联动。
 * 不能放在 run_ansi() 里，否则并行扫描时会对同一组全局变量重复写。 */
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        scan_set_lib_mode(1);
    }
    return TRUE;
}
