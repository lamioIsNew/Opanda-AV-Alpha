/* folder_guard.c -- 用户态主动防御（第一版，纯 Win32、不碰内核/驱动）
 * ---------------------------------------------------------------------------
 * 用 ReadDirectoryChangesW 监控指定目录（默认 Downloads + Desktop）：
 *   一旦有新文件落地，且扩展名是 .exe / .dll / .ps1 / .cmd，
 *   就自动调用同目录下的 scan.exe（命令行模式，不弹界面）给它打分；
 *   判 [HIGH RISK] 就打印告警，可选（--lock）用 SetFileAttributesW 置为只读。
 *
 * 编译：
 *   gcc folder_guard.c -o folder_guard.exe -static
 *
 * 用法：
 *   folder_guard.exe                 # 只告警
 *   folder_guard.exe --lock          # 高危文件自动置只读（拦截落地）
 *   folder_guard.exe --scan <scan.exe> --scaler <scaler.txt>
 *   folder_guard.exe --dir "C:\某个目录" --dir "D:\另一个目录"
 *   folder_guard.exe --recursive     # 递归监控子目录（默认只监控本层）
 *
 * 说明与边界（第一版）：
 *   - 纯用户态轮询"目录变化"，不是实时拦截；文件已落地后才扫描。
 *   - 只认 scan.exe 的判定，不做进程行为拦截（那需要内核/ETW 回调，见后续版本）。
 *   - 不写任何东西进被监控目录，避免自我触发。
 * ---------------------------------------------------------------------------
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define MAX_WATCH   16
#define OUT_CAP     262144     /* 收集 scan.exe 输出的缓冲上限 */
#define DEDUP_SLOTS 64

/* ---------------- 全局配置 ---------------- */
static wchar_t  g_dirs[MAX_WATCH][MAX_PATH];
static int      g_ndirs   = 0;
static int      g_lock    = 0;       /* --lock：高危文件置只读 */
static int      g_recurse = 0;       /* --recursive */
static wchar_t  g_scanner[MAX_PATH];  /* scan.exe 全路径 */
static wchar_t  g_scaler [MAX_PATH];  /* scaler.txt 全路径 */

/* 简单去重：记录最近处理过的"路径+写入时间"，避免同一文件被反复扫描 */
static wchar_t  g_seen[DEDUP_SLOTS][MAX_PATH];
static DWORD    g_seenTime[DEDUP_SLOTS];
static int      g_seenIdx = 0;
static CRITICAL_SECTION g_seenLock;

/* ---------------- 小工具 ---------------- */
static void wcappend(wchar_t *dst, size_t cap, const wchar_t *src) {
    size_t d = wcslen(dst);
    if (d + 1 >= cap) return;
    wcsncat(dst, src, cap - d - 1);
}

/* 宽字符 -> UTF-8（打印用；控制台已切到 UTF-8 代码页） */
static void w2utf8(const wchar_t *w, char *out, int cap) {
    if (cap <= 0) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, NULL, NULL);
    if (n <= 0) out[0] = '\0';
}

/* UTF-8 -> 系统 ANSI(ACP)：拼接给 scan.exe 的命令行/mingw 运行时用 */
static void w2acp(const wchar_t *w, char *out, int cap) {
    if (cap <= 0) return;
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, out, cap, NULL, NULL);
    if (n <= 0) out[0] = '\0';
}

static int ext_watched(const wchar_t *name) {
    static const wchar_t *exts[] = { L".exe", L".dll", L".ps1", L".cmd" };
    const wchar_t *dot = wcsrchr(name, L'.');
    if (!dot) return 0;
    for (int i = 0; i < (int)(sizeof(exts) / sizeof(exts[0])); i++) {
        if (_wcsicmp(dot, exts[i]) == 0) return 1;
    }
    return 0;
}

/* 去重：同一路径且写入时间未变 => 视为已处理 */
static int dedup_should_skip(const wchar_t *path, DWORD wt) {
    int skip = 0;
    EnterCriticalSection(&g_seenLock);
    for (int i = 0; i < DEDUP_SLOTS; i++) {
        if (g_seen[i][0] && _wcsicmp(g_seen[i], path) == 0 && g_seenTime[i] == wt) { skip = 1; break; }
    }
    if (!skip) {
        wcsncpy(g_seen[g_seenIdx], path, MAX_PATH - 1);
        g_seen[g_seenIdx][MAX_PATH - 1] = 0;
        g_seenTime[g_seenIdx] = wt;
        g_seenIdx = (g_seenIdx + 1) % DEDUP_SLOTS;
    }
    LeaveCriticalSection(&g_seenLock);
    return skip;
}

/* ---------------- 调用 scan.exe 打分 ---------------- */
/* 返回：1=高危(命中[ HIGH RISK )，0=其他，-1=调用失败 */
static int scan_verdict(const wchar_t *filepath, char *out, int outcap) {
    wchar_t cmd[32768];
    cmd[0] = 0;
    wcappend(cmd, _countof(cmd), L"\"");
    wcappend(cmd, _countof(cmd), g_scanner);
    wcappend(cmd, _countof(cmd), L"\" \"");
    wcappend(cmd, _countof(cmd), g_scaler);
    wcappend(cmd, _countof(cmd), L"\" \"");
    wcappend(cmd, _countof(cmd), filepath);
    wcappend(cmd, _countof(cmd), L"\"");

    SECURITY_ATTRIBUTES sa; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;
    HANDLE hRd = NULL, hWr = NULL;
    if (!CreatePipe(&hRd, &hWr, &sa, 0)) return -1;
    SetHandleInformation(hRd, HANDLE_FLAG_INHERIT, 0);

    /* 空stdin：万一 scan.exe 走到 system("pause")（如 scaler.txt 缺失）也不会卡住 */
    HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;                 /* 不弹界面 */
    si.hStdOutput = hWr;
    si.hStdError  = hWr;
    si.hStdInput  = hNul;

    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
                             NULL, NULL, &si, &pi);
    CloseHandle(hWr);
    if (!ok) {
        if (hRd) CloseHandle(hRd);
        if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);
        return -1;
    }

    /* 收输出（有界读取，避免超大输出把内存吃光） */
    int total = 0; DWORD got = 0; char buf[4096];
    while (ReadFile(hRd, buf, sizeof(buf) - 1, &got, NULL) && got > 0) {
        buf[got] = 0;
        if (total < outcap - 1) {
            int room = outcap - 1 - total;
            int cp = (int)got < room ? (int)got : room;
            memcpy(out + total, buf, cp);
            total += cp;
        }
        if (pi.hProcess) { /* 继续排空，但不再往缓冲里塞 */ }
    }
    out[total] = 0;

    DWORD wr = WaitForSingleObject(pi.hProcess, 30000);   /* 最多等 30 秒 */
    if (wr == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRd);
    if (hNul != INVALID_HANDLE_VALUE) CloseHandle(hNul);

    return strstr(out, "[HIGH RISK") ? 1 : 0;
}

/* 从 scan.exe 输出里摘出【检测名】一行（UTF-8） */
static void extract_caro(const char *out, char *dst, int cap) {
    dst[0] = 0;
    const char *p = strstr(out, "【检测名】");
    if (!p) return;
    p += strlen("【检测名】");
    int i = 0;
    while (p[i] && p[i] != '\r' && p[i] != '\n' && i < cap - 1) { dst[i] = p[i]; i++; }
    dst[i] = 0;
}

/* 等到文件可打开（写盘动作已结束）；返回 0 成功 */
static int wait_readable(const wchar_t *path, int tries) {
    for (int i = 0; i < tries; i++) {
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz; sz.QuadPart = 0;
            GetFileSizeEx(h, &sz);
            CloseHandle(h);
            if (sz.QuadPart > 0) return 0;     /* 非空且可读 => 认为已写完 */
        }
        Sleep(400);
    }
    return -1;
}

static void handle_new_file(const wchar_t *path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return;
    if (fad.nFileSizeHigh == 0 && fad.nFileSizeLow == 0) return;      /* 空文件不扫 */
    if (dedup_should_skip(path, fad.ftLastWriteTime.dwLowDateTime)) return;

    char pu[1024]; w2utf8(path, pu, sizeof(pu));

    if (wait_readable(path, 12) != 0) {   /* 最多等 ~5 秒 */
        printf("[跳过] 文件仍被占用/未写完：%s\n", pu);
        return;
    }

    static char out[OUT_CAP];
    out[0] = 0;
    int v = scan_verdict(path, out, sizeof(out));
    if (v < 0) { printf("[错误] 调用 scan.exe 失败：%s\n", pu); return; }

    char caro[128]; extract_caro(out, caro, sizeof(caro));
    if (v == 1) {
        printf("\n*** [告警] 新落地文件判为【高危】***\n");
        printf("    文件  : %s\n", pu);
        printf("    检测名: %s\n", caro[0] ? caro : "(特征码/模型命中)");
        if (g_lock) {
            DWORD attr = GetFileAttributesW(path);
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_READONLY)) {
                if (SetFileAttributesW(path, attr | FILE_ATTRIBUTE_READONLY))
                    printf("    处置  : 已置为只读（SetFileAttributesW）\n");
                else
                    printf("    处置  : 置只读失败 (err=%lu)\n", GetLastError());
            } else {
                printf("    处置  : 已是只读，无需处理\n");
            }
        } else {
            printf("    处置  : 仅告警（要自动置只读请加 --lock 启动）\n");
        }
        printf("*******************************\n");
    } else if (strstr(out, "[SUSPICIOUS")) {
        printf("[疑似] %s   %s\n", pu, caro[0] ? caro : "");
    } else {
        printf("[正常] %s\n", pu);
    }
    fflush(stdout);
}

/* ---------------- 每个目录一个监控线程 ---------------- */
typedef struct { wchar_t dir[MAX_PATH]; } DIRARG;

static DWORD WINAPI watch_thread(LPVOID param) {
    DIRARG *da = (DIRARG *)param;
    HANDLE h = CreateFileW(da->dir, FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        char d8[1024]; w2utf8(da->dir, d8, sizeof(d8));
        printf("[警告] 无法监控目录（可能不存在/无权限）：%s  (err=%lu)\n", d8, GetLastError());
        return 1;
    }
    char d8[1024]; w2utf8(da->dir, d8, sizeof(d8));
    printf("[就绪] 正在监控: %s%s\n", d8, g_recurse ? "  (含子目录)" : "");

    const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE;
    char buf[64 * 1024];
    for (;;) {
        DWORD ret = 0;
        if (!ReadDirectoryChangesW(h, buf, sizeof(buf), g_recurse ? TRUE : FALSE,
                                   filter, &ret, NULL, NULL)) {
            printf("[警告] ReadDirectoryChangesW 失败 (err=%lu)，2 秒后重试\n", GetLastError());
            Sleep(2000);
            continue;
        }
        FILE_NOTIFY_INFORMATION *p = (FILE_NOTIFY_INFORMATION *)buf;
        for (;;) {
            BOOL interesting = (p->Action == FILE_ACTION_ADDED ||
                                p->Action == FILE_ACTION_RENAMED_NEW_NAME ||
                                p->Action == FILE_ACTION_MODIFIED);
            if (interesting && p->FileNameLength > 0) {
                int n = p->FileNameLength / sizeof(WCHAR);
                wchar_t name[MAX_PATH];
                if (n >= MAX_PATH) n = MAX_PATH - 1;
                wmemcpy(name, p->FileName, n); name[n] = 0;

                const wchar_t *theName = name;
                const wchar_t *slash = wcsrchr(name, L'\\');
                if (slash) theName = slash + 1;

                if (ext_watched(theName)) {
                    wchar_t full[MAX_PATH * 2];
                    full[0] = 0;
                    wcappend(full, _countof(full), da->dir);
                    if (name[0] != L'\\') wcappend(full, _countof(full), L"\\");
                    wcappend(full, _countof(full), name);
                    handle_new_file(full);
                }
            }
            if (p->NextEntryOffset == 0) break;
            p = (FILE_NOTIFY_INFORMATION *)((char *)p + p->NextEntryOffset);
        }
    }
    return 0;
}

/* ---------------- 主函数 ---------------- */
static void add_dir(const wchar_t *d) {
    if (g_ndirs >= MAX_WATCH) return;
    wcsncpy(g_dirs[g_ndirs], d, MAX_PATH - 1);
    g_dirs[g_ndirs][MAX_PATH - 1] = 0;
    g_ndirs++;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    /* 默认监控目录 */
    wchar_t home[MAX_PATH];
    home[0] = 0;
    {
        wchar_t prof[MAX_PATH];
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", prof, MAX_PATH);
        if (n > 0 && n < MAX_PATH) wcsncpy(home, prof, MAX_PATH - 1);
    }
    if (home[0]) {
        wchar_t a[MAX_PATH]; a[0] = 0; wcappend(a, MAX_PATH, home); wcappend(a, MAX_PATH, L"\\Downloads");
        wchar_t b[MAX_PATH]; b[0] = 0; wcappend(b, MAX_PATH, home); wcappend(b, MAX_PATH, L"\\Desktop");
        add_dir(a); add_dir(b);
    } else {
        add_dir(L"C:\\Users\\17265\\Downloads");
        add_dir(L"C:\\Users\\17265\\Desktop");
    }

    wchar_t exeDir[MAX_PATH]; exeDir[0] = 0;
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    {
        wchar_t *s = wcsrchr(exeDir, L'\\');
        if (s) *s = 0;
    }

    /* 解析参数 */
    int userDirs = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lock") == 0) g_lock = 1;
        else if (strcmp(argv[i], "--recursive") == 0 || strcmp(argv[i], "-r") == 0) g_recurse = 1;
        else if (strcmp(argv[i], "--scan") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, g_scanner, MAX_PATH);
        }
        else if (strcmp(argv[i], "--scaler") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, g_scaler, MAX_PATH);
        }
        else if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) {
            if (!userDirs) { g_ndirs = 0; userDirs = 1; }   /* 用户指定则不再用默认 */
            wchar_t d[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, argv[++i], -1, d, MAX_PATH);
            add_dir(d);
        }
    }

    /* scan.exe / scaler.txt 默认取本程序同目录 */
    if (!g_scanner[0]) {
        wcappend(g_scanner, MAX_PATH, exeDir);
        wcappend(g_scanner, MAX_PATH, L"\\scan.exe");
    }
    if (!g_scaler[0]) {
        wcappend(g_scaler, MAX_PATH, exeDir);
        wcappend(g_scaler, MAX_PATH, L"\\scaler.txt");
    }

    char s8[2048]; w2utf8(g_scanner, s8, sizeof(s8));
    char t8[2048]; w2utf8(g_scaler,  t8, sizeof(t8));

    printf("============================================\n");
    printf("  目录主动防御 folder_guard（第一版·用户态）\n");
    printf("============================================\n");
    printf("监控扩展名 : .exe .dll .ps1 .cmd\n");
    printf("扫描器     : %s%s\n", s8, GetFileAttributesW(g_scanner) == INVALID_FILE_ATTRIBUTES ? "   [警告: 未找到]" : "");
    printf("模型参数   : %s%s\n", t8, GetFileAttributesW(g_scaler)  == INVALID_FILE_ATTRIBUTES ? "   [警告: 未找到]" : "");
    printf("处置方式   : %s\n", g_lock ? "高危文件自动置只读" : "仅告警（加 --lock 可自动置只读）");
    printf("监控目录数 : %d\n\n", g_ndirs);

    InitializeCriticalSection(&g_seenLock);

    DIRARG args[MAX_WATCH];
    HANDLE th[MAX_WATCH];
    for (int i = 0; i < g_ndirs; i++) {
        wcsncpy(args[i].dir, g_dirs[i], MAX_PATH - 1);
        args[i].dir[MAX_PATH - 1] = 0;
        th[i] = CreateThread(NULL, 0, watch_thread, &args[i], 0, NULL);
        if (!th[i]) { char d8[1024]; w2utf8(g_dirs[i], d8, sizeof(d8)); printf("[错误] 线程创建失败: %s\n", d8); }
    }

    printf("\n(按 Ctrl+C 退出)\n");
    for (;;) Sleep(1000);
    return 0;
}
