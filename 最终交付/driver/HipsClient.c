/* HipsClient.c -- HIPS 驱动用户态调用示例
 *
 * 必须以 SYSTEM 运行（设备 ACL 仅允许 SYSTEM）：
 *   HipsClient.exe version
 *   HipsClient.exe kill <pid>
 *   HipsClient.exe delete <win32-or-nt-path>
 *   HipsClient.exe selftest
 *
 * 构建：cl /nologo /O2 /MT /utf-8 /DUNICODE /D_UNICODE HipsClient.c
 */
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <wchar.h>
#include <strsafe.h>

#include "HipsDriver.h"

static void print_win32_error(const wchar_t *what, DWORD err) {
    wchar_t *buf = NULL;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    if (n && buf) {
        while (n && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' || buf[n - 1] == L' ')) buf[--n] = 0;
        wprintf(L"%ls failed: %lu (%ls)\n", what, err, buf);
        LocalFree(buf);
    } else {
        wprintf(L"%ls failed: %lu\n", what, err);
    }
}

static HANDLE open_driver(void) {
    HANDLE h = CreateFileW(HIPS_USER_NAME,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        print_win32_error(L"CreateFileW(\\\\.\\HipsDriver)", GetLastError());
        wprintf(L"提示：设备 ACL 仅允许 SYSTEM；请用 SYSTEM 身份运行本程序。\n");
    }
    return h;
}

static int do_version(HANDLE h) {
    HIPS_VERSION_INFO vi;
    DWORD bytes = 0;
    ZeroMemory(&vi, sizeof(vi));
    if (!DeviceIoControl(h, HIPS_IOCTL_QUERY_VERSION, NULL, 0, &vi, sizeof(vi), &bytes, NULL)) {
        print_win32_error(L"DeviceIoControl(QUERY_VERSION)", GetLastError());
        return 1;
    }
    wprintf(L"HIPS driver %lu.%lu.%lu (%ls)\n", vi.Major, vi.Minor, vi.Build, vi.Tag);
    return 0;
}

static int do_kill(HANDLE h, const wchar_t *arg) {
    wchar_t *end = NULL;
    unsigned long pid = wcstoul(arg, &end, 10);
    HIPS_PROCESS_REQUEST req;
    DWORD bytes = 0;

    if (!end || *end != 0 || pid == 0) {
        wprintf(L"无效 PID: %ls\n", arg);
        return 2;
    }
    ZeroMemory(&req, sizeof(req));
    req.Size = sizeof(req);
    req.ProcessId = (ULONG)pid;
    req.ExitCode = 0;

    if (!DeviceIoControl(h, HIPS_IOCTL_TERMINATE_PROCESS, &req, sizeof(req), NULL, 0, &bytes, NULL)) {
        print_win32_error(L"DeviceIoControl(TERMINATE_PROCESS)", GetLastError());
        return 1;
    }
    wprintf(L"terminated pid %lu\n", pid);
    return 0;
}

static BOOL to_nt_path(const wchar_t *in, wchar_t *out, size_t out_chars) {
    wchar_t full[1024];
    DWORD n;

    if (!in || !in[0] || !out || out_chars == 0) return FALSE;
    if (wcsncmp(in, L"\\??\\", 4) == 0 || wcsncmp(in, L"\\Device\\", 8) == 0) {
        return SUCCEEDED(StringCchCopyW(out, out_chars, in));
    }
    n = GetFullPathNameW(in, (DWORD)(sizeof(full) / sizeof(full[0])), full, NULL);
    if (n == 0 || n >= (DWORD)(sizeof(full) / sizeof(full[0]))) return FALSE;
    if (wcsncmp(full, L"\\\\", 2) == 0) {
        return SUCCEEDED(StringCchPrintfW(out, out_chars, L"\\??\\UNC\\%s", full + 2));
    }
    return SUCCEEDED(StringCchPrintfW(out, out_chars, L"\\??\\%s", full));
}

static int do_delete(HANDLE h, const wchar_t *arg) {
    HIPS_FILE_REQUEST req;
    DWORD bytes = 0;

    ZeroMemory(&req, sizeof(req));
    req.Size = sizeof(req);
    req.Flags = 0;
    if (!to_nt_path(arg, req.Path, HIPS_MAX_PATH)) {
        wprintf(L"路径转换失败: %ls\n", arg);
        return 2;
    }

    if (!DeviceIoControl(h, HIPS_IOCTL_DELETE_FILE, &req, sizeof(req), NULL, 0, &bytes, NULL)) {
        print_win32_error(L"DeviceIoControl(DELETE_FILE)", GetLastError());
        return 1;
    }
    wprintf(L"deleted: %ls\n", req.Path);
    return 0;
}

static int do_selftest(HANDLE h) {
    wchar_t tmp[MAX_PATH];
    wchar_t path[MAX_PATH + 32];
    HANDLE f;
    DWORD wrote = 0;
    int rc = 1;

    if (!GetTempPathW(MAX_PATH, tmp)) {
        print_win32_error(L"GetTempPathW", GetLastError());
        return 1;
    }
    if (FAILED(StringCchPrintfW(path, sizeof(path) / sizeof(path[0]),
                                L"%lships_selftest_%lu.txt", tmp, GetCurrentProcessId()))) {
        return 1;
    }
    f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        print_win32_error(L"CreateFileW(selftest)", GetLastError());
        return 1;
    }
    WriteFile(f, "hips selftest", 12, &wrote, NULL);
    CloseHandle(f);

    rc = do_delete(h, path);
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"selftest: file removed\n");
        rc = 0;
    } else {
        wprintf(L"selftest: file still exists\n");
        rc = 1;
    }
    DeleteFileW(path);
    return rc;
}

static void usage(void) {
    wprintf(L"HipsClient.exe version\n");
    wprintf(L"HipsClient.exe kill <pid>\n");
    wprintf(L"HipsClient.exe delete <win32-or-nt-path>\n");
    wprintf(L"HipsClient.exe selftest\n");
}

int wmain(int argc, wchar_t **argv) {
    HANDLE h;
    int rc;

    if (argc < 2) {
        usage();
        return 2;
    }
    h = open_driver();
    if (h == INVALID_HANDLE_VALUE) return 1;

    if (wcscmp(argv[1], L"version") == 0) rc = do_version(h);
    else if (wcscmp(argv[1], L"kill") == 0 && argc >= 3) rc = do_kill(h, argv[2]);
    else if (wcscmp(argv[1], L"delete") == 0 && argc >= 3) rc = do_delete(h, argv[2]);
    else if (wcscmp(argv[1], L"selftest") == 0) rc = do_selftest(h);
    else {
        usage();
        rc = 2;
    }
    CloseHandle(h);
    return rc;
}
