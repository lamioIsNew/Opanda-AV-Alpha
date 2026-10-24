/* HipsTestTarget.c -- 仅用于 VM 的良性测试目标
 *
 * 创建一个文件并保持映射，模拟“被占用/被映射”的文件；
 * 同时把 PID 与路径写入 %TEMP%\hips_target_info.txt，供测试脚本读取。
 * 不会执行任何样本，也不会修改系统文件。
 *
 * 构建：cl /nologo /O2 /MT /utf-8 /DUNICODE /D_UNICODE HipsTestTarget.c
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <strsafe.h>

int wmain(void) {
    wchar_t tmp[MAX_PATH];
    wchar_t path[MAX_PATH + 32];
    wchar_t info[MAX_PATH + 64];
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = NULL;
    void *view = NULL;
    DWORD wrote = 0;

    /* 优先用 C:\opanda_test（测试脚本创建的固定目录），否则退回 %TEMP%。 */
    if (GetFileAttributesW(L"C:\\opanda_test") != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(tmp, MAX_PATH, L"C:\\opanda_test\\");
    } else if (!GetTempPathW(MAX_PATH, tmp)) {
        return 1;
    }
    if (FAILED(StringCchPrintfW(path, sizeof(path) / sizeof(path[0]),
                                L"%lships_target_locked.txt", tmp))) return 1;
    if (FAILED(StringCchPrintfW(info, sizeof(info) / sizeof(info[0]),
                                L"%lships_target_info.txt", tmp))) return 1;

    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 2;
    WriteFile(file, "hips locked target", 18, &wrote, NULL);
    FlushFileBuffers(file);

    mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 4096, NULL);
    if (mapping) view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (view) memcpy(view, "mapped", 6);

    {
        FILE *fp = NULL;
        if (_wfopen_s(&fp, info, L"w, ccs=UTF-8") == 0 && fp) {
            fwprintf(fp, L"PID=%lu\nPATH=%ls\n", (unsigned long)GetCurrentProcessId(), path);
            fclose(fp);
        }
    }
    wprintf(L"PID=%lu\nPATH=%ls\nINFO=%ls\n", (unsigned long)GetCurrentProcessId(), path, info);
    wprintf(L"holding mapping for 10 minutes...\n");
    Sleep(600000);

    if (view) UnmapViewOfFile(view);
    if (mapping) CloseHandle(mapping);
    CloseHandle(file);
    DeleteFileW(path);
    return 0;
}
