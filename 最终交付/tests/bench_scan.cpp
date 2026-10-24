/* bench_scan.cpp -- benign-only scanner benchmark (never touches 样本集)
 * usage: bench_scan.exe <scanner.dll> <benign-dir> [threads] [maxFiles]
 */
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

#define SCANNER_STATIC
#include "scanner_api.h"

typedef int (__cdecl *PFN_SCAN_W)(const wchar_t *, ScannerResult *);
typedef int (__cdecl *PFN_LEVEL)(const ScannerResult *);

static bool unsafe_dir(const std::wstring &p) {
    return p.find(L"样本集") != std::wstring::npos ||
           p.find(L"_work") != std::wstring::npos ||
           p.find(L"实测") != std::wstring::npos ||
           p.find(L"行为沙箱") != std::wstring::npos;
}

static void collect(const std::wstring &dir, std::vector<std::wstring> &out,
                    long long max_bytes, size_t max_files) {
    if (out.size() >= max_files) return;
    std::wstring pat = dir;
    if (!pat.empty() && pat.back() != L'\\' && pat.back() != L'/') pat += L'\\';
    pat += L'*';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pat.c_str(), FindExInfoBasic, &fd,
                                FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring p = dir;
        if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p += L'\\';
        p += fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            collect(p, out, max_bytes, max_files);
            if (out.size() >= max_files) break;
        } else {
            LARGE_INTEGER sz;
            sz.LowPart = fd.nFileSizeLow;
            sz.HighPart = (LONG)fd.nFileSizeHigh;
            if (sz.QuadPart <= 0 || sz.QuadPart > max_bytes) continue;
            out.push_back(p);
            if (out.size() >= max_files) break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage: bench_scan.exe <scanner.dll> <benign-dir> [threads] [maxFiles]\n");
        return 2;
    }
    std::wstring dll = argv[1];
    std::wstring dir = argv[2];
    if (unsafe_dir(dir)) {
        wprintf(L"REFUSED: benchmark target looks like the malware corpus: %ls\n", dir.c_str());
        return 3;
    }
    int threads = (argc > 3) ? _wtoi(argv[3]) : 12;
    if (threads < 1) threads = 1;
    if (threads > 32) threads = 32;
    size_t maxFiles = (argc > 4) ? (size_t)_wtoi(argv[4]) : 200;
    if (maxFiles == 0) maxFiles = 200;

    HMODULE hm = LoadLibraryW(dll.c_str());
    if (!hm) { wprintf(L"LoadLibrary failed: %lu\n", GetLastError()); return 4; }
    PFN_SCAN_W scan = (PFN_SCAN_W)GetProcAddress(hm, "scanner_scan_file_w");
    PFN_LEVEL level = (PFN_LEVEL)GetProcAddress(hm, "scanner_result_level");
    if (!scan || !level) { wprintf(L"missing exports\n"); return 5; }

    std::vector<std::wstring> files;
    collect(dir, files, 64LL * 1024 * 1024, maxFiles);
    if (files.empty()) { wprintf(L"no files under %ls\n", dir.c_str()); return 6; }

    unsigned long long bytes = 0;
    for (const auto &f : files) {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExW(f.c_str(), GetFileExInfoStandard, &fa)) {
            LARGE_INTEGER sz; sz.LowPart = fa.nFileSizeLow; sz.HighPart = (LONG)fa.nFileSizeHigh;
            bytes += (unsigned long long)sz.QuadPart;
        }
    }

    std::atomic<size_t> next{0};
    std::atomic<int> high{0}, susp{0}, normal{0}, skip{0}, err{0};
    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        pool.emplace_back([&]() {
            for (;;) {
                size_t i = next.fetch_add(1);
                if (i >= files.size()) break;
                ScannerResult r;
                memset(&r, 0, sizeof(r));
                int rc = scan(files[i].c_str(), &r);
                int lv = (rc == 0) ? level(&r) : 0;
                if (rc != 0) err.fetch_add(1);
                else if (lv >= 3) high.fetch_add(1);
                else if (lv == 2) susp.fetch_add(1);
                else if (lv == 5) skip.fetch_add(1);
                else normal.fetch_add(1);
            }
        });
    }
    for (auto &th : pool) th.join();
    auto t1 = std::chrono::steady_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();
    if (sec <= 0) sec = 0.000001;

    wprintf(L"dir=%ls\nthreads=%d files=%zu bytes=%llu sec=%.3f files/s=%.1f MB/s=%.1f\n",
            dir.c_str(), threads, files.size(), bytes, sec,
            (double)files.size() / sec, (double)bytes / 1048576.0 / sec);
    wprintf(L"high=%d susp=%d normal=%d skip=%d error=%d\n",
            high.load(), susp.load(), normal.load(), skip.load(), err.load());
    FreeLibrary(hm);
    return 0;
}
