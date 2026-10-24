/* app.h -- 应用状态、图形资源和 UI 契约 */
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#define SCANNER_STATIC
#include "scanner_api.h"
#include "theme.h"

#define WM_APP_SCAN_TICK (WM_APP + 1)
#define WM_APP_SCAN_DONE (WM_APP + 2)

enum class Page {
    Home = 0,
    Scan,
    Protection,
    Quarantine,
    Logs,
    Driver,
    Settings,
    Count
};

enum class ThemeMode {
    System = 0,
    Light = 1,
    Dark = 2
};

struct ScanEntry {
    std::wstring path;
    ScannerResult r;
    int level = 0;
    bool quarantined = false;
};

struct ScanStats {
    int files = 0;
    int high = 0;
    int suspicious = 0;
    int normal = 0;
    int packed = 0;
    int skipped = 0;
    int errors = 0;
};

struct HistoryEntry {
    std::wstring time;
    std::wstring path;
    std::wstring bracket;
    std::wstring caro;
    std::wstring detail;
    double score = 0;
    int level = 0;
};

struct QuarantineEntry {
    std::wstring time;
    std::wstring original;
    std::wstring stored;
    std::wstring sha;
    std::wstring bracket;
    std::wstring caro;
};

struct Settings {
    int theme = 0;          /* 0 跟随系统 1 浅色 2 深色 */
    int maxMb = 256;
    int animations = 1;
    int autoQuarantine = 0;
    int minimizeToTray = 0;
};

struct Hit {
    int id = 0;
    D2D1_RECT_F rect = D2D1::RectF(0, 0, 0, 0);
};

struct Gfx {
    ID2D1Factory *factory = nullptr;
    ID2D1HwndRenderTarget *rt = nullptr;
    IDWriteFactory *dwrite = nullptr;
    ID2D1SolidColorBrush *brush = nullptr;

    IDWriteTextFormat *fBrand = nullptr;
    IDWriteTextFormat *fH1 = nullptr;
    IDWriteTextFormat *fH2 = nullptr;
    IDWriteTextFormat *fH3 = nullptr;
    IDWriteTextFormat *fBody = nullptr;
    IDWriteTextFormat *fSmall = nullptr;
    IDWriteTextFormat *fBadge = nullptr;
    IDWriteTextFormat *fButton = nullptr;
    IDWriteTextFormat *fHero = nullptr;
    IDWriteTextFormat *fHeroSub = nullptr;
    IDWriteTextFormat *fStat = nullptr;
    IDWriteTextFormat *fIcon = nullptr;
    IDWriteTextFormat *fIconBig = nullptr;
    IDWriteTextFormat *fIconBrand = nullptr;
    IDWriteTextFormat *fIconHuge = nullptr;
    IDWriteTextFormat *fMono = nullptr;

    float dpi = 96.0f;

    bool init(HWND hwnd);
    void release();
    void resize(UINT w, UINT h);
    void begin();
    void end();
};

struct App {
    HINSTANCE inst = nullptr;
    HWND hwnd = nullptr;
    Gfx gfx;
    Theme theme;
    ThemeMode themeMode = ThemeMode::System;
    Settings settings;

    Page page = Page::Home;
    Page lastPage = Page::Home;
    ULONGLONG pageAnimStart = 0;
    bool animating = false;

    int hoverId = 0;
    int pressedId = 0;
    std::vector<Hit> hits;

    /* 扫描状态 */
    std::wstring scanPath;
    bool scanPathIsDir = false;
    std::atomic<bool> scanning{false};
    std::atomic<bool> cancelRequested{false};
    HANDLE scanThread = nullptr;
    std::mutex resultMutex;
    std::vector<ScanEntry> pending;
    std::wstring currentFile;
    std::wstring scanRootLabel;
    ScanStats stats;
    std::vector<ScanEntry> results;
    int selectedResult = -1;
    float scrollScan = 0.0f;
    ULONGLONG scanStart = 0;
    bool scanFinished = false;
    bool scanCanceled = false;
    std::atomic<int> skippedCount{0};
    std::atomic<long long> bytesScanned{0};
    int skippedApplied = 0;
    std::wstring engineVersion = L"-";
    int abiVersion = 0;
    bool engineReady = false;

    /* 历史 / 隔离区 */
    std::vector<HistoryEntry> history;
    std::vector<QuarantineEntry> quarantine;
    int selectedQuar = -1;
    int selectedLog = -1;
    float scrollQuar = 0.0f;
    float scrollLog = 0.0f;

    /* 驱动页 */
    std::wstring driverState = L"未安装";
    std::wstring driverDetail = L"未检测到 MalwareScannerDrv 服务";

    /* 病毒库 */
    int dbCount = 0;
    std::wstring dbPath;

    /* 轻提示 */
    std::wstring toast;
    ULONGLONG toastUntil = 0;

    int hit_test(float x, float y) const;
    void start_page_anim();
    void show_toast(const std::wstring &s, int ms = 2600);
};

extern App g_app;

/* main.cpp */
void apply_theme(bool force);
void update_backdrop(bool dark);
void set_timer_for_animation();

/* scan.cpp */
bool scanner_runtime_init();
void scanner_runtime_shutdown();
int scanner_db_count();
int scanner_db_reload();
void scanner_start(const std::vector<std::wstring> &roots, int maxMb);
void scanner_cancel();
void scanner_join(DWORD ms);
void scanner_apply_pending();
void scanner_on_done();
void scanner_load_history();
void scanner_save_history();
void scanner_clear_history();
void scanner_load_quarantine();
void scanner_save_quarantine();
void scanner_quarantine_selected();
void scanner_restore_selected();
void scanner_delete_selected();
void scanner_refresh_driver();
void scanner_load_settings();
void scanner_save_settings();
std::wstring scanner_data_dir();
std::wstring scanner_db_display_path();
void open_data_dir();
void scan_quick();
void scan_path_async(const std::wstring &path);
void pick_and_scan_file();
void pick_and_scan_folder();

/* ui.cpp */
void ui_draw(App &app);
void ui_on_click(App &app, int id, float x, float y);
void ui_on_move(App &app, float x, float y);
void ui_on_wheel(App &app, float x, float y, int delta);
void ui_on_key(App &app, WPARAM key);
