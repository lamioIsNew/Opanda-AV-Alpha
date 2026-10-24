/* main.cpp -- Win32 窗口、Direct2D 初始化、主题/背景、文件选择 */
#define _WIN32_WINNT 0x0A00

#include "app.h"

#include <d2d1helper.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <commdlg.h>
#include <commctrl.h>
#include <windowsx.h>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif

App g_app;

static UINT system_dpi() {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    typedef UINT (WINAPI *PFN_GETSYSTEMDPI)(void);
    PFN_GETSYSTEMDPI f = u32 ? (PFN_GETSYSTEMDPI)GetProcAddress(u32, "GetDpiForSystem") : nullptr;
    if (f) {
        UINT d = f();
        if (d >= 96) return d;
    }
    HDC dc = GetDC(NULL);
    UINT d = dc ? (UINT)GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(NULL, dc);
    return d >= 96 ? d : 96;
}

/* MinGW 的 uuid 库不一定提供这些 COM GUID，使用本地常量避免链接差异 */
static const GUID kIID_IDWriteFactory =
    {0xb859ee5a, 0xd838, 0x4b5b, {0xa2, 0xe8, 0x1a, 0xdc, 0x7d, 0x93, 0xdb, 0x48}};
static const CLSID kCLSID_FileOpenDialog =
    {0xdc1c5a9c, 0xe88a, 0x4dde, {0xa5, 0xa1, 0x60, 0xf8, 0x2a, 0x20, 0xae, 0xf7}};
static const IID kIID_IFileOpenDialog =
    {0xd57c7288, 0xd4ad, 0x4768, {0xbe, 0x02, 0x9d, 0x96, 0x95, 0x32, 0xd9, 0x60}};

/* ---------------- Direct2D / DirectWrite ---------------- */
static bool create_formats(Gfx &g) {
    auto mk = [&](const wchar_t *family, float size, DWRITE_FONT_WEIGHT weight,
                  IDWriteTextFormat **out) -> bool {
        HRESULT hr = g.dwrite->CreateTextFormat(family, NULL, weight,
                                                DWRITE_FONT_STYLE_NORMAL,
                                                DWRITE_FONT_STRETCH_NORMAL,
                                                size, L"zh-CN", out);
        if (FAILED(hr) || !*out) return false;
        (*out)->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
        return true;
    };
    if (!mk(L"Segoe UI", 15.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fBrand)) return false;
    if (!mk(L"Segoe UI", 27.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fH1)) return false;
    if (!mk(L"Segoe UI", 18.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fH2)) return false;
    if (!mk(L"Segoe UI", 14.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fH3)) return false;
    if (!mk(L"Segoe UI", 13.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fBody)) return false;
    if (!mk(L"Segoe UI", 11.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fSmall)) return false;
    if (!mk(L"Segoe UI", 10.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fBadge)) return false;
    if (!mk(L"Segoe UI", 13.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fButton)) return false;
    if (!mk(L"Segoe UI", 25.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fHero)) return false;
    if (!mk(L"Segoe UI", 12.5f, DWRITE_FONT_WEIGHT_NORMAL, &g.fHeroSub)) return false;
    if (!mk(L"Segoe UI", 25.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &g.fStat)) return false;
    if (!mk(L"Segoe MDL2 Assets", 17.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fIcon)) return false;
    if (!mk(L"Segoe MDL2 Assets", 42.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fIconBig)) return false;
    if (!mk(L"Segoe MDL2 Assets", 30.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fIconBrand)) return false;
    if (!mk(L"Segoe MDL2 Assets", 96.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fIconHuge)) return false;
    if (!mk(L"Consolas", 11.0f, DWRITE_FONT_WEIGHT_NORMAL, &g.fMono)) return false;

    IDWriteInlineObject *sign = nullptr;
    DWRITE_TRIMMING tr = {DWRITE_TRIMMING_GRANULARITY_CHARACTER, 0, 0};
    g.dwrite->CreateEllipsisTrimmingSign(g.fBody, &sign);
    if (sign) { g.fBody->SetTrimming(&tr, sign); sign->Release(); }
    sign = nullptr;
    g.dwrite->CreateEllipsisTrimmingSign(g.fSmall, &sign);
    if (sign) { g.fSmall->SetTrimming(&tr, sign); sign->Release(); }
    sign = nullptr;
    g.dwrite->CreateEllipsisTrimmingSign(g.fH3, &sign);
    if (sign) { g.fH3->SetTrimming(&tr, sign); sign->Release(); }
    return true;
}

static bool create_target(Gfx &g, HWND hwnd) {
    RECT rc;
    GetClientRect(hwnd, &rc);
    D2D1_SIZE_U size = D2D1::SizeU((UINT32)std::max(1L, rc.right - rc.left),
                                   (UINT32)std::max(1L, rc.bottom - rc.top));
    HRESULT hr = g.factory->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(
            D2D1_RENDER_TARGET_TYPE_DEFAULT,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE),
            g.dpi, g.dpi),
        D2D1::HwndRenderTargetProperties(hwnd, size, D2D1_PRESENT_OPTIONS_IMMEDIATELY),
        &g.rt);
    if (FAILED(hr) || !g.rt) return false;
    g.rt->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    g.rt->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
    g.rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0), &g.brush);
    return g.brush != nullptr;
}

bool Gfx::init(HWND hwnd) {
    dpi = 96.0f;
    typedef UINT (WINAPI *PFN_GETDPI)(HWND);
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    PFN_GETDPI getdpi = u32 ? (PFN_GETDPI)GetProcAddress(u32, "GetDpiForWindow") : nullptr;
    if (getdpi) {
        UINT d = getdpi(hwnd);
        if (d >= 96) dpi = (float)d;
    }
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &factory)) || !factory)
        return false;
    if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, kIID_IDWriteFactory,
                                   reinterpret_cast<IUnknown **>(&dwrite))) || !dwrite)
        return false;
    if (!create_formats(*this)) return false;
    return create_target(*this, hwnd);
}

void Gfx::release() {
    if (rt) { rt->Release(); rt = nullptr; }
    if (brush) { brush->Release(); brush = nullptr; }
    auto rel = [](IDWriteTextFormat *&p) { if (p) { p->Release(); p = nullptr; } };
    rel(fBrand); rel(fH1); rel(fH2); rel(fH3); rel(fBody); rel(fSmall); rel(fBadge);
    rel(fButton); rel(fHero); rel(fHeroSub); rel(fStat); rel(fIcon); rel(fIconBig); rel(fIconBrand); rel(fIconHuge); rel(fMono);
    if (dwrite) { dwrite->Release(); dwrite = nullptr; }
    if (factory) { factory->Release(); factory = nullptr; }
}

void Gfx::resize(UINT w, UINT h) {
    if (!rt) {
        if (g_app.hwnd) create_target(*this, g_app.hwnd);
        return;
    }
    rt->Resize(D2D1::SizeU(std::max(1U, w), std::max(1U, h)));
}

void Gfx::begin() {
    if (rt) {
        rt->BeginDraw();
        rt->SetTransform(D2D1::Matrix3x2F::Identity());
    }
}

void Gfx::end() {
    if (!rt) return;
    HRESULT hr = rt->EndDraw();
    if (hr == D2DERR_RECREATE_TARGET) {
        if (brush) { brush->Release(); brush = nullptr; }
        if (rt) { rt->Release(); rt = nullptr; }
        if (g_app.hwnd) create_target(*this, g_app.hwnd);
    }
}

/* ---------------- 主题 ---------------- */
static bool system_dark() {
    HKEY h = NULL;
    DWORD v = 1, sz = sizeof(v), type = 0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                      0, KEY_READ, &h) == ERROR_SUCCESS) {
        RegQueryValueExW(h, L"AppsUseLightTheme", NULL, &type, (LPBYTE)&v, &sz);
        RegCloseKey(h);
    }
    return v == 0;
}

void update_backdrop(bool dark) {
    if (!g_app.hwnd) return;

    BOOL darkFlag = dark ? TRUE : FALSE;
    if (FAILED(DwmSetWindowAttribute(g_app.hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                                     &darkFlag, sizeof(darkFlag))))
        DwmSetWindowAttribute(g_app.hwnd, 19, &darkFlag, sizeof(darkFlag));

    int corner = 2; /* DWMWCP_ROUND */
    DwmSetWindowAttribute(g_app.hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));

    /* 深色窗口的边框跟随主题，避免浅色 DWM 边框在暗色背景外露 */
    COLORREF border = dark ? RGB(42, 46, 52) : RGB(226, 229, 235);
    DwmSetWindowAttribute(g_app.hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));

    /* Windows 11: Mica；Windows 10: Acrylic（未文档化，失败则静默回退） */
    typedef struct { int AccentState; int AccentFlags; int GradientColor; int AnimationId; } ACCENT_POLICY;
    typedef struct { int Attrib; PVOID pvData; SIZE_T cbData; } WCADATA;
    typedef BOOL (WINAPI *PFN_SETWCA)(HWND, const WCADATA *);
    static PFN_SETWCA set_wca = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE u32 = GetModuleHandleW(L"user32.dll");
        if (u32) set_wca = (PFN_SETWCA)GetProcAddress(u32, "SetWindowCompositionAttribute");
    }

    MARGINS margins = {-1, -1, -1, -1};
    DwmExtendFrameIntoClientArea(g_app.hwnd, &margins);

    if (set_wca) {
        ACCENT_POLICY accent;
        memset(&accent, 0, sizeof(accent));
        accent.AccentState = 4; /* ACCENT_ENABLE_ACRYLICBLURBEHIND */
        accent.AccentFlags = 2;
        accent.GradientColor = dark ? 0xCC202124 : 0xCCF4F6F9;
        WCADATA data;
        data.Attrib = 19; /* WCA_ACCENT_POLICY */
        data.pvData = &accent;
        data.cbData = sizeof(accent);
        set_wca(g_app.hwnd, &data);
    }

    /* 让标准标题栏跟随深浅色 */
    SetWindowPos(g_app.hwnd, NULL, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
}

void apply_theme(bool force) {
    bool want = g_app.themeMode == ThemeMode::Dark;
    if (g_app.themeMode == ThemeMode::System) want = system_dark();
    if (!force && g_app.theme.dark == want) return;
    g_app.theme = make_theme(want);
    update_backdrop(want);
    if (g_app.hwnd) InvalidateRect(g_app.hwnd, NULL, FALSE);
}

/* ---------------- App ---------------- */
int App::hit_test(float x, float y) const {
    for (auto it = hits.rbegin(); it != hits.rend(); ++it) {
        if (x >= it->rect.left && x <= it->rect.right &&
            y >= it->rect.top && y <= it->rect.bottom)
            return it->id;
    }
    return 0;
}

void App::start_page_anim() {
    pageAnimStart = GetTickCount64();
    animating = settings.animations != 0;
    set_timer_for_animation();
}

void App::show_toast(const std::wstring &s, int ms) {
    toast = s;
    toastUntil = GetTickCount64() + (ULONGLONG)ms;
    set_timer_for_animation();
    if (hwnd) InvalidateRect(hwnd, NULL, FALSE);
}

/* ---------------- 文件选择 ---------------- */
static bool pick_path(bool folder, std::wstring &out) {
    out.clear();
    IFileOpenDialog *dlg = nullptr;
    HRESULT hr = CoCreateInstance(kCLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                                  kIID_IFileOpenDialog, reinterpret_cast<void **>(&dlg));
    if (SUCCEEDED(hr) && dlg) {
        DWORD opts = 0;
        dlg->GetOptions(&opts);
        dlg->SetOptions(opts | FOS_FORCEFILESYSTEM | (folder ? FOS_PICKFOLDERS : 0));
        if (SUCCEEDED(dlg->Show(g_app.hwnd))) {
            IShellItem *item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item)) && item) {
                PWSTR p = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &p)) && p) {
                    out = p;
                    CoTaskMemFree(p);
                }
                item->Release();
            }
        }
        dlg->Release();
        if (!out.empty()) return true;
    }

    /* 回退：老式对话框 */
    if (folder) {
        BROWSEINFOW bi;
        memset(&bi, 0, sizeof(bi));
        bi.hwndOwner = g_app.hwnd;
        bi.lpszTitle = L"选择要扫描的文件夹";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        LPITEMIDLIST idl = SHBrowseForFolderW(&bi);
        if (idl) {
            wchar_t p[MAX_PATH * 2];
            if (SHGetPathFromIDListW(idl, p)) out = p;
            CoTaskMemFree(idl);
        }
    } else {
        wchar_t p[MAX_PATH * 2];
        p[0] = 0;
        OPENFILENAMEW ofn;
        memset(&ofn, 0, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_app.hwnd;
        ofn.lpstrFile = p;
        ofn.nMaxFile = (DWORD)(sizeof(p) / sizeof(p[0]));
        ofn.lpstrFilter = L"所有文件\0*.*\0可执行文件\0*.exe;*.dll;*.sys\0\0";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if (GetOpenFileNameW(&ofn)) out = p;
    }
    return !out.empty();
}

void pick_and_scan_file() {
    std::wstring p;
    if (pick_path(false, p)) scan_path_async(p);
}

void pick_and_scan_folder() {
    std::wstring p;
    if (pick_path(true, p)) scan_path_async(p);
}

/* ---------------- 窗口 ---------------- */
static void update_timer() {
    bool need = g_app.scanning.load() || g_app.animating ||
                GetTickCount64() < g_app.toastUntil;
    if (need) SetTimer(g_app.hwnd, 1, 16, NULL);
    else KillTimer(g_app.hwnd, 1);
}

void set_timer_for_animation() {
    if (g_app.hwnd) update_timer();
}

static void client_to_dip(LPARAM lp, float &x, float &y) {
    float d = g_app.gfx.dpi >= 96.0f ? g_app.gfx.dpi : 96.0f;
    x = (float)GET_X_LPARAM(lp) * 96.0f / d;
    y = (float)GET_Y_LPARAM(lp) * 96.0f / d;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            g_app.hwnd = hwnd;
            if (!g_app.gfx.init(hwnd)) {
                MessageBoxW(hwnd, L"Direct2D 初始化失败。", L"恶意软件扫描器", MB_OK | MB_ICONERROR);
                return -1;
            }
            DragAcceptFiles(hwnd, TRUE);
            return 0;

        case WM_SIZE:
            g_app.gfx.resize(LOWORD(lp), HIWORD(lp));
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case WM_DPICHANGED: {
            RECT *r = (RECT *)lp;
            UINT nd = HIWORD(wp);
            g_app.gfx.dpi = nd >= 96 ? (float)nd : 96.0f;
            if (g_app.gfx.rt) g_app.gfx.rt->SetDpi(g_app.gfx.dpi, g_app.gfx.dpi);
            SetWindowPos(hwnd, NULL, r->left, r->top, r->right - r->left,
                         r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            g_app.gfx.resize((UINT)(r->right - r->left), (UINT)(r->bottom - r->top));
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_GETMINMAXINFO: {
            MINMAXINFO *mm = (MINMAXINFO *)lp;
            UINT d = 96;
            HMODULE u32 = GetModuleHandleW(L"user32.dll");
            typedef UINT (WINAPI *PFN_GETDPI)(HWND);
            PFN_GETDPI getdpi = u32 ? (PFN_GETDPI)GetProcAddress(u32, "GetDpiForWindow") : nullptr;
            if (getdpi) d = getdpi(hwnd);
            float s = (float)d / 96.0f;
            mm->ptMinTrackSize.x = (LONG)(1000 * s);
            mm->ptMinTrackSize.y = (LONG)(640 * s);
            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
            ui_draw(g_app);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_MOUSEMOVE: {
            float x = 0, y = 0; client_to_dip(lp, x, y);
            ui_on_move(g_app, x, y);
            TRACKMOUSEEVENT tme;
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            tme.dwHoverTime = 0;
            TrackMouseEvent(&tme);
            return 0;
        }

        case WM_MOUSELEAVE:
            g_app.hoverId = 0;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case WM_LBUTTONDOWN: {
            float x = 0, y = 0; client_to_dip(lp, x, y);
            int id = g_app.hit_test(x, y);
            g_app.pressedId = id;
            if (id) SetCapture(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_LBUTTONUP: {
            float x = 0, y = 0; client_to_dip(lp, x, y);
            int id = g_app.hit_test(x, y);
            int pressed = g_app.pressedId;
            g_app.pressedId = 0;
            if (GetCapture() == hwnd) ReleaseCapture();
            if (id && id == pressed) ui_on_click(g_app, id, x, y);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }

        case WM_MOUSEWHEEL:
            ui_on_wheel(g_app, 0, 0, GET_WHEEL_DELTA_WPARAM(wp));
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;

        case WM_KEYDOWN:
            if (wp == VK_ESCAPE) {
                scanner_cancel();
                return 0;
            }
            if (wp == VK_F5) {
                scanner_refresh_driver();
                scanner_db_count();
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
            ui_on_key(g_app, wp);
            return 0;

        case WM_DROPFILES: {
            HDROP drop = (HDROP)wp;
            UINT n = DragQueryFileW(drop, 0xFFFFFFFF, NULL, 0);
            if (n > 0) {
                UINT len = DragQueryFileW(drop, 0, NULL, 0);
                std::wstring p(len, L'\0');
                DragQueryFileW(drop, 0, &p[0], len + 1);
                scan_path_async(p);
            }
            DragFinish(drop);
            return 0;
        }

        case WM_SETTINGCHANGE:
            if (g_app.themeMode == ThemeMode::System) apply_theme(false);
            return 0;

        case WM_DWMCOLORIZATIONCOLORCHANGED:
            if (g_app.themeMode == ThemeMode::System) apply_theme(false);
            return 0;

        case WM_APP_SCAN_TICK:
            scanner_apply_pending();
            InvalidateRect(hwnd, NULL, FALSE);
            update_timer();
            return 0;

        case WM_APP_SCAN_DONE:
            scanner_on_done();
            scanner_join(2000);
            InvalidateRect(hwnd, NULL, FALSE);
            update_timer();
            return 0;

        case WM_TIMER:
            if (wp == 1) {
                InvalidateRect(hwnd, NULL, FALSE);
                update_timer();
            }
            return 0;

        case WM_CLOSE:
            scanner_cancel();
            scanner_join(8000);
            scanner_save_settings();
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            g_app.gfx.release();
            scanner_runtime_shutdown();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
    /* 先声明 DPI 感知，避免 Windows 把窗口缩放到 96 DPI 虚拟坐标。 */
    {
        HMODULE u32 = GetModuleHandleW(L"user32.dll");
        typedef BOOL (WINAPI *PFN_SETCTX)(HANDLE);
        PFN_SETCTX setctx = u32 ? (PFN_SETCTX)GetProcAddress(u32, "SetProcessDpiAwarenessContext") : nullptr;
        if (!setctx || !setctx((HANDLE)-4)) SetProcessDPIAware();
    }
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    g_app.inst = inst;
    scanner_load_settings();
    scanner_load_history();
    scanner_load_quarantine();
    scanner_refresh_driver();
    if (!scanner_runtime_init()) {
        CoUninitialize();
        return 1;
    }

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(32518));
    wc.hIconSm = wc.hIcon;
    wc.lpszClassName = L"MalwareScannerUI";
    if (!RegisterClassExW(&wc)) {
        scanner_runtime_shutdown();
        CoUninitialize();
        return 1;
    }

    RECT work;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int waW = work.right - work.left;
    int waH = work.bottom - work.top;
    UINT sdpi = system_dpi();
    float s = (float)sdpi / 96.0f;
    int w = (int)(1180.0f * s);
    int h = (int)(640.0f * s);
    w = std::min(w, waW - 16);
    h = std::min(h, waH - 16);
    int x = work.left + (waW - w) / 2;
    int y = work.top + (waH - h) / 2;
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"恶意软件扫描器",
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                x, y, w, h, NULL, NULL, inst, NULL);
    if (!hwnd) {
        scanner_runtime_shutdown();
        CoUninitialize();
        return 1;
    }
    g_app.hwnd = hwnd;
    apply_theme(true);
    scanner_refresh_driver();
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* 可选命令行：ScannerUI.exe --scan "路径"；--page scan/protection/... */
    {
        int argc = 0;
        LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        std::wstring startupScan;
        std::wstring startupPage;
        if (argv) {
            for (int i = 1; i < argc; i++) {
                std::wstring a = argv[i];
                if (a == L"--scan" && i + 1 < argc) startupScan = argv[++i];
                else if (a == L"--page" && i + 1 < argc) startupPage = argv[++i];
                else if (!a.empty() && a[0] != L'-' && startupScan.empty()) startupScan = a;
            }
            LocalFree(argv);
        }
        if (!startupPage.empty()) {
            if (startupPage == L"scan") g_app.page = Page::Scan;
            else if (startupPage == L"protection") g_app.page = Page::Protection;
            else if (startupPage == L"quarantine") g_app.page = Page::Quarantine;
            else if (startupPage == L"logs") g_app.page = Page::Logs;
            else if (startupPage == L"driver") g_app.page = Page::Driver;
            else if (startupPage == L"settings") g_app.page = Page::Settings;
            g_app.start_page_anim();
        }
        if (!startupScan.empty()) {
            g_app.page = Page::Scan;
            g_app.start_page_anim();
            scan_path_async(startupScan);
        }
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return 0;
}
