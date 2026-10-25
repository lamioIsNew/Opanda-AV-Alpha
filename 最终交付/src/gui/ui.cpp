/* ui.cpp -- WD 风格极简 GUI（任务 1）
 *
 * 约束：
 *   · 只用黑/白/灰，自适应浅色/深色，不出现彩色文字；
 *   · 左侧扁平侧边栏，仅 5 项；
 *   · 图标使用 Segoe Fluent Icons / Segoe MDL2 Assets 字体字形，
 *     不自绘图标；
 *   · 原生 DWM 圆角在 main.cpp 的 update_backdrop() 中设置。
 */
#include "app.h"
#include "qtn_crypto.h"

#include <d2d1helper.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace {

const float SIDEBAR_W = 236.0f;
const float PAD = 28.0f;
const float HEADER_H = 92.0f;
const float ROW_H = 40.0f;
const float HIST_ROW_H = 52.0f;

enum : int {
    ID_NAV_OVERVIEW = 1001,
    ID_NAV_PROTECTION,
    ID_NAV_QUARANTINE,
    ID_NAV_HISTORY,
    ID_NAV_SETTINGS,

    ID_QUICK = 2001,
    ID_PICK_FILE,
    ID_PICK_FOLDER,
    ID_STOP,
    ID_CLEAR,
    ID_QUAR_SEL,
    ID_OPEN_SEL,
    ID_HW_REFRESH,
    ID_VIEW_HISTORY,

    ID_RESTORE = 3001,
    ID_DELETE,
    ID_QUAR_REFRESH,

    ID_HIST_REFRESH = 4001,
    ID_HIST_CLEAR,
    ID_OPEN_LOGS,

    ID_THEME_SYS = 5001,
    ID_THEME_LIGHT,
    ID_THEME_DARK,
    ID_ANIM,
    ID_DB_RELOAD,
    ID_OPEN_DATA,
    ID_DRV_REFRESH,
    ID_MAX_MINUS,
    ID_MAX_PLUS,
    ID_KEY_TPM,
    ID_KEY_SGX,

    ID_RESULT_ROW = 20000,
    ID_QUAR_ROW = 30000,
    ID_HIST_ROW = 40000
};

struct Layout {
    float w = 1000.0f;
    float h = 640.0f;
    float contentL = SIDEBAR_W + PAD;
    float contentR = 1000.0f - PAD;
    float contentW = 1000.0f - SIDEBAR_W - PAD * 2;
    float bodyTop = HEADER_H;
};

static D2D1_RECT_F R(float l, float t, float r, float b) {
    return D2D1::RectF(l, t, r, b);
}

static float rw(const D2D1_RECT_F &r) { return r.right - r.left; }
static float rh(const D2D1_RECT_F &r) { return r.bottom - r.top; }

static Layout make_layout(App &a) {
    Layout l;
    RECT rc;
    GetClientRect(a.hwnd, &rc);
    float dpi = a.gfx.dpi >= 96.0f ? a.gfx.dpi : 96.0f;
    l.w = std::max(320.0f, (float)(rc.right - rc.left) * 96.0f / dpi);
    l.h = std::max(240.0f, (float)(rc.bottom - rc.top) * 96.0f / dpi);
    l.contentL = SIDEBAR_W + PAD;
    l.contentR = l.w - PAD;
    l.contentW = std::max(160.0f, l.contentR - l.contentL);
    l.bodyTop = HEADER_H;
    return l;
}

static std::wstring u8(const char *s) {
    if (!s || !s[0]) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 1) return L"";
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    while (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::wstring base_name(const std::wstring &p) {
    size_t x = p.find_last_of(L"\\/");
    return (x == std::wstring::npos) ? p : p.substr(x + 1);
}

static std::wstring elide(const std::wstring &s, size_t max_chars) {
    if (s.size() <= max_chars) return s;
    if (max_chars <= 3) return s.substr(0, max_chars);
    return L"…" + s.substr(s.size() - (max_chars - 1));
}

static std::wstring bracket_short(const std::wstring &b) {
    if (b.find(L"HIGH RISK") != std::wstring::npos) return L"高危";
    if (b.find(L"SUSPICIOUS") != std::wstring::npos) return L"疑似";
    if (b.find(L"TRUSTED") != std::wstring::npos) return L"可信";
    if (b.find(L"PACKED") != std::wstring::npos) return L"加壳";
    if (b.find(L"SKIP") != std::wstring::npos) return L"跳过";
    if (b.find(L"NORMAL") != std::wstring::npos) return L"正常";
    return b.empty() ? L"未知" : b;
}

static void fill_rect(App &a, const D2D1_RECT_F &r, const D2D1_COLOR_F &c, float radius = 0.0f) {
    if (!a.gfx.rt || !a.gfx.brush) return;
    a.gfx.brush->SetColor(c);
    if (radius > 0.0f) {
        float rr = std::min(radius, std::min(rw(r), rh(r)) * 0.5f);
        a.gfx.rt->FillRoundedRectangle(D2D1::RoundedRect(r, rr, rr), a.gfx.brush);
    } else {
        a.gfx.rt->FillRectangle(r, a.gfx.brush);
    }
}

static void stroke_rect(App &a, const D2D1_RECT_F &r, const D2D1_COLOR_F &c, float radius = 0.0f, float width = 1.0f) {
    if (!a.gfx.rt || !a.gfx.brush) return;
    a.gfx.brush->SetColor(c);
    if (radius > 0.0f) {
        float rr = std::min(radius, std::min(rw(r), rh(r)) * 0.5f);
        a.gfx.rt->DrawRoundedRectangle(D2D1::RoundedRect(r, rr, rr), a.gfx.brush, width);
    } else {
        a.gfx.rt->DrawRectangle(r, a.gfx.brush, width);
    }
}

static void line(App &a, float x1, float y1, float x2, float y2, const D2D1_COLOR_F &c, float width = 1.0f) {
    if (!a.gfx.rt || !a.gfx.brush) return;
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), a.gfx.brush, width);
}

static void text(App &a, const std::wstring &s, const D2D1_RECT_F &r, const D2D1_COLOR_F &c,
                 IDWriteTextFormat *fmt, DWRITE_TEXT_ALIGNMENT align = DWRITE_TEXT_ALIGNMENT_LEADING,
                 DWRITE_PARAGRAPH_ALIGNMENT valign = DWRITE_PARAGRAPH_ALIGNMENT_NEAR) {
    if (!a.gfx.rt || !a.gfx.brush || !fmt || s.empty()) return;
    fmt->SetTextAlignment(align);
    fmt->SetParagraphAlignment(valign);
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawTextW(s.c_str(), (UINT32)s.size(), fmt, r, a.gfx.brush,
                        D2D1_DRAW_TEXT_OPTIONS_CLIP);
}

static void text_wrap(App &a, const std::wstring &s, const D2D1_RECT_F &r, const D2D1_COLOR_F &c,
                      IDWriteTextFormat *fmt) {
    if (!a.gfx.rt || !a.gfx.brush || !fmt || s.empty()) return;
    fmt->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
    fmt->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
    fmt->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawTextW(s.c_str(), (UINT32)s.size(), fmt, r, a.gfx.brush,
                        D2D1_DRAW_TEXT_OPTIONS_CLIP);
    fmt->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
}

static void card(App &a, const D2D1_RECT_F &r) {
    fill_rect(a, r, a.theme.card, 10.0f);
    stroke_rect(a, r, a.theme.border, 10.0f);
}

static void chip(App &a, const D2D1_RECT_F &r, const std::wstring &s, bool strong = false) {
    fill_rect(a, r, strong ? a.theme.accentSoft : a.theme.card2, rh(r) * 0.5f);
    stroke_rect(a, r, a.theme.border, rh(r) * 0.5f);
    text(a, s, r, strong ? a.theme.text : a.theme.text2, a.gfx.fBadge,
         DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static bool button(App &a, int id, const D2D1_RECT_F &r, const std::wstring &label,
                   bool primary = false, bool enabled = true) {
    bool hover = enabled && a.hoverId == id;
    bool pressed = enabled && a.pressedId == id;
    D2D1_COLOR_F bg, fg, bd;

    if (!enabled) {
        bg = a.theme.card2;
        fg = a.theme.text3;
        bd = a.theme.border;
    } else if (primary) {
        bg = pressed ? a.theme.accent2 : a.theme.accent;
        fg = a.theme.dark ? a.theme.black : a.theme.white;
        bd = bg;
    } else {
        bg = hover ? a.theme.cardHover : a.theme.card;
        fg = a.theme.text;
        bd = hover ? a.theme.borderStrong : a.theme.border;
    }
    fill_rect(a, r, bg, 6.0f);
    stroke_rect(a, r, bd, 6.0f);
    text(a, label, r, fg, a.gfx.fButton, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    if (enabled) a.hits.push_back({id, r});
    return enabled;
}

static void nav_item(App &a, int id, float x, float y, float w, float h,
                     const wchar_t *icon, const std::wstring &label, bool selected) {
    D2D1_RECT_F r = R(x, y, x + w, y + h);
    if (selected) fill_rect(a, r, a.theme.accentSoft, 8.0f);
    else if (a.hoverId == id) fill_rect(a, r, a.theme.hover, 8.0f);

    if (selected) fill_rect(a, R(x, y + 9.0f, x + 3.0f, y + h - 9.0f), a.theme.accent, 1.5f);
    text(a, icon, R(x + 14.0f, y, x + 42.0f, y + h), a.theme.text, a.gfx.fIcon,
         DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, label, R(x + 46.0f, y, x + w - 10.0f, y + h), a.theme.text, a.gfx.fBody,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    a.hits.push_back({id, r});
}

static const wchar_t *page_title(Page p) {
    switch (p) {
    case Page::Overview:   return L"安全性概览";
    case Page::Protection: return L"病毒和威胁防护";
    case Page::Quarantine: return L"隔离区";
    case Page::History:    return L"保护历史记录";
    case Page::Settings:   return L"安全设置";
    default:               return L"";
    }
}

static const wchar_t *page_sub(Page p) {
    switch (p) {
    case Page::Overview:   return L"设备安全状态、硬件环境与最近活动";
    case Page::Protection: return L"手动扫描、结果处置与威胁隔离";
    case Page::Quarantine: return L"隔离文件使用 AES-256-GCM + TPM/SGX 密钥存储";
    case Page::History:    return L"扫描与处置的历史记录";
    case Page::Settings:   return L"外观、扫描、内核执行端与数据";
    default:               return L"";
    }
}

static void draw_header(App &a, const Layout &l) {
    text(a, page_title(a.page), R(l.contentL, 24.0f, l.contentR, 58.0f), a.theme.text,
         a.gfx.fH1, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, page_sub(a.page), R(l.contentL, 58.0f, l.contentR, 80.0f), a.theme.text2,
         a.gfx.fSmall, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    line(a, l.contentL, HEADER_H - 10.0f, l.contentR, HEADER_H - 10.0f, a.theme.border);
}

static void draw_sidebar(App &a, const Layout &l) {
    fill_rect(a, R(0, 0, SIDEBAR_W, l.h), a.theme.sidebar);
    line(a, SIDEBAR_W - 1.0f, 0, SIDEBAR_W - 1.0f, l.h, a.theme.border);

    /* 品牌：纯灰阶方块 + 字体字形，不自绘图标 */
    D2D1_RECT_F brand = R(20.0f, 22.0f, 52.0f, 54.0f);
    fill_rect(a, brand, a.theme.accent, 8.0f);
    text(a, L"\uEA18", brand, a.theme.dark ? a.theme.black : a.theme.white, a.gfx.fIcon,
         DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, L"Opanda", R(62.0f, 20.0f, 210.0f, 40.0f), a.theme.text, a.gfx.fH3,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, L"安全中心", R(62.0f, 39.0f, 210.0f, 56.0f), a.theme.text3, a.gfx.fSmall,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    const wchar_t *icons[5] = {L"\uE72E", L"\uE8B7", L"\uE74D", L"\uE81C", L"\uE713"};
    const wchar_t *labels[5] = {L"安全性概览", L"病毒和威胁防护", L"隔离区", L"保护历史记录", L"安全设置"};
    float y = 104.0f;
    for (int i = 0; i < 5; i++) {
        nav_item(a, ID_NAV_OVERVIEW + i, 12.0f, y, SIDEBAR_W - 24.0f, 44.0f,
                 icons[i], labels[i], (int)a.page == i);
        y += 48.0f;
    }

    /* 底部状态 */
    float by = l.h - 94.0f;
    line(a, 20.0f, by, SIDEBAR_W - 20.0f, by, a.theme.border);
    std::wstring e = a.engineReady ? (L"引擎 " + a.engineVersion) : L"扫描引擎未加载";
    text(a, e, R(20.0f, by + 12.0f, SIDEBAR_W - 20.0f, by + 30.0f), a.theme.text2,
         a.gfx.fSmall);
    text(a, L"病毒库 " + std::to_wstring(a.dbCount) + L" 条", R(20.0f, by + 30.0f, SIDEBAR_W - 20.0f, by + 48.0f),
         a.theme.text3, a.gfx.fSmall);
    text(a, L"隔离区 " + std::to_wstring(a.quarantine.size()) + L" 项", R(20.0f, by + 48.0f, SIDEBAR_W - 20.0f, by + 66.0f),
         a.theme.text3, a.gfx.fSmall);
}

static void draw_empty(App &a, const D2D1_RECT_F &r, const std::wstring &title, const std::wstring &sub) {
    text(a, title, R(r.left, r.top + rh(r) * 0.32f, r.right, r.top + rh(r) * 0.32f + 26.0f),
         a.theme.text2, a.gfx.fH3, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, sub, R(r.left, r.top + rh(r) * 0.32f + 30.0f, r.right, r.top + rh(r) * 0.32f + 52.0f),
         a.theme.text3, a.gfx.fSmall, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void draw_overview(App &a, const Layout &l) {
    float y = l.bodyTop;

    /* Hero */
    D2D1_RECT_F hero = R(l.contentL, y, l.contentR, y + 128.0f);
    card(a, hero);
    D2D1_RECT_F ibox = R(hero.left + 18.0f, hero.top + 18.0f, hero.left + 74.0f, hero.top + 74.0f);
    fill_rect(a, ibox, a.theme.accentSoft, 10.0f);
    text(a, L"\uEA18", ibox, a.theme.text, a.gfx.fIconBig,
         DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    std::wstring heroTitle = a.engineReady ? L"扫描引擎已就绪" : L"扫描引擎未就绪";
    std::wstring heroSub;
    if (a.scanning.load()) {
        heroSub = L"正在扫描：" + elide(base_name(a.currentFile), 52);
    } else if (a.scanFinished) {
        heroSub = L"上次扫描 " + std::to_wstring(a.stats.files) + L" 个文件 · 高危 " +
                  std::to_wstring(a.stats.high) + L" · 疑似 " + std::to_wstring(a.stats.suspicious);
    } else {
        heroSub = L"手动扫描模式 · 选择文件或文件夹开始";
    }
    text(a, heroTitle, R(hero.left + 90.0f, hero.top + 16.0f, hero.right - 150.0f, hero.top + 44.0f),
         a.theme.text, a.gfx.fH2, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    text(a, heroSub, R(hero.left + 90.0f, hero.top + 44.0f, hero.right - 24.0f, hero.top + 68.0f),
         a.theme.text2, a.gfx.fSmall, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    chip(a, R(hero.right - 132.0f, hero.top + 18.0f, hero.right - 18.0f, hero.top + 44.0f),
         a.engineReady ? L"引擎在线" : L"引擎离线", a.engineReady);

    button(a, ID_QUICK, R(hero.left + 18.0f, hero.top + 88.0f, hero.left + 128.0f, hero.top + 116.0f),
           L"快速扫描", true, a.engineReady && !a.scanning.load());
    button(a, ID_PICK_FILE, R(hero.left + 138.0f, hero.top + 88.0f, hero.left + 248.0f, hero.top + 116.0f),
           L"选择文件", false, a.engineReady && !a.scanning.load());
    button(a, ID_PICK_FOLDER, R(hero.left + 258.0f, hero.top + 88.0f, hero.left + 378.0f, hero.top + 116.0f),
           L"选择文件夹", false, a.engineReady && !a.scanning.load());

    /* 统计 */
    y = hero.bottom + 14.0f;
    float gap = 12.0f;
    float cw = (l.contentW - gap * 2.0f) / 3.0f;
    struct Stat { const wchar_t *label; std::wstring value; const wchar_t *sub; };
    Stat st[3] = {
        {L"病毒库", std::to_wstring(a.dbCount), L"条外部特征"},
        {L"隔离区", std::to_wstring(a.quarantine.size()), L"个隔离文件"},
        {L"历史记录", std::to_wstring(a.history.size()), L"条扫描记录"}
    };
    for (int i = 0; i < 3; i++) {
        D2D1_RECT_F r = R(l.contentL + i * (cw + gap), y, l.contentL + i * (cw + gap) + cw, y + 72.0f);
        card(a, r);
        text(a, st[i].label, R(r.left + 14.0f, r.top + 8.0f, r.right - 14.0f, r.top + 26.0f),
             a.theme.text3, a.gfx.fSmall);
        text(a, st[i].value, R(r.left + 14.0f, r.top + 24.0f, r.right - 14.0f, r.top + 54.0f),
             a.theme.text, a.gfx.fStat);
        text(a, st[i].sub, R(r.left + 14.0f, r.top + 52.0f, r.right - 14.0f, r.top + 68.0f),
             a.theme.text3, a.gfx.fSmall);
    }

    /* 硬件环境检测 */
    y += 72.0f + 14.0f;
    D2D1_RECT_F hw = R(l.contentL, y, l.contentR, y + 156.0f);
    card(a, hw);
    text(a, L"硬件环境检测", R(hw.left + 18.0f, hw.top + 12.0f, hw.right - 120.0f, hw.top + 34.0f),
         a.theme.text, a.gfx.fH3);
    button(a, ID_HW_REFRESH, R(hw.right - 100.0f, hw.top + 10.0f, hw.right - 18.0f, hw.top + 38.0f),
           L"刷新", false, a.engineReady);

    std::wstring sgx = a.hwReady ? (a.hw.sgx ? L"支持" : L"不支持") : L"不可用";
    std::wstring pt = a.hwReady ? (a.hw.pt ? L"支持" : L"不支持") : L"不可用";
    std::wstring tpm;
    if (!a.hwReady) tpm = L"不可用";
    else if (a.hw.tpm20) tpm = L"TPM 2.0 已启用";
    else if (a.hw.tpm_version == 12) tpm = L"仅 TPM 1.2";
    else tpm = L"未检测到 / 未启用";
    std::wstring hv = a.hwReady ? (a.hw.hypervisor ? L"是（虚拟机）" : L"否（物理机）") : L"不可用";

    struct HW { const wchar_t *label; std::wstring value; const wchar_t *src; };
    HW hwv[4] = {
        {L"Intel SGX", sgx, L"CPUID.7:EBX[2]"},
        {L"Intel PT", pt, L"CPUID.7:EBX[25]"},
        {L"TPM 2.0", tpm, L"TBS Tbsi_GetDeviceInfo"},
        {L"虚拟化环境", hv, L"CPUID.1:ECX[31]"}
    };
    float colW = (rw(hw) - 36.0f) / 2.0f;
    for (int i = 0; i < 4; i++) {
        int cx = i % 2;
        int cy = i / 2;
        D2D1_RECT_F r = R(hw.left + 18.0f + cx * (colW + 12.0f),
                          hw.top + 44.0f + cy * 48.0f,
                          hw.left + 18.0f + cx * (colW + 12.0f) + colW,
                          hw.top + 44.0f + cy * 48.0f + 42.0f);
        fill_rect(a, r, a.theme.card2, 6.0f);
        text(a, hwv[i].label, R(r.left + 10.0f, r.top + 4.0f, r.right - 10.0f, r.top + 22.0f),
             a.theme.text3, a.gfx.fSmall);
        text(a, hwv[i].value, R(r.left + 10.0f, r.top + 20.0f, r.right - 10.0f, r.top + 40.0f),
             a.theme.text, a.gfx.fBody);
        text(a, hwv[i].src, R(r.left + 10.0f, r.top + 38.0f, r.right - 10.0f, r.top + 50.0f),
             a.theme.text3, a.gfx.fSmall);
    }
    if (a.hwReady && a.hw.detail[0]) {
        text(a, u8(a.hw.detail), R(hw.left + 18.0f, hw.bottom - 22.0f, hw.right - 18.0f, hw.bottom - 6.0f),
             a.theme.text3, a.gfx.fSmall);
    }

    /* 最近活动 */
    y += 156.0f + 14.0f;
    float listBottom = l.h - PAD;
    if (listBottom - y < 44.0f) return;
    D2D1_RECT_F hist = R(l.contentL, y, l.contentR, listBottom);
    card(a, hist);
    text(a, L"最近活动", R(hist.left + 18.0f, hist.top + 10.0f, hist.right - 120.0f, hist.top + 32.0f),
         a.theme.text, a.gfx.fH3);
    button(a, ID_VIEW_HISTORY, R(hist.right - 100.0f, hist.top + 8.0f, hist.right - 18.0f, hist.top + 34.0f),
           L"查看全部", false, true);

    float hy = hist.top + 40.0f;
    int shown = 0;
    for (size_t i = 0; i < a.history.size() && shown < 4; i++, shown++) {
        if (hy + 28.0f > hist.bottom - 6.0f) break;
        const HistoryEntry &h = a.history[i];
        text(a, h.time, R(hist.left + 18.0f, hy, hist.left + 156.0f, hy + 24.0f), a.theme.text3, a.gfx.fSmall);
        chip(a, R(hist.left + 160.0f, hy + 2.0f, hist.left + 218.0f, hy + 22.0f), bracket_short(h.bracket), h.level >= 2);
        text(a, elide(h.path, 64), R(hist.left + 228.0f, hy, hist.right - 18.0f, hy + 24.0f),
             a.theme.text2, a.gfx.fSmall);
        hy += 28.0f;
    }
    if (a.history.empty()) {
        draw_empty(a, R(hist.left, hist.top + 34.0f, hist.right, hist.bottom), L"暂无活动记录", L"完成一次扫描后会在这里显示");
    }
}

static void draw_protection(App &a, const Layout &l) {
    float y = l.bodyTop;

    /* 工具栏 */
    button(a, ID_QUICK, R(l.contentL, y, l.contentL + 100.0f, y + 34.0f), L"快速扫描", true,
           a.engineReady && !a.scanning.load());
    button(a, ID_PICK_FILE, R(l.contentL + 108.0f, y, l.contentL + 208.0f, y + 34.0f), L"选择文件", false,
           a.engineReady && !a.scanning.load());
    button(a, ID_PICK_FOLDER, R(l.contentL + 216.0f, y, l.contentL + 326.0f, y + 34.0f), L"选择文件夹", false,
           a.engineReady && !a.scanning.load());
    button(a, ID_STOP, R(l.contentL + 334.0f, y, l.contentL + 414.0f, y + 34.0f), L"停止", false,
           a.scanning.load());
    button(a, ID_CLEAR, R(l.contentR - 76.0f, y, l.contentR, y + 34.0f), L"清空", false,
           !a.scanning.load() && !a.results.empty());

    /* 扫描状态 */
    y += 44.0f;
    D2D1_RECT_F st = R(l.contentL, y, l.contentR, y + 64.0f);
    card(a, st);
    std::wstring title;
    std::wstring sub;
    if (a.scanning.load()) {
        title = L"正在扫描";
        sub = elide(a.currentFile, 80);
    } else if (a.scanFinished) {
        title = a.scanCanceled ? L"扫描已停止" : L"扫描完成";
        sub = L"文件 " + std::to_wstring(a.stats.files) + L" · 高危 " + std::to_wstring(a.stats.high) +
              L" · 疑似 " + std::to_wstring(a.stats.suspicious) + L" · 跳过 " + std::to_wstring(a.stats.skipped);
    } else {
        title = L"准备就绪";
        sub = L"选择文件/文件夹，或把文件拖入窗口";
    }
    text(a, title, R(st.left + 16.0f, st.top + 8.0f, st.right - 220.0f, st.top + 30.0f),
         a.theme.text, a.gfx.fH3);
    text(a, sub, R(st.left + 16.0f, st.top + 31.0f, st.right - 16.0f, st.top + 52.0f),
         a.theme.text2, a.gfx.fSmall);

    float barY = st.bottom - 10.0f;
    fill_rect(a, R(st.left + 16.0f, barY, st.right - 16.0f, barY + 3.0f), a.theme.track, 2.0f);
    if (a.scanning.load()) {
        float full = rw(st) - 32.0f;
        float t = (float)((GetTickCount64() / 8) % 1000) / 1000.0f;
        float bw = full * 0.32f;
        float x = st.left + 16.0f + (full - bw) * t;
        fill_rect(a, R(x, barY, x + bw, barY + 3.0f), a.theme.accent, 2.0f);
    } else if (a.scanFinished) {
        fill_rect(a, R(st.left + 16.0f, barY, st.right - 16.0f, barY + 3.0f), a.theme.accent, 2.0f);
    }

    /* 结果表 */
    y += 74.0f;
    float c0 = l.contentL + 14.0f;
    float c1 = c0 + 92.0f;
    float c2 = l.contentR - 14.0f - 150.0f - 56.0f - 84.0f;
    float c3 = c2 + 84.0f;
    float c4 = c3 + 56.0f;
    float c5 = l.contentR - 14.0f;
    D2D1_RECT_F head = R(l.contentL, y, l.contentR, y + 30.0f);
    fill_rect(a, head, a.theme.card2, 6.0f);
    text(a, L"结论", R(c0, head.top, c1, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"文件", R(c1, head.top, c2, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"层级", R(c2, head.top, c3, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"分数", R(c3, head.top, c4, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"检测名", R(c4, head.top, c5, head.bottom), a.theme.text3, a.gfx.fSmall);

    float listTop = y + 34.0f;
    float listBottom = l.h - 72.0f;
    D2D1_RECT_F list = R(l.contentL, listTop, l.contentR, listBottom);
    a.viewScanH = rh(list);
    float maxScroll = std::max(0.0f, (float)a.results.size() * ROW_H - a.viewScanH);
    if (a.scrollScan > maxScroll) a.scrollScan = maxScroll;

    a.gfx.rt->PushAxisAlignedClip(list, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    for (size_t i = 0; i < a.results.size(); i++) {
        float ry = listTop + (float)i * ROW_H - a.scrollScan;
        if (ry + ROW_H < listTop) continue;
        if (ry > listBottom) break;
        const ScanEntry &e = a.results[i];
        D2D1_RECT_F row = R(l.contentL, ry, l.contentR, ry + ROW_H - 2.0f);
        if ((int)i == a.selectedResult) fill_rect(a, row, a.theme.accentSoft, 6.0f);
        else if (a.hoverId == ID_RESULT_ROW + (int)i) fill_rect(a, row, a.theme.hover, 6.0f);
        chip(a, R(c0, ry + 8.0f, c0 + 70.0f, ry + 30.0f), bracket_short(u8(e.r.bracket)), e.level >= 2);
        text(a, elide(e.path, 72), R(c1, ry, c2 - 6.0f, ry + ROW_H), a.theme.text, a.gfx.fSmall);
        text(a, u8(e.r.layer), R(c2, ry, c3 - 4.0f, ry + ROW_H), a.theme.text3, a.gfx.fSmall);
        wchar_t sc[32];
        if (e.r.score < 0) swprintf(sc, 32, L"-");
        else swprintf(sc, 32, L"%.1f", e.r.score);
        text(a, sc, R(c3, ry, c4 - 4.0f, ry + ROW_H), a.theme.text2, a.gfx.fSmall);
        std::wstring caro = u8(e.r.caro);
        if (e.quarantined) caro = caro.empty() ? L"已隔离" : (caro + L" · 已隔离");
        text(a, elide(caro, 22), R(c4, ry, c5, ry + ROW_H), a.theme.text3, a.gfx.fSmall);
        a.hits.push_back({ID_RESULT_ROW + (int)i, row});
    }
    a.gfx.rt->PopAxisAlignedClip();

    if (a.results.empty()) {
        draw_empty(a, list, L"暂无扫描结果", L"选择文件或文件夹开始扫描");
    }

    bool selOk = a.selectedResult >= 0 && a.selectedResult < (int)a.results.size();
    bool canQuar = selOk && a.results[(size_t)a.selectedResult].level >= 2 &&
                   !a.results[(size_t)a.selectedResult].quarantined;
    button(a, ID_QUAR_SEL, R(l.contentL, l.h - 54.0f, l.contentL + 116.0f, l.h - 22.0f),
           L"隔离选中", true, canQuar);
    button(a, ID_OPEN_SEL, R(l.contentL + 124.0f, l.h - 54.0f, l.contentL + 240.0f, l.h - 22.0f),
           L"打开位置", false, selOk);
    text(a, L"提示：选中疑似/高危项后可隔离；隔离会移动并加密文件。",
         R(l.contentL + 252.0f, l.h - 54.0f, l.contentR, l.h - 22.0f), a.theme.text3, a.gfx.fSmall,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void draw_quarantine(App &a, const Layout &l) {
    float y = l.bodyTop;
    text(a, L"共 " + std::to_wstring(a.quarantine.size()) + L" 项",
         R(l.contentL, y, l.contentR - 260.0f, y + 34.0f), a.theme.text2, a.gfx.fBody,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    button(a, ID_RESTORE, R(l.contentR - 252.0f, y, l.contentR - 136.0f, y + 34.0f), L"恢复选中", true,
           a.selectedQuar >= 0 && a.selectedQuar < (int)a.quarantine.size());
    button(a, ID_DELETE, R(l.contentR - 128.0f, y, l.contentR - 68.0f, y + 34.0f), L"删除", false,
           a.selectedQuar >= 0 && a.selectedQuar < (int)a.quarantine.size());
    button(a, ID_QUAR_REFRESH, R(l.contentR - 60.0f, y, l.contentR, y + 34.0f), L"刷新", false, true);

    y += 44.0f;
    float q0 = l.contentL + 14.0f;
    float q1 = q0 + 148.0f;
    float q2 = l.contentR - 14.0f - 150.0f - 96.0f;
    float q3 = q2 + 96.0f;
    float q4 = l.contentR - 14.0f;
    D2D1_RECT_F head = R(l.contentL, y, l.contentR, y + 30.0f);
    fill_rect(a, head, a.theme.card2, 6.0f);
    text(a, L"隔离时间", R(q0, head.top, q1, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"原路径", R(q1, head.top, q2, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"结论", R(q2, head.top, q3, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"检测名", R(q3, head.top, q4, head.bottom), a.theme.text3, a.gfx.fSmall);

    float listTop = y + 34.0f;
    float listBottom = l.h - 72.0f;
    D2D1_RECT_F list = R(l.contentL, listTop, l.contentR, listBottom);
    a.viewQuarH = rh(list);
    float maxScroll = std::max(0.0f, (float)a.quarantine.size() * ROW_H - a.viewQuarH);
    if (a.scrollQuar > maxScroll) a.scrollQuar = maxScroll;

    a.gfx.rt->PushAxisAlignedClip(list, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    for (size_t i = 0; i < a.quarantine.size(); i++) {
        float ry = listTop + (float)i * ROW_H - a.scrollQuar;
        if (ry + ROW_H < listTop) continue;
        if (ry > listBottom) break;
        const QuarantineEntry &q = a.quarantine[i];
        D2D1_RECT_F row = R(l.contentL, ry, l.contentR, ry + ROW_H - 2.0f);
        if ((int)i == a.selectedQuar) fill_rect(a, row, a.theme.accentSoft, 6.0f);
        else if (a.hoverId == ID_QUAR_ROW + (int)i) fill_rect(a, row, a.theme.hover, 6.0f);
        text(a, q.time, R(q0, ry, q1 - 6.0f, ry + ROW_H), a.theme.text3, a.gfx.fSmall);
        text(a, elide(q.original, 58), R(q1, ry, q2 - 6.0f, ry + ROW_H), a.theme.text, a.gfx.fSmall);
        chip(a, R(q2, ry + 8.0f, q2 + 76.0f, ry + 30.0f), bracket_short(q.bracket), false);
        text(a, elide(q.caro, 22), R(q3, ry, q4, ry + ROW_H), a.theme.text3, a.gfx.fSmall);
        a.hits.push_back({ID_QUAR_ROW + (int)i, row});
    }
    a.gfx.rt->PopAxisAlignedClip();
    if (a.quarantine.empty()) {
        draw_empty(a, list, L"隔离区为空", L"在扫描结果中选中疑似/高危文件，点击“隔离选中”");
    }

    text(a, L"AES-256-GCM · 默认 TPM 2.0 / SGX 实验 · 旧 QTN1 兼容 · 恢复时自动解密",
         R(l.contentL, l.h - 54.0f, l.contentR, l.h - 22.0f), a.theme.text3, a.gfx.fSmall,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void draw_history(App &a, const Layout &l) {
    float y = l.bodyTop;
    text(a, L"共 " + std::to_wstring(a.history.size()) + L" 条",
         R(l.contentL, y, l.contentR - 360.0f, y + 34.0f), a.theme.text2, a.gfx.fBody,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    button(a, ID_HIST_REFRESH, R(l.contentR - 352.0f, y, l.contentR - 276.0f, y + 34.0f), L"刷新", true, true);
    button(a, ID_HIST_CLEAR, R(l.contentR - 268.0f, y, l.contentR - 160.0f, y + 34.0f), L"清空", false,
           !a.history.empty());
    button(a, ID_OPEN_LOGS, R(l.contentR - 152.0f, y, l.contentR, y + 34.0f), L"打开日志目录", false, true);

    y += 44.0f;
    float h0 = l.contentL + 14.0f;
    float h1 = h0 + 140.0f;
    float h2 = l.contentR - 14.0f;
    D2D1_RECT_F head = R(l.contentL, y, l.contentR, y + 30.0f);
    fill_rect(a, head, a.theme.card2, 6.0f);
    text(a, L"时间 / 结论", R(h0, head.top, h1, head.bottom), a.theme.text3, a.gfx.fSmall);
    text(a, L"文件 / 详情", R(h1, head.top, h2, head.bottom), a.theme.text3, a.gfx.fSmall);

    float listTop = y + 34.0f;
    float listBottom = l.h - 24.0f;
    D2D1_RECT_F list = R(l.contentL, listTop, l.contentR, listBottom);
    a.viewLogH = rh(list);
    float maxScroll = std::max(0.0f, (float)a.history.size() * HIST_ROW_H - a.viewLogH);
    if (a.scrollLog > maxScroll) a.scrollLog = maxScroll;

    a.gfx.rt->PushAxisAlignedClip(list, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    for (size_t i = 0; i < a.history.size(); i++) {
        float ry = listTop + (float)i * HIST_ROW_H - a.scrollLog;
        if (ry + HIST_ROW_H < listTop) continue;
        if (ry > listBottom) break;
        const HistoryEntry &h = a.history[i];
        D2D1_RECT_F row = R(l.contentL, ry, l.contentR, ry + HIST_ROW_H - 2.0f);
        if ((int)i == a.selectedLog) fill_rect(a, row, a.theme.accentSoft, 6.0f);
        else if (a.hoverId == ID_HIST_ROW + (int)i) fill_rect(a, row, a.theme.hover, 6.0f);
        text(a, h.time, R(h0, ry + 4.0f, h0 + 132.0f, ry + 24.0f), a.theme.text3, a.gfx.fSmall);
        chip(a, R(h0 + 136.0f, ry + 4.0f, h0 + 196.0f, ry + 24.0f), bracket_short(h.bracket), h.level >= 2);
        text(a, elide(h.path, 80), R(h1, ry + 2.0f, h2, ry + 24.0f), a.theme.text, a.gfx.fSmall);
        std::wstring detail = h.detail;
        if (detail.empty()) detail = h.caro;
        text(a, elide(detail, 120), R(h1, ry + 24.0f, h2, ry + 46.0f), a.theme.text3, a.gfx.fSmall);
        a.hits.push_back({ID_HIST_ROW + (int)i, row});
    }
    a.gfx.rt->PopAxisAlignedClip();
    if (a.history.empty()) {
        draw_empty(a, list, L"暂无历史记录", L"完成扫描或处置后，记录会写入 logs\\history.tsv");
    }
}

static void settings_label(App &a, float x, float y, float w, const std::wstring &label) {
    text(a, label, R(x, y, x + 170.0f, y + 30.0f), a.theme.text2, a.gfx.fBody,
         DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    (void)w;
}

static void draw_settings(App &a, const Layout &l) {
    float y = l.bodyTop;
    float inner = l.contentW - 36.0f;

    /* 外观 */
    D2D1_RECT_F c1 = R(l.contentL, y, l.contentR, y + 112.0f);
    card(a, c1);
    text(a, L"外观", R(c1.left + 18.0f, c1.top + 10.0f, c1.right - 18.0f, c1.top + 34.0f),
         a.theme.text, a.gfx.fH3);
    settings_label(a, c1.left + 18.0f, c1.top + 40.0f, inner, L"主题");
    button(a, ID_THEME_SYS, R(c1.left + 196.0f, c1.top + 40.0f, c1.left + 300.0f, c1.top + 70.0f),
           L"跟随系统", a.settings.theme == 0, true);
    button(a, ID_THEME_LIGHT, R(c1.left + 308.0f, c1.top + 40.0f, c1.left + 388.0f, c1.top + 70.0f),
           L"浅色", a.settings.theme == 1, true);
    button(a, ID_THEME_DARK, R(c1.left + 396.0f, c1.top + 40.0f, c1.left + 476.0f, c1.top + 70.0f),
           L"深色", a.settings.theme == 2, true);
    settings_label(a, c1.left + 18.0f, c1.top + 76.0f, inner, L"动画");
    button(a, ID_ANIM, R(c1.left + 196.0f, c1.top + 76.0f, c1.left + 296.0f, c1.top + 106.0f),
           a.settings.animations ? L"开启" : L"关闭", a.settings.animations != 0, true);

    /* 扫描 */
    y = c1.bottom + 12.0f;
    D2D1_RECT_F c2 = R(l.contentL, y, l.contentR, y + 150.0f);
    card(a, c2);
    text(a, L"扫描", R(c2.left + 18.0f, c2.top + 10.0f, c2.right - 18.0f, c2.top + 34.0f),
         a.theme.text, a.gfx.fH3);
    settings_label(a, c2.left + 18.0f, c2.top + 40.0f, inner, L"最大扫描文件");
    text(a, std::to_wstring(a.settings.maxMb) + L" MB",
         R(c2.left + 196.0f, c2.top + 40.0f, c2.left + 300.0f, c2.top + 70.0f),
         a.theme.text, a.gfx.fBody, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    button(a, ID_MAX_MINUS, R(c2.left + 306.0f, c2.top + 40.0f, c2.left + 342.0f, c2.top + 70.0f), L"-", false, true);
    button(a, ID_MAX_PLUS, R(c2.left + 350.0f, c2.top + 40.0f, c2.left + 386.0f, c2.top + 70.0f), L"+", false, true);
    settings_label(a, c2.left + 18.0f, c2.top + 76.0f, inner, L"病毒库");
    text(a, std::to_wstring(a.dbCount) + L" 条",
         R(c2.left + 196.0f, c2.top + 76.0f, c2.left + 300.0f, c2.top + 106.0f),
         a.theme.text, a.gfx.fBody, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    button(a, ID_DB_RELOAD, R(c2.left + 306.0f, c2.top + 76.0f, c2.left + 386.0f, c2.top + 106.0f), L"重载", false, true);
    button(a, ID_OPEN_DATA, R(c2.left + 394.0f, c2.top + 76.0f, c2.left + 510.0f, c2.top + 106.0f),
           L"打开数据目录", false, true);

    /* 隔离密钥后端：TPM 默认；SGX 可选、默认关闭 */
    settings_label(a, c2.left + 18.0f, c2.top + 108.0f, inner, L"隔离密钥");
    button(a, ID_KEY_TPM, R(c2.left + 196.0f, c2.top + 108.0f, c2.left + 300.0f, c2.top + 138.0f),
           L"TPM 2.0", qtn_get_key_mode() == 0, true);
    bool sgx_ok = qtn_sgx_available();
    button(a, ID_KEY_SGX, R(c2.left + 308.0f, c2.top + 108.0f, c2.left + 408.0f, c2.top + 138.0f),
           L"SGX（实验）", qtn_get_key_mode() == 1, sgx_ok);
    {
        std::wstring st;
        if (sgx_ok) st = L"SGX 可用（实验，默认关闭）";
        else if (qtn_sgx_cpu_support()) st = L"CPU 支持 SGX，但 enclave 后端未编译/未加载";
        else st = L"CPU 不支持 SGX（CPUID.7:EBX[2]=0）";
        text(a, st, R(c2.left + 420.0f, c2.top + 108.0f, c2.right - 18.0f, c2.top + 138.0f),
             a.theme.text3, a.gfx.fSmall, DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    }

    /* 内核执行端 */
    y = c2.bottom + 12.0f;
    D2D1_RECT_F c3 = R(l.contentL, y, l.contentR, y + 96.0f);
    card(a, c3);
    text(a, L"内核执行端（HIPS）", R(c3.left + 18.0f, c3.top + 10.0f, c3.right - 120.0f, c3.top + 34.0f),
         a.theme.text, a.gfx.fH3);
    chip(a, R(c3.right - 128.0f, c3.top + 10.0f, c3.right - 18.0f, c3.top + 34.0f), a.driverState, a.driverState == L"运行中");
    text(a, a.driverDetail, R(c3.left + 18.0f, c3.top + 40.0f, c3.right - 128.0f, c3.top + 62.0f),
         a.theme.text3, a.gfx.fSmall);
    button(a, ID_DRV_REFRESH, R(c3.right - 128.0f, c3.top + 64.0f, c3.right - 18.0f, c3.top + 92.0f),
           L"刷新状态", false, true);
    text(a, L"驱动设备 ACL 仅允许 SYSTEM；本机不加载未签名驱动，测试只在 VM 快照内进行。",
         R(c3.left + 18.0f, c3.top + 64.0f, c3.right - 140.0f, c3.top + 92.0f),
         a.theme.text3, a.gfx.fSmall);

    /* 关于 */
    y = c3.bottom + 12.0f;
    D2D1_RECT_F c4 = R(l.contentL, y, l.contentR, y + 116.0f);
    card(a, c4);
    text(a, L"关于", R(c4.left + 18.0f, c4.top + 10.0f, c4.right - 18.0f, c4.top + 34.0f),
         a.theme.text, a.gfx.fH3);
    text(a, L"扫描引擎  " + a.engineVersion + L"    ABI " + std::to_wstring(a.abiVersion),
         R(c4.left + 18.0f, c4.top + 40.0f, c4.right - 18.0f, c4.top + 62.0f),
         a.theme.text2, a.gfx.fSmall);
    text(a, L"数据目录  " + scanner_data_dir(),
         R(c4.left + 18.0f, c4.top + 62.0f, c4.right - 18.0f, c4.top + 84.0f),
         a.theme.text3, a.gfx.fSmall);
    text(a, L"边界：静态扫描、手动隔离、历史记录；不含实时监控、自动处置或未签名驱动加载。",
         R(c4.left + 18.0f, c4.top + 88.0f, c4.right - 18.0f, c4.top + 112.0f),
         a.theme.text3, a.gfx.fSmall);
}

static void draw_toast(App &a, const Layout &l) {
    if (a.toast.empty() || GetTickCount64() >= a.toastUntil) return;
    float w = std::min(460.0f, l.contentW - 40.0f);
    D2D1_RECT_F r = R((l.w - w) * 0.5f, l.h - 46.0f, (l.w + w) * 0.5f, l.h - 12.0f);
    fill_rect(a, r, a.theme.accent, 6.0f);
    text(a, a.toast, R(r.left + 14.0f, r.top, r.right - 14.0f, r.bottom),
         a.theme.dark ? a.theme.black : a.theme.white, a.gfx.fSmall,
         DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void open_location(const std::wstring &path) {
    if (path.empty()) return;
    std::wstring args = L"/select,\"" + path + L"\"";
    ShellExecuteW(NULL, L"open", L"explorer.exe", args.c_str(), NULL, SW_SHOWNORMAL);
}

} // namespace

void ui_draw(App &a) {
    if (!a.gfx.rt) return;
    a.hits.clear();
    Layout l = make_layout(a);
    a.gfx.begin();
    fill_rect(a, R(0, 0, l.w, l.h), a.theme.bg1);
    draw_sidebar(a, l);
    draw_header(a, l);
    switch (a.page) {
    case Page::Overview:   draw_overview(a, l); break;
    case Page::Protection: draw_protection(a, l); break;
    case Page::Quarantine: draw_quarantine(a, l); break;
    case Page::History:    draw_history(a, l); break;
    case Page::Settings:   draw_settings(a, l); break;
    default: break;
    }
    draw_toast(a, l);
    a.gfx.end();
}

void ui_on_click(App &a, int id, float x, float y) {
    (void)x;
    (void)y;

    if (id >= ID_NAV_OVERVIEW && id <= ID_NAV_SETTINGS) {
        a.page = (Page)(id - ID_NAV_OVERVIEW);
        a.start_page_anim();
        return;
    }
    if (id >= ID_RESULT_ROW && id < ID_RESULT_ROW + 10000) {
        a.selectedResult = id - ID_RESULT_ROW;
        return;
    }
    if (id >= ID_QUAR_ROW && id < ID_QUAR_ROW + 10000) {
        a.selectedQuar = id - ID_QUAR_ROW;
        return;
    }
    if (id >= ID_HIST_ROW && id < ID_HIST_ROW + 10000) {
        a.selectedLog = id - ID_HIST_ROW;
        return;
    }

    switch (id) {
    case ID_QUICK:
        scan_quick();
        break;
    case ID_PICK_FILE:
        pick_and_scan_file();
        break;
    case ID_PICK_FOLDER:
        pick_and_scan_folder();
        break;
    case ID_STOP:
        scanner_cancel();
        a.show_toast(L"已请求停止扫描");
        break;
    case ID_CLEAR:
        scanner_clear_results();
        break;
    case ID_QUAR_SEL:
        scanner_quarantine_selected();
        break;
    case ID_OPEN_SEL:
        if (a.selectedResult >= 0 && a.selectedResult < (int)a.results.size())
            open_location(a.results[(size_t)a.selectedResult].path);
        break;
    case ID_HW_REFRESH:
        scanner_refresh_hardware();
        a.show_toast(L"硬件环境已刷新");
        break;
    case ID_VIEW_HISTORY:
        a.page = Page::History;
        a.start_page_anim();
        break;

    case ID_RESTORE:
        scanner_restore_selected();
        break;
    case ID_DELETE:
        scanner_delete_selected();
        break;
    case ID_QUAR_REFRESH:
        scanner_load_quarantine();
        a.show_toast(L"隔离区已刷新");
        break;

    case ID_HIST_REFRESH:
        scanner_load_history();
        a.show_toast(L"历史记录已刷新");
        break;
    case ID_HIST_CLEAR:
        scanner_clear_history();
        break;
    case ID_OPEN_LOGS:
        open_log_dir();
        break;

    case ID_THEME_SYS:
        a.settings.theme = 0;
        a.themeMode = ThemeMode::System;
        apply_theme(true);
        scanner_save_settings();
        break;
    case ID_THEME_LIGHT:
        a.settings.theme = 1;
        a.themeMode = ThemeMode::Light;
        apply_theme(true);
        scanner_save_settings();
        break;
    case ID_THEME_DARK:
        a.settings.theme = 2;
        a.themeMode = ThemeMode::Dark;
        apply_theme(true);
        scanner_save_settings();
        break;
    case ID_ANIM:
        a.settings.animations = a.settings.animations ? 0 : 1;
        scanner_save_settings();
        break;
    case ID_DB_RELOAD:
        scanner_db_reload();
        break;
    case ID_OPEN_DATA:
        open_data_dir();
        break;
    case ID_DRV_REFRESH:
        scanner_refresh_driver();
        a.show_toast(L"驱动状态已刷新");
        break;
    case ID_MAX_MINUS:
        a.settings.maxMb = std::max(16, a.settings.maxMb - 16);
        scanner_save_settings();
        break;
    case ID_MAX_PLUS:
        a.settings.maxMb = std::min(4096, a.settings.maxMb + 16);
        scanner_save_settings();
        break;
    case ID_KEY_TPM:
        if (qtn_set_key_mode(0)) {
            a.settings.keyMode = 0;
            scanner_save_settings();
            a.show_toast(L"隔离密钥后端：TPM 2.0");
        }
        break;
    case ID_KEY_SGX:
        if (qtn_sgx_available() && qtn_set_key_mode(1)) {
            a.settings.keyMode = 1;
            scanner_save_settings();
            a.show_toast(L"隔离密钥后端：SGX（实验）");
        } else {
            a.show_toast(L"SGX 不可用：CPU 不支持或 enclave 后端未加载");
        }
        break;
    default:
        break;
    }
}

void ui_on_move(App &a, float x, float y) {
    int id = a.hit_test(x, y);
    if (id != a.hoverId) {
        a.hoverId = id;
        if (a.hwnd) InvalidateRect(a.hwnd, NULL, FALSE);
    }
}

void ui_on_wheel(App &a, float x, float y, int delta) {
    (void)x;
    (void)y;
    float step = (delta > 0) ? -60.0f : 60.0f;
    if (a.page == Page::Protection) {
        float maxS = std::max(0.0f, (float)a.results.size() * ROW_H - a.viewScanH);
        a.scrollScan = std::max(0.0f, std::min(maxS, a.scrollScan + step));
    } else if (a.page == Page::Quarantine) {
        float maxS = std::max(0.0f, (float)a.quarantine.size() * ROW_H - a.viewQuarH);
        a.scrollQuar = std::max(0.0f, std::min(maxS, a.scrollQuar + step));
    } else if (a.page == Page::History) {
        float maxS = std::max(0.0f, (float)a.history.size() * HIST_ROW_H - a.viewLogH);
        a.scrollLog = std::max(0.0f, std::min(maxS, a.scrollLog + step));
    }
}

void ui_on_key(App &a, WPARAM key) {
    if (key == VK_ESCAPE) {
        scanner_cancel();
        return;
    }
    if (key == VK_F5) {
        scanner_refresh_hardware();
        scanner_refresh_driver();
        scanner_db_count();
        a.show_toast(L"状态已刷新");
        return;
    }
    if (key == VK_DOWN || key == VK_UP) {
        int d = (key == VK_DOWN) ? 1 : -1;
        if (a.page == Page::Protection && !a.results.empty()) {
            int n = (int)a.results.size();
            a.selectedResult = std::max(0, std::min(n - 1, (a.selectedResult < 0 ? 0 : a.selectedResult) + d));
        } else if (a.page == Page::Quarantine && !a.quarantine.empty()) {
            int n = (int)a.quarantine.size();
            a.selectedQuar = std::max(0, std::min(n - 1, (a.selectedQuar < 0 ? 0 : a.selectedQuar) + d));
        } else if (a.page == Page::History && !a.history.empty()) {
            int n = (int)a.history.size();
            a.selectedLog = std::max(0, std::min(n - 1, (a.selectedLog < 0 ? 0 : a.selectedLog) + d));
        }
    }
}
