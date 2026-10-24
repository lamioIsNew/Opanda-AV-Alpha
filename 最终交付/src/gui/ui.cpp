/* ui.cpp -- Direct2D 自绘界面（WD 风格） */
#include "app.h"

#include <d2d1helper.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>
#include <shellapi.h>

enum {
    ID_NAV_HOME = 1, ID_NAV_SCAN, ID_NAV_PROTECTION, ID_NAV_QUARANTINE,
    ID_NAV_LOGS, ID_NAV_DRIVER, ID_NAV_SETTINGS,
    ID_HEADER_STATUS = 20,

    ID_HOME_QUICK = 100, ID_HOME_CUSTOM, ID_HOME_VIEW_LOGS, ID_HOME_PROTECT,

    ID_SCAN_FILE = 200, ID_SCAN_DIR, ID_SCAN_QUICK, ID_SCAN_START, ID_SCAN_CLEAR,
    ID_SCAN_QUARANTINE, ID_SCAN_OPEN,

    ID_PROT_DRIVER = 300,

    ID_QUAR_REFRESH = 400, ID_QUAR_RESTORE, ID_QUAR_DELETE,

    ID_LOG_REFRESH = 500, ID_LOG_CLEAR, ID_LOG_OPEN,

    ID_DRV_REFRESH = 600, ID_DRV_OPEN_DATA,

    ID_SET_THEME_SYS = 700, ID_SET_THEME_LIGHT, ID_SET_THEME_DARK,
    ID_SET_MAX_MINUS, ID_SET_MAX_PLUS, ID_SET_ANIM, ID_SET_RELOAD, ID_SET_OPEN,

    ID_ROW_RESULT = 1000,
    ID_ROW_QUAR = 2000,
    ID_ROW_LOG = 3000
};

struct Layout {
    float W, H, sb, cx, cw;
};

static Layout layout_of(App &a) {
    D2D1_SIZE_F s = a.gfx.rt ? a.gfx.rt->GetSize() : D2D1::SizeF(1240, 840);
    Layout l;
    l.W = s.width;
    l.H = s.height;
    l.sb = (l.W < 1120.0f) ? 212.0f : 232.0f;
    l.cx = l.sb + 30.0f;
    l.cw = l.W - l.cx - 30.0f;
    return l;
}

static D2D1_RECT_F R(float l, float t, float r, float b) {
    return D2D1::RectF(l, t, r, b);
}

static void fr(App &a, const D2D1_RECT_F &r, float rad, const D2D1_COLOR_F &c) {
    if (!a.gfx.rt || r.right <= r.left || r.bottom <= r.top) return;
    a.gfx.brush->SetColor(c);
    a.gfx.rt->FillRoundedRectangle(D2D1::RoundedRect(r, rad, rad), a.gfx.brush);
}

static void sr(App &a, const D2D1_RECT_F &r, float rad, const D2D1_COLOR_F &c, float w = 1.0f) {
    if (!a.gfx.rt || r.right <= r.left || r.bottom <= r.top) return;
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawRoundedRectangle(D2D1::RoundedRect(r, rad, rad), a.gfx.brush, w);
}

static void rect(App &a, const D2D1_RECT_F &r, const D2D1_COLOR_F &c) {
    if (!a.gfx.rt) return;
    a.gfx.brush->SetColor(c);
    a.gfx.rt->FillRectangle(r, a.gfx.brush);
}

static void line(App &a, float x1, float y1, float x2, float y2,
                 const D2D1_COLOR_F &c, float w = 1.0f) {
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), a.gfx.brush, w);
}

static void txt(App &a, const std::wstring &s, const D2D1_RECT_F &r,
                IDWriteTextFormat *f, const D2D1_COLOR_F &c,
                DWRITE_TEXT_ALIGNMENT al = DWRITE_TEXT_ALIGNMENT_LEADING,
                DWRITE_PARAGRAPH_ALIGNMENT va = DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
                D2D1_DRAW_TEXT_OPTIONS opt = D2D1_DRAW_TEXT_OPTIONS_CLIP) {
    if (!a.gfx.rt || !f || s.empty()) return;
    f->SetTextAlignment(al);
    f->SetParagraphAlignment(va);
    a.gfx.brush->SetColor(c);
    a.gfx.rt->DrawText(s.c_str(), (UINT32)s.size(), f, r, a.gfx.brush, opt);
}

static void icon(App &a, const wchar_t *glyph, const D2D1_RECT_F &r,
                 const D2D1_COLOR_F &c, IDWriteTextFormat *f = nullptr) {
    txt(a, glyph ? glyph : L"", r, f ? f : a.gfx.fIcon, c,
        DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void shadow(App &a, const D2D1_RECT_F &r, float rad) {
    if (!a.settings.animations) return;
    float base = a.theme.dark ? 0.16f : 0.045f;
    for (int i = 0; i < 3; i++) {
        float o = 1.0f + i * 2.0f;
        D2D1_RECT_F s = R(r.left - o, r.top + o, r.right + o, r.bottom + o + 2.0f);
        fr(a, s, rad + o, C(0x000000, base - i * 0.012f));
    }
}

static void card(App &a, const D2D1_RECT_F &r, float rad = 14.0f, bool hover = false) {
    shadow(a, r, rad);
    fr(a, r, rad, hover ? a.theme.cardHover : a.theme.card);
    sr(a, r, rad, a.theme.border, 1.0f);
}

static void chip(App &a, const D2D1_RECT_F &r, const std::wstring &s,
                 const D2D1_COLOR_F &fg, const D2D1_COLOR_F &bg,
                 IDWriteTextFormat *fmt = nullptr) {
    fr(a, r, (r.bottom - r.top) * 0.5f, bg);
    txt(a, s, r, fmt ? fmt : a.gfx.fBadge, fg,
        DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void button(App &a, int id, const D2D1_RECT_F &r, const std::wstring &label,
                   bool primary = false, bool danger = false, bool enabled = true,
                   const wchar_t *glyph = nullptr) {
    bool hov = enabled && a.hoverId == id;
    bool press = enabled && a.pressedId == id && hov;
    D2D1_COLOR_F fill, fg, border;

    if (!enabled) {
        fill = a.theme.hover;
        fg = a.theme.text3;
        border = a.theme.border;
    } else if (primary) {
        fill = a.theme.accent;
        if (hov) fill = mixc(fill, a.theme.white, 0.10f);
        if (press) fill = mixc(fill, a.theme.black, 0.10f);
        fg = a.theme.white;
        border = fill;
    } else if (danger) {
        fill = a.theme.dangerSoft;
        fg = a.theme.danger;
        border = mixc(a.theme.danger, a.theme.card, 0.55f);
        if (hov) fill = mixc(fill, a.theme.danger, 0.08f);
    } else {
        fill = a.theme.card2;
        fg = a.theme.text;
        border = a.theme.border;
        if (hov) fill = a.theme.cardHover;
        if (press) fill = mixc(fill, a.theme.black, a.theme.dark ? 0.10f : 0.05f);
    }

    fr(a, r, 8.0f, fill);
    sr(a, r, 8.0f, border, 1.0f);
    if (enabled) a.hits.push_back({id, r});

    float textLeft = r.left + 14.0f;
    if (glyph) {
        D2D1_RECT_F ir = R(r.left + 12.0f, r.top, r.left + 34.0f, r.bottom);
        icon(a, glyph, ir, fg, a.gfx.fIcon);
        textLeft = r.left + 36.0f;
    }
    D2D1_RECT_F tr = R(textLeft, r.top, r.right - 10.0f, r.bottom);
    txt(a, label, tr, a.gfx.fButton, fg, DWRITE_TEXT_ALIGNMENT_CENTER,
        DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

static void toggle(App &a, const D2D1_RECT_F &r, bool on, bool enabled) {
    D2D1_COLOR_F track = !enabled ? a.theme.track : (on ? a.theme.accent : a.theme.track);
    fr(a, r, r.bottom - r.top, track);
    float d = (r.bottom - r.top) - 6.0f;
    float x = on ? (r.right - 3.0f - d) : (r.left + 3.0f);
    D2D1_ELLIPSE e = D2D1::Ellipse(D2D1::Point2F(x + d * 0.5f, (r.top + r.bottom) * 0.5f),
                                   d * 0.5f, d * 0.5f);
    a.gfx.brush->SetColor(enabled ? a.theme.white : a.theme.text3);
    a.gfx.rt->FillEllipse(e, a.gfx.brush);
}

static std::wstring from_u8(const char *p) {
    if (!p || !*p) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, p, -1, NULL, 0);
    if (n <= 1) return L"";
    std::wstring s((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, p, -1, &s[0], n);
    return s;
}

static std::wstring base_name(const std::wstring &p) {
    size_t x = p.find_last_of(L"\\/");
    return (x == std::wstring::npos) ? p : p.substr(x + 1);
}

static std::wstring score_text(double s) {
    if (s < 0) return L"—";
    wchar_t b[32];
    if (s < 10.0) swprintf(b, 32, L"%.2f", s);
    else swprintf(b, 32, L"%.1f", s);
    return b;
}

static D2D1_COLOR_F level_fg(App &a, int lv) {
    switch (lv) {
        case 3: return a.theme.danger;
        case 2: return a.theme.warning;
        case 1: return a.theme.success;
        case 4: return a.theme.warning;
        case 5: return a.theme.text3;
        default: return a.theme.danger;
    }
}

static D2D1_COLOR_F level_bg(App &a, int lv) {
    switch (lv) {
        case 3: return a.theme.dangerSoft;
        case 2: return a.theme.warningSoft;
        case 1: return a.theme.successSoft;
        case 4: return a.theme.warningSoft;
        case 5: return a.theme.hover;
        default: return a.theme.dangerSoft;
    }
}

static const wchar_t *level_glyph(int lv) {
    switch (lv) {
        case 3: return L"\uEA39"; /* blocked */
        case 2: return L"\uE7BA"; /* warning */
        case 1: return L"\uE73E"; /* check */
        case 4: return L"\uE7B8"; /* package */
        case 5: return L"\uE8AB"; /* skip */
        default: return L"\uE783"; /* error */
    }
}

static std::wstring level_name(int lv) {
    switch (lv) {
        case 3: return L"高危";
        case 2: return L"疑似";
        case 1: return L"正常";
        case 4: return L"加壳";
        case 5: return L"跳过";
        default: return L"错误";
    }
}

static void scrollbar(App &a, const D2D1_RECT_F &r, float scroll, float content, float view) {
    if (content <= view + 1.0f) return;
    float trackW = 4.0f;
    float x = r.right - trackW;
    fr(a, R(x, r.top, x + trackW, r.bottom), trackW * 0.5f, a.theme.track);
    float thumbH = std::max(30.0f, view * view / content);
    float maxScroll = content - view;
    float t = maxScroll > 0 ? scroll / maxScroll : 0;
    float y = r.top + t * (view - thumbH);
    fr(a, R(x, y, x + trackW, y + thumbH), trackW * 0.5f, a.theme.text3);
}

static std::wstring theme_name(int t) {
    if (t == 1) return L"浅色";
    if (t == 2) return L"深色";
    return L"跟随系统";
}

/* ---------------- 侧边栏 / 顶栏 ---------------- */
static void draw_sidebar(App &a, const Layout &l) {
    rect(a, R(0, 0, l.sb, l.H), a.theme.sidebar);
    line(a, l.sb - 1, 0, l.sb - 1, l.H, a.theme.border, 1.0f);

    icon(a, L"\uEA18", R(18, 22, 52, 56), a.theme.accent, a.gfx.fIconBrand);
    txt(a, L"恶意软件扫描器", R(60, 22, l.sb - 12, 46), a.gfx.fBrand, a.theme.text);
    txt(a, L"Malware Scanner", R(61, 46, l.sb - 12, 62), a.gfx.fSmall, a.theme.text3);

    const wchar_t *glyphs[] = {
        L"\uE80F", L"\uE721", L"\uEA18", L"\uE74D",
        L"\uE9D9", L"\uE7EF", L"\uE713"
    };
    const wchar_t *names[] = {
        L"主页", L"扫描", L"防护", L"隔离区", L"日志", L"驱动与内核", L"设置"
    };

    float y = 100.0f;
    const float itemH = 42.0f;
    const float gap = 4.0f;
    for (int i = 0; i < 7; i++) {
        int id = ID_NAV_HOME + i;
        D2D1_RECT_F r = R(12, y, l.sb - 12, y + itemH);
        bool sel = (int)a.page == i;
        bool hov = a.hoverId == id;
        if (sel) {
            fr(a, r, 9.0f, a.theme.accentSoft);
            fr(a, R(r.left, r.top + 11, r.left + 3, r.bottom - 11), 1.5f, a.theme.accent);
        } else if (hov) {
            fr(a, r, 9.0f, a.theme.hover);
        }
        D2D1_COLOR_F fg = sel ? a.theme.accent : a.theme.text2;
        icon(a, glyphs[i], R(r.left + 14, r.top, r.left + 40, r.bottom), fg);
        txt(a, names[i], R(r.left + 48, r.top, r.right - 40, r.bottom), a.gfx.fBody, fg,
            DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        if (i == 3 && !a.quarantine.empty()) {
            std::wstring n = std::to_wstring(a.quarantine.size());
            D2D1_RECT_F br = R(r.right - 38, r.top + 12, r.right - 12, r.bottom - 12);
            chip(a, br, n, a.theme.danger, a.theme.dangerSoft, a.gfx.fBadge);
        }
        a.hits.push_back({id, r});
        y += itemH + gap;
    }

    /* 底部引擎/病毒库状态 */
    D2D1_RECT_F sc = R(12, l.H - 100, l.sb - 12, l.H - 18);
    fr(a, sc, 11.0f, a.theme.card2);
    sr(a, sc, 11.0f, a.theme.border, 1.0f);
    D2D1_ELLIPSE dot = D2D1::Ellipse(D2D1::Point2F(sc.left + 16, sc.top + 20), 4, 4);
    a.gfx.brush->SetColor(a.engineReady ? a.theme.success : a.theme.danger);
    a.gfx.rt->FillEllipse(dot, a.gfx.brush);
    txt(a, a.engineReady ? L"扫描引擎已就绪" : L"扫描引擎未加载",
        R(sc.left + 28, sc.top + 9, sc.right - 10, sc.top + 31), a.gfx.fSmall, a.theme.text2);
    txt(a, L"病毒库 " + std::to_wstring(a.dbCount) + L" 条",
        R(sc.left + 14, sc.top + 36, sc.right - 10, sc.top + 56), a.gfx.fSmall, a.theme.text3);
    txt(a, L"v" + a.engineVersion,
        R(sc.left + 14, sc.top + 56, sc.right - 10, sc.top + 76), a.gfx.fSmall, a.theme.text3);
}

static void draw_header(App &a, const Layout &l, const std::wstring &title,
                        const std::wstring &sub) {
    txt(a, title, R(l.cx, 22, l.cx + l.cw - 240, 58), a.gfx.fH1, a.theme.text);
    txt(a, sub, R(l.cx, 60, l.cx + l.cw - 260, 82), a.gfx.fBody, a.theme.text2);

    std::wstring status = a.scanning.load() ? L"正在扫描" : L"手动扫描模式";
    D2D1_RECT_F chipR = R(l.cx + l.cw - 188, 28, l.cx + l.cw, 60);
    chip(a, chipR, status, a.scanning.load() ? a.theme.accent : a.theme.warning,
         a.scanning.load() ? a.theme.accentSoft : a.theme.warningSoft, a.gfx.fButton);
    a.hits.push_back({ID_HEADER_STATUS, chipR});
}

/* ---------------- 主页 ---------------- */
static void draw_home(App &a, const Layout &l) {
    draw_header(a, l, L"主页", L"设备状态、最近活动与保护概览");

    float y = 96;
    D2D1_RECT_F hero = R(l.cx, y, l.cx + l.cw, y + 180);
    fr(a, hero, 16.0f, a.theme.accent);
    /* 柔光装饰 */
    D2D1_ELLIPSE e1 = D2D1::Ellipse(D2D1::Point2F(hero.right - 90, hero.top + 46), 140, 140);
    a.gfx.brush->SetColor(C(0xFFFFFF, a.theme.dark ? 0.05f : 0.08f));
    a.gfx.rt->FillEllipse(e1, a.gfx.brush);
    D2D1_ELLIPSE e2 = D2D1::Ellipse(D2D1::Point2F(hero.right - 190, hero.bottom - 18), 90, 90);
    a.gfx.brush->SetColor(C(0xFFFFFF, 0.04f));
    a.gfx.rt->FillEllipse(e2, a.gfx.brush);
    icon(a, L"\uEA18", R(hero.right - 230, hero.top + 20, hero.right - 30, hero.bottom - 10),
         C(0xFFFFFF, 0.18f), a.gfx.fIconHuge);

    txt(a, L"保持你的设备安全", R(hero.left + 26, hero.top + 22, hero.right - 260, hero.top + 60),
        a.gfx.fHero, a.theme.white);
    txt(a, L"快速扫描常见位置，或选择自定义文件夹。", R(hero.left + 26, hero.top + 66, hero.right - 280, hero.top + 92),
        a.gfx.fHeroSub, C(0xFFFFFF, 0.88f));
    txt(a, L"判定阈值：风险评分 ≥ 80 高危，≥ 50 疑似",
        R(hero.left + 26, hero.top + 94, hero.right - 280, hero.top + 116),
        a.gfx.fSmall, C(0xFFFFFF, 0.70f));

    D2D1_RECT_F b1 = R(hero.left + 26, hero.bottom - 48, hero.left + 146, hero.bottom - 12);
    D2D1_RECT_F b2 = R(hero.left + 158, hero.bottom - 48, hero.left + 290, hero.bottom - 12);
    fr(a, b1, 8.0f, a.theme.white);
    a.hits.push_back({ID_HOME_QUICK, b1});
    txt(a, L"快速扫描", b1, a.gfx.fButton, a.theme.accent,
        DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    sr(a, b2, 8.0f, C(0xFFFFFF, 0.65f), 1.0f);
    a.hits.push_back({ID_HOME_CUSTOM, b2});
    txt(a, L"自定义扫描", b2, a.gfx.fButton, a.theme.white,
        DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    float sy = y + 198;
    float gap = 14;
    float sw = (l.cw - gap * 2) / 3;
    const wchar_t *labels[3] = {L"上次扫描文件", L"发现威胁", L"特征库条目"};
    std::wstring values[3];
    values[0] = a.stats.files > 0 ? std::to_wstring(a.stats.files) : L"—";
    values[1] = a.stats.high > 0 ? std::to_wstring(a.stats.high) : L"0";
    values[2] = std::to_wstring(a.dbCount);
    const wchar_t *icons[3] = {L"\uE9D9", L"\uEA39", L"\uE8F1"};
    for (int i = 0; i < 3; i++) {
        D2D1_RECT_F c = R(l.cx + i * (sw + gap), sy, l.cx + i * (sw + gap) + sw, sy + 108);
        card(a, c);
        txt(a, labels[i], R(c.left + 18, c.top + 16, c.right - 56, c.top + 36),
            a.gfx.fSmall, a.theme.text2);
        txt(a, values[i], R(c.left + 18, c.top + 38, c.right - 60, c.top + 78),
            a.gfx.fStat, a.theme.text);
        D2D1_RECT_F ic = R(c.right - 50, c.top + 16, c.right - 18, c.top + 48);
        fr(a, ic, 8.0f, a.theme.accentSoft);
        icon(a, icons[i], ic, a.theme.accent);
        std::wstring sub = i == 1
                               ? L"高危 / 疑似 " + std::to_wstring(a.stats.high) + L" / " +
                                     std::to_wstring(a.stats.suspicious)
                               : (i == 0 ? L"本次会话累计" : L"signatures.db");
        txt(a, sub, R(c.left + 18, c.top + 78, c.right - 18, c.top + 98),
            a.gfx.fSmall, a.theme.text3);
    }

    float by = sy + 126;
    float bh = std::max(120.0f, l.H - by - 26);
    float bw = l.cw * 0.58f;
    D2D1_RECT_F recent = R(l.cx, by, l.cx + bw, by + bh);
    D2D1_RECT_F protect = R(recent.right + 16, by, l.cx + l.cw, by + bh);
    card(a, recent);
    card(a, protect);

    txt(a, L"最近活动", R(recent.left + 18, recent.top + 14, recent.right - 120, recent.top + 38),
        a.gfx.fH2, a.theme.text);
    D2D1_RECT_F vw = R(recent.right - 92, recent.top + 15, recent.right - 14, recent.top + 35);
    button(a, ID_HOME_VIEW_LOGS, vw, L"查看全部", false, false, true);

    if (a.history.empty()) {
        icon(a, L"\uE9D9", R(recent.left + 18, recent.top + 52, recent.left + 58, recent.top + 92),
             a.theme.text3, a.gfx.fIconBig);
        txt(a, L"还没有扫描记录", R(recent.left + 70, recent.top + 58, recent.right - 18, recent.top + 82),
            a.gfx.fH3, a.theme.text2);
        txt(a, L"快速扫描后，这里会显示最近发现。", R(recent.left + 70, recent.top + 82, recent.right - 18, recent.top + 102),
            a.gfx.fSmall, a.theme.text3);
    } else {
        float ry = recent.top + 50;
        int n = std::min<int>(4, (int)a.history.size());
        for (int i = 0; i < n; i++) {
            const HistoryEntry &h = a.history[(size_t)i];
            if (ry + 42 > recent.bottom - 8) break;
            D2D1_ELLIPSE dot = D2D1::Ellipse(D2D1::Point2F(recent.left + 28, ry + 18), 9, 9);
            a.gfx.brush->SetColor(level_bg(a, h.level));
            a.gfx.rt->FillEllipse(dot, a.gfx.brush);
            icon(a, level_glyph(h.level), R(recent.left + 19, ry + 9, recent.left + 37, ry + 27),
                 level_fg(a, h.level), a.gfx.fSmall);
            txt(a, base_name(h.path), R(recent.left + 48, ry + 4, recent.right - 100, ry + 24),
                a.gfx.fBody, a.theme.text);
            txt(a, h.time + L"  ·  " + h.caro, R(recent.left + 48, ry + 24, recent.right - 100, ry + 42),
                a.gfx.fSmall, a.theme.text3);
            D2D1_RECT_F br = R(recent.right - 92, ry + 7, recent.right - 16, ry + 29);
            chip(a, br, h.level == 0 ? L"错误" : level_name(h.level), level_fg(a, h.level),
                 level_bg(a, h.level));
            ry += 46;
        }
    }

    txt(a, L"保护状态", R(protect.left + 18, protect.top + 14, protect.right - 18, protect.top + 38),
        a.gfx.fH2, a.theme.text);
    struct Item { const wchar_t *glyph; const wchar_t *name; std::wstring value; int lv; };
    Item items[3] = {
        {L"\uEA18", L"实时保护", L"未启用", 2},
        {L"\uE7EF", L"执行驱动", a.driverState, a.driverState == L"运行中" ? 1 : 2},
        {L"\uE8F1", L"病毒库", std::to_wstring(a.dbCount) + L" 条", a.dbCount > 0 ? 1 : 2}
    };
    float py = protect.top + 52;
    for (int i = 0; i < 3; i++) {
        if (py + 30 > protect.bottom - 8) break;
        D2D1_RECT_F ir = R(protect.left + 18, py, protect.left + 48, py + 30);
        fr(a, ir, 7.0f, level_bg(a, items[i].lv));
        icon(a, items[i].glyph, ir, level_fg(a, items[i].lv));
        txt(a, items[i].name, R(protect.left + 58, py + 1, protect.right - 90, py + 21),
            a.gfx.fBody, a.theme.text);
        txt(a, items[i].value, R(protect.right - 100, py + 3, protect.right - 18, py + 23),
            a.gfx.fSmall, level_fg(a, items[i].lv), DWRITE_TEXT_ALIGNMENT_TRAILING);
        py += 42;
    }
    D2D1_RECT_F pb = R(protect.left + 18, protect.bottom - 42, protect.right - 18, protect.bottom - 12);
    if (pb.top > py - 2) {
        button(a, ID_HOME_PROTECT, pb, L"打开防护设置", false, false, true, L"\uE713");
    }
}

/* ---------------- 扫描页 ---------------- */
static void draw_scan(App &a, const Layout &l) {
    draw_header(a, l, L"扫描", L"文件与文件夹的静态扫描；不执行样本");

    D2D1_RECT_F pathCard = R(l.cx, 96, l.cx + l.cw, 184);
    card(a, pathCard);
    txt(a, L"扫描范围", R(pathCard.left + 18, pathCard.top + 14, pathCard.left + 120, pathCard.top + 34),
        a.gfx.fSmall, a.theme.text2);
    std::wstring path = a.scanPath.empty() ? L"拖入文件/文件夹，或点击右侧选择" : a.scanPath;
    txt(a, path, R(pathCard.left + 18, pathCard.top + 38, pathCard.right - 330, pathCard.top + 62),
        a.gfx.fBody, a.scanPath.empty() ? a.theme.text3 : a.theme.text);

    D2D1_RECT_F bf = R(pathCard.right - 306, pathCard.top + 14, pathCard.right - 210, pathCard.top + 48);
    D2D1_RECT_F bd = R(pathCard.right - 200, pathCard.top + 14, pathCard.right - 100, pathCard.top + 48);
    D2D1_RECT_F bq = R(pathCard.right - 90, pathCard.top + 14, pathCard.right - 14, pathCard.top + 48);
    button(a, ID_SCAN_FILE, bf, L"选择文件", false, false, true);
    button(a, ID_SCAN_DIR, bd, L"选择文件夹", false, false, true);
    button(a, ID_SCAN_QUICK, bq, L"快速扫描", false, false, true);

    txt(a, a.scanPathIsDir ? L"将递归扫描该文件夹（跳过系统缓存与重解析点）"
                           : L"单文件扫描；可随时拖入新的文件",
        R(pathCard.left + 18, pathCard.top + 64, pathCard.right - 18, pathCard.top + 84),
        a.gfx.fSmall, a.theme.text3);

    float ay = pathCard.bottom + 16;
    D2D1_RECT_F start = R(l.cx, ay, l.cx + 132, ay + 40);
    if (a.scanning.load())
        button(a, ID_SCAN_START, start, L"停止扫描", false, true, true, L"\uE71A");
    else
        button(a, ID_SCAN_START, start, L"开始扫描", true, false, true, L"\uE721");

    std::wstring status;
    if (a.scanning.load()) {
        status = L"已扫描 " + std::to_wstring(a.stats.files) + L" 个文件  ·  跳过 " +
                 std::to_wstring(a.stats.skipped);
    } else if (a.scanFinished && a.scanCanceled) {
        status = L"扫描已停止：已扫描 " + std::to_wstring(a.stats.files) + L" 个文件";
    } else if (a.scanFinished) {
        status = L"扫描完成：" + std::to_wstring(a.stats.files) + L" 个文件";
    } else {
        status = L"就绪；也可以把文件直接拖进窗口";
    }
    txt(a, status, R(start.right + 18, ay + 4, l.cx + l.cw - 120, ay + 36),
        a.gfx.fBody, a.theme.text2, DWRITE_TEXT_ALIGNMENT_LEADING,
        DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    D2D1_RECT_F clear = R(l.cx + l.cw - 100, ay + 2, l.cx + l.cw, ay + 38);
    button(a, ID_SCAN_CLEAR, clear, L"清空", false, false, a.scanFinished || !a.results.empty());

    float py = ay + 56;
    D2D1_RECT_F prog = R(l.cx, py, l.cx + l.cw, py + 82);
    card(a, prog);
    std::wstring cur;
    {
        std::lock_guard<std::mutex> lk(a.resultMutex);
        cur = a.currentFile;
    }
    if (cur.empty()) cur = L"等待开始扫描";
    txt(a, a.scanning.load() ? L"正在扫描"
                             : (a.scanFinished
                                    ? (a.scanCanceled ? L"扫描已停止" : L"扫描完成")
                                    : L"就绪"),
        R(prog.left + 18, prog.top + 12, prog.left + 120, prog.top + 34),
        a.gfx.fH3, a.theme.text);
    txt(a, cur, R(prog.left + 110, prog.top + 13, prog.right - 18, prog.top + 34),
        a.gfx.fSmall, a.theme.text3, DWRITE_TEXT_ALIGNMENT_TRAILING);

    D2D1_RECT_F track = R(prog.left + 18, prog.bottom - 24, prog.right - 18, prog.bottom - 16);
    fr(a, track, 4.0f, a.theme.track);
    if (a.scanFinished) {
        fr(a, track, 4.0f, a.theme.accent);
    } else if (a.scanning.load()) {
        float phase = a.settings.animations
                          ? (float)((GetTickCount64() - a.scanStart) % 1400) / 1400.0f
                          : 0.45f;
        float w = (track.right - track.left) * 0.30f;
        float x = track.left + phase * ((track.right - track.left) + w) - w;
        float x1 = std::max(track.left, x);
        float x2 = std::min(track.right, x + w);
        if (x2 > x1) fr(a, R(x1, track.top, x2, track.bottom), 4.0f, a.theme.accent);
    }
    std::wstring pc = a.scanning.load()
                          ? L"正在分析文件内容…"
                          : (a.scanFinished
                                 ? (a.scanCanceled ? L"扫描已停止；已完成的条目仍可隔离或打开位置"
                                                   : L"结果已写入下方列表，可隔离或打开位置")
                                 : L"选择范围后开始扫描");
    txt(a, pc, R(prog.left + 18, prog.bottom - 50, prog.right - 18, prog.bottom - 30),
        a.gfx.fSmall, a.theme.text3);

    float ry = prog.bottom + 14;
    D2D1_RECT_F res = R(l.cx, ry, l.cx + l.cw, l.H - 26);
    card(a, res);
    txt(a, L"扫描结果", R(res.left + 18, res.top + 13, res.left + 120, res.top + 37),
        a.gfx.fH2, a.theme.text);

    float chipX = res.left + 126;
    struct ChipDef { std::wstring text; int lv; };
    ChipDef chips[5] = {
        {L"高危 " + std::to_wstring(a.stats.high), 3},
        {L"疑似 " + std::to_wstring(a.stats.suspicious), 2},
        {L"正常 " + std::to_wstring(a.stats.normal), 1},
        {L"加壳 " + std::to_wstring(a.stats.packed), 4},
        {L"跳过 " + std::to_wstring(a.stats.skipped), 5}
    };
    for (int i = 0; i < 5; i++) {
        D2D1_RECT_F cr = R(chipX, res.top + 14, chipX + 68, res.top + 36);
        chip(a, cr, chips[i].text, level_fg(a, chips[i].lv), level_bg(a, chips[i].lv));
        chipX += 74;
    }

    bool canQuar = a.selectedResult >= 0 && a.selectedResult < (int)a.results.size() &&
                   a.results[(size_t)a.selectedResult].level >= 2 &&
                   !a.results[(size_t)a.selectedResult].quarantined;
    D2D1_RECT_F qb = R(res.right - 302, res.top + 12, res.right - 200, res.top + 38);
    D2D1_RECT_F ob = R(res.right - 194, res.top + 12, res.right - 96, res.top + 38);
    D2D1_RECT_F cb = R(res.right - 90, res.top + 12, res.right - 16, res.top + 38);
    button(a, ID_SCAN_QUARANTINE, qb, L"隔离选中", false, true, canQuar);
    button(a, ID_SCAN_OPEN, ob, L"打开位置", false, false, a.selectedResult >= 0 &&
                                                          a.selectedResult < (int)a.results.size());
    button(a, ID_SCAN_CLEAR, cb, L"清空", false, false, !a.results.empty());
    line(a, res.left + 18, res.top + 46, res.right - 18, res.top + 46, a.theme.border, 1.0f);

    float listTop = res.top + 56;
    float listBottom = res.bottom - 10;
    float viewH = std::max(20.0f, listBottom - listTop);
    const float rowH = 56.0f;
    float contentH = (float)a.results.size() * rowH;
    float maxScroll = std::max(0.0f, contentH - viewH);
    a.scrollScan = std::max(0.0f, std::min(a.scrollScan, maxScroll));

    if (a.results.empty()) {
        icon(a, a.scanning.load() ? L"\uE895" : L"\uE721",
             R(res.left + l.cw * 0.5f - 28, listTop + 34, res.left + l.cw * 0.5f + 28, listTop + 90),
             a.theme.text3, a.gfx.fIconBig);
        txt(a, a.scanning.load() ? L"正在扫描…" : L"暂无扫描结果",
            R(res.left + 20, listTop + 96, res.right - 20, listTop + 122),
            a.gfx.fH3, a.theme.text2, DWRITE_TEXT_ALIGNMENT_CENTER);
        txt(a, a.scanning.load() ? L"结果会实时出现在这里" : L"选择一个文件或文件夹开始扫描",
            R(res.left + 20, listTop + 122, res.right - 20, listTop + 144),
            a.gfx.fSmall, a.theme.text3, DWRITE_TEXT_ALIGNMENT_CENTER);
    } else {
        a.gfx.rt->PushAxisAlignedClip(R(res.left, listTop, res.right, listBottom),
                                      D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        for (int i = 0; i < (int)a.results.size(); i++) {
            float y = listTop + i * rowH - a.scrollScan;
            if (y + rowH < listTop || y > listBottom) continue;
            const ScanEntry &e = a.results[(size_t)i];
            int rid = ID_ROW_RESULT + i;
            D2D1_RECT_F rr = R(res.left + 10, y + 2, res.right - 12, y + rowH - 4);
            bool sel = i == a.selectedResult;
            bool hov = a.hoverId == rid;
            if (sel) fr(a, rr, 8.0f, a.theme.accentSoft);
            else if (hov) fr(a, rr, 8.0f, a.theme.hover);
            a.hits.push_back({rid, rr});

            D2D1_RECT_F icr = R(rr.left + 10, y + 10, rr.left + 44, y + 44);
            fr(a, icr, 9.0f, level_bg(a, e.level));
            icon(a, level_glyph(e.level), icr, level_fg(a, e.level));

            std::wstring nm = base_name(e.path);
            txt(a, nm.empty() ? e.path : nm,
                R(rr.left + 54, y + 7, rr.right - 280, y + 29), a.gfx.fBody, a.theme.text);
            std::wstring sub = e.path;
            if (e.r.caro[0]) sub = from_u8(e.r.caro) + L"  ·  " + sub;
            txt(a, sub, R(rr.left + 54, y + 29, rr.right - 280, y + 48),
                a.gfx.fSmall, a.theme.text3);

            if (e.quarantined) {
                D2D1_RECT_F qr = R(rr.right - 268, y + 14, rr.right - 178, y + 38);
                chip(a, qr, L"已隔离", a.theme.success, a.theme.successSoft);
            }
            D2D1_RECT_F br = R(rr.right - 170, y + 14, rr.right - 68, y + 38);
            chip(a, br, level_name(e.level), level_fg(a, e.level), level_bg(a, e.level));
            txt(a, score_text(e.r.score), R(rr.right - 64, y + 10, rr.right - 12, y + 40),
                a.gfx.fBody, a.theme.text2, DWRITE_TEXT_ALIGNMENT_TRAILING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }
        a.gfx.rt->PopAxisAlignedClip();
        scrollbar(a, R(res.right - 18, listTop, res.right - 8, listBottom),
                  a.scrollScan, contentH, viewH);
    }
}

/* ---------------- 防护页 ---------------- */
static void draw_protection(App &a, const Layout &l) {
    draw_header(a, l, L"防护", L"当前为手动扫描模式；常驻防护需要服务与驱动");

    D2D1_RECT_F banner = R(l.cx, 96, l.cx + l.cw, 172);
    card(a, banner);
    D2D1_RECT_F bi = R(banner.left + 18, banner.top + 18, banner.left + 54, banner.top + 54);
    fr(a, bi, 9.0f, a.theme.warningSoft);
    icon(a, L"\uE7BA", bi, a.theme.warning);
    txt(a, L"当前没有常驻防护", R(banner.left + 68, banner.top + 16, banner.right - 220, banner.top + 40),
        a.gfx.fH2, a.theme.text);
    txt(a, L"扫描判定全部在用户态完成；实时监控、强杀、强删与自保护需要后台服务和驱动。",
        R(banner.left + 68, banner.top + 42, banner.right - 220, banner.top + 66),
        a.gfx.fSmall, a.theme.text2);
    D2D1_RECT_F bb = R(banner.right - 190, banner.top + 24, banner.right - 18, banner.top + 60);
    button(a, ID_PROT_DRIVER, bb, L"查看驱动状态", false, false, true, L"\uE7EF");

    float gap = 16;
    float cw = (l.cw - gap) * 0.5f;
    float ch = 150;
    struct CardDef {
        const wchar_t *glyph;
        const wchar_t *title;
        const wchar_t *status;
        const wchar_t *desc;
        int lv;
        bool toggle;
        bool enabled;
    };
    CardDef defs[4] = {
        {L"\uEA18", L"实时文件保护", L"未启用",
         L"需要后台服务常驻监控新文件；当前版本只在手动扫描时分析。", 2, true, false},
        {L"\uE9D2", L"行为监控", L"已封存",
         L"pe_vm 虚拟执行不并入 DLL，默认关闭，避免把“无法定论”当成恶意。", 5, true, false},
        {L"\uE7EF", L"驱动自保护", a.driverState.c_str(), L"执行端只负责强杀、强删与自保护；判定仍在用户态。",
         a.driverState == L"运行中" ? 1 : 2, false, false},
        {L"\uE823", L"计划扫描", L"未启用",
         L"计划任务、空闲扫描与通知将在服务化阶段加入。", 5, true, false}
    };

    for (int i = 0; i < 4; i++) {
        int col = i % 2, row = i / 2;
        D2D1_RECT_F c = R(l.cx + col * (cw + gap), 190 + row * (ch + gap),
                          l.cx + col * (cw + gap) + cw, 190 + row * (ch + gap) + ch);
        card(a, c);
        D2D1_RECT_F ic = R(c.left + 18, c.top + 18, c.left + 50, c.top + 50);
        fr(a, ic, 8.0f, level_bg(a, defs[i].lv));
        icon(a, defs[i].glyph, ic, level_fg(a, defs[i].lv));
        txt(a, defs[i].title, R(c.left + 62, c.top + 16, c.right - 120, c.top + 38),
            a.gfx.fH3, a.theme.text);
        D2D1_RECT_F st = R(c.left + 62, c.top + 40, c.left + 146, c.top + 62);
        chip(a, st, defs[i].status, level_fg(a, defs[i].lv), level_bg(a, defs[i].lv));
        txt(a, defs[i].desc, R(c.left + 18, c.top + 72, c.right - 18, c.top + 112),
            a.gfx.fSmall, a.theme.text2);
        if (defs[i].toggle) {
            D2D1_RECT_F tr = R(c.right - 58, c.top + 20, c.right - 18, c.top + 40);
            toggle(a, tr, false, false);
        }
        if (i == 2) {
            D2D1_RECT_F b = R(c.left + 18, c.bottom - 42, c.left + 150, c.bottom - 12);
            button(a, ID_PROT_DRIVER, b, L"驱动与内核", false, false, true, L"\uE7EF");
        }
    }

    float iy = 190 + 2 * ch + gap + 16;
    if (iy + 48 <= l.H - 26) {
        D2D1_RECT_F info = R(l.cx, iy, l.cx + l.cw, l.H - 26);
        card(a, info);
        txt(a, L"边界说明", R(info.left + 18, info.top + 10, info.right - 18, info.top + 32),
            a.gfx.fBody, a.theme.text);
        const wchar_t *lines[] = {
            L"静态扫描不执行样本；实时保护/驱动未启用时，不拦截、不修改文件。",
            L"隔离区是用户主动操作：文件移动到 quarantine 目录，可恢复或永久删除。",
            L"驱动只做执行端；PPL 进程、被映射/占用文件、内核级攻击存在能力边界。",
            L"加壳文件给出 [PACKED]，不直接判恶意；静态扫描不等于沙箱行为分析。"
        };
        float yy2 = info.top + 32;
        for (const wchar_t *s : lines) {
            if (yy2 + 20 > info.bottom - 2) break;
            txt(a, s, R(info.left + 18, yy2, info.right - 18, yy2 + 20),
                a.gfx.fSmall, a.theme.text2);
            yy2 += 22;
        }
    }
}

/* ---------------- 隔离区 ---------------- */
static void draw_quarantine(App &a, const Layout &l) {
    draw_header(a, l, L"隔离区", L"已隔离文件可以恢复或永久删除");

    D2D1_RECT_F rf = R(l.cx, 96, l.cx + 84, 130);
    D2D1_RECT_F rs = R(l.cx + 92, 96, l.cx + 204, 130);
    D2D1_RECT_F rd = R(l.cx + 212, 96, l.cx + 324, 130);
    button(a, ID_QUAR_REFRESH, rf, L"刷新", false, false, true, L"\uE72C");
    bool sel = a.selectedQuar >= 0 && a.selectedQuar < (int)a.quarantine.size();
    button(a, ID_QUAR_RESTORE, rs, L"恢复选中", false, false, sel);
    button(a, ID_QUAR_DELETE, rd, L"删除选中", false, true, sel);

    txt(a, L"共 " + std::to_wstring(a.quarantine.size()) + L" 项",
        R(l.cx + l.cw - 160, 100, l.cx + l.cw, 128), a.gfx.fBody, a.theme.text2,
        DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    D2D1_RECT_F table = R(l.cx, 146, l.cx + l.cw, l.H - 26);
    card(a, table);
    float colTime = table.left + 18;
    float colPath = table.left + 190;
    float colVerdict = table.right - 350;
    float colCaro = table.right - 180;
    txt(a, L"隔离时间", R(colTime, table.top + 14, colPath - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"原路径", R(colPath, table.top + 14, colVerdict - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"结论", R(colVerdict, table.top + 14, colCaro - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"检测名", R(colCaro, table.top + 14, table.right - 18, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    line(a, table.left + 18, table.top + 42, table.right - 18, table.top + 42, a.theme.border, 1.0f);

    float listTop = table.top + 50;
    float listBottom = table.bottom - 10;
    float viewH = std::max(20.0f, listBottom - listTop);
    const float rowH = 54.0f;
    float contentH = (float)a.quarantine.size() * rowH;
    float maxScroll = std::max(0.0f, contentH - viewH);
    a.scrollQuar = std::max(0.0f, std::min(a.scrollQuar, maxScroll));

    if (a.quarantine.empty()) {
        icon(a, L"\uE74D", R(table.left + l.cw * 0.5f - 28, listTop + 36,
                            table.left + l.cw * 0.5f + 28, listTop + 92),
             a.theme.text3, a.gfx.fIconBig);
        txt(a, L"隔离区为空", R(table.left + 20, listTop + 98, table.right - 20, listTop + 124),
            a.gfx.fH3, a.theme.text2, DWRITE_TEXT_ALIGNMENT_CENTER);
        txt(a, L"在扫描结果中选中疑似/高危文件，点击“隔离选中”。",
            R(table.left + 20, listTop + 124, table.right - 20, listTop + 146),
            a.gfx.fSmall, a.theme.text3, DWRITE_TEXT_ALIGNMENT_CENTER);
    } else {
        a.gfx.rt->PushAxisAlignedClip(R(table.left, listTop, table.right, listBottom),
                                      D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        for (int i = 0; i < (int)a.quarantine.size(); i++) {
            float y = listTop + i * rowH - a.scrollQuar;
            if (y + rowH < listTop || y > listBottom) continue;
            const QuarantineEntry &q = a.quarantine[(size_t)i];
            int id = ID_ROW_QUAR + i;
            D2D1_RECT_F rr = R(table.left + 10, y + 2, table.right - 12, y + rowH - 4);
            if (i == a.selectedQuar) fr(a, rr, 8.0f, a.theme.accentSoft);
            else if (a.hoverId == id) fr(a, rr, 8.0f, a.theme.hover);
            a.hits.push_back({id, rr});
            txt(a, q.time, R(colTime, y + 8, colPath - 10, y + 28), a.gfx.fSmall, a.theme.text3);
            txt(a, base_name(q.original), R(colPath, y + 5, colVerdict - 10, y + 25),
                a.gfx.fBody, a.theme.text);
            txt(a, q.original, R(colPath, y + 25, colVerdict - 10, y + 45),
                a.gfx.fSmall, a.theme.text3);
            D2D1_RECT_F br = R(colVerdict, y + 13, colVerdict + 160, y + 37);
            chip(a, br, q.bracket.empty() ? L"隔离" : q.bracket,
                 a.theme.danger, a.theme.dangerSoft);
            txt(a, q.caro.empty() ? L"—" : q.caro,
                R(colCaro, y + 10, table.right - 18, y + 40), a.gfx.fSmall, a.theme.text2,
                DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }
        a.gfx.rt->PopAxisAlignedClip();
        scrollbar(a, R(table.right - 18, listTop, table.right - 8, listBottom),
                  a.scrollQuar, contentH, viewH);
    }
}

/* ---------------- 日志 ---------------- */
static void draw_logs(App &a, const Layout &l) {
    draw_header(a, l, L"日志", L"扫描发现与摘要，保存在 logs\\history.tsv");

    D2D1_RECT_F rf = R(l.cx, 96, l.cx + 84, 130);
    D2D1_RECT_F rc = R(l.cx + 92, 96, l.cx + 204, 130);
    D2D1_RECT_F ro = R(l.cx + 212, 96, l.cx + 344, 130);
    button(a, ID_LOG_REFRESH, rf, L"刷新", false, false, true, L"\uE72C");
    button(a, ID_LOG_CLEAR, rc, L"清空日志", false, true, !a.history.empty());
    button(a, ID_LOG_OPEN, ro, L"打开日志目录", false, false, true, L"\uE838");
    txt(a, L"共 " + std::to_wstring(a.history.size()) + L" 条",
        R(l.cx + l.cw - 160, 100, l.cx + l.cw, 128), a.gfx.fBody, a.theme.text2,
        DWRITE_TEXT_ALIGNMENT_TRAILING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    D2D1_RECT_F table = R(l.cx, 146, l.cx + l.cw, l.H - 26);
    card(a, table);
    float colTime = table.left + 18;
    float colPath = table.left + 190;
    float colVerdict = table.right - 340;
    float colScore = table.right - 90;
    txt(a, L"时间", R(colTime, table.top + 14, colPath - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"路径 / 范围", R(colPath, table.top + 14, colVerdict - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"结论", R(colVerdict, table.top + 14, colScore - 10, table.top + 34),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"评分", R(colScore, table.top + 14, table.right - 18, table.top + 34),
        a.gfx.fSmall, a.theme.text3, DWRITE_TEXT_ALIGNMENT_TRAILING);
    line(a, table.left + 18, table.top + 42, table.right - 18, table.top + 42, a.theme.border, 1.0f);

    float listTop = table.top + 50;
    float listBottom = table.bottom - 10;
    float viewH = std::max(20.0f, listBottom - listTop);
    const float rowH = 56.0f;
    float contentH = (float)a.history.size() * rowH;
    float maxScroll = std::max(0.0f, contentH - viewH);
    a.scrollLog = std::max(0.0f, std::min(a.scrollLog, maxScroll));

    if (a.history.empty()) {
        icon(a, L"\uE9D9", R(table.left + l.cw * 0.5f - 28, listTop + 36,
                            table.left + l.cw * 0.5f + 28, listTop + 92),
             a.theme.text3, a.gfx.fIconBig);
        txt(a, L"暂无日志", R(table.left + 20, listTop + 98, table.right - 20, listTop + 124),
            a.gfx.fH3, a.theme.text2, DWRITE_TEXT_ALIGNMENT_CENTER);
        txt(a, L"完成一次扫描后，这里会出现摘要与威胁记录。",
            R(table.left + 20, listTop + 124, table.right - 20, listTop + 146),
            a.gfx.fSmall, a.theme.text3, DWRITE_TEXT_ALIGNMENT_CENTER);
    } else {
        a.gfx.rt->PushAxisAlignedClip(R(table.left, listTop, table.right, listBottom),
                                      D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        for (int i = 0; i < (int)a.history.size(); i++) {
            float y = listTop + i * rowH - a.scrollLog;
            if (y + rowH < listTop || y > listBottom) continue;
            const HistoryEntry &h = a.history[(size_t)i];
            int id = ID_ROW_LOG + i;
            D2D1_RECT_F rr = R(table.left + 10, y + 2, table.right - 12, y + rowH - 4);
            if (i == a.selectedLog) fr(a, rr, 8.0f, a.theme.accentSoft);
            else if (a.hoverId == id) fr(a, rr, 8.0f, a.theme.hover);
            a.hits.push_back({id, rr});
            txt(a, h.time, R(colTime, y + 8, colPath - 10, y + 28), a.gfx.fSmall, a.theme.text3);
            txt(a, base_name(h.path), R(colPath, y + 5, colVerdict - 10, y + 25),
                a.gfx.fBody, a.theme.text);
            txt(a, h.detail.empty() ? h.path : h.detail,
                R(colPath, y + 25, colVerdict - 10, y + 47), a.gfx.fSmall, a.theme.text3);
            D2D1_RECT_F br = R(colVerdict, y + 15, colVerdict + 160, y + 39);
            chip(a, br, h.bracket.empty() ? L"—" : h.bracket,
                 level_fg(a, h.level), level_bg(a, h.level));
            std::wstring sc = score_text(h.score);
            txt(a, sc, R(colScore, y + 12, table.right - 18, y + 42),
                a.gfx.fBody, a.theme.text2, DWRITE_TEXT_ALIGNMENT_TRAILING,
                DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }
        a.gfx.rt->PopAxisAlignedClip();
        scrollbar(a, R(table.right - 18, listTop, table.right - 8, listBottom),
                  a.scrollLog, contentH, viewH);
    }
}

/* ---------------- 驱动与内核 ---------------- */
static void draw_driver(App &a, const Layout &l) {
    draw_header(a, l, L"驱动与内核", L"执行端状态、能力边界与安装前提");

    D2D1_RECT_F main = R(l.cx, 96, l.cx + l.cw, 278);
    card(a, main);
    bool running = a.driverState == L"运行中";
    D2D1_RECT_F ic = R(main.left + 24, main.top + 28, main.left + 88, main.top + 92);
    fr(a, ic, 14.0f, running ? a.theme.successSoft : a.theme.warningSoft);
    icon(a, L"\uE7EF", ic, running ? a.theme.success : a.theme.warning, a.gfx.fIconBig);
    txt(a, L"MalwareScannerDrv", R(main.left + 108, main.top + 24, main.right - 220, main.top + 54),
        a.gfx.fH1, a.theme.text);
    D2D1_RECT_F st = R(main.left + 108, main.top + 60, main.left + 208, main.top + 84);
    chip(a, st, a.driverState, running ? a.theme.success : a.theme.warning,
         running ? a.theme.successSoft : a.theme.warningSoft, a.gfx.fButton);
    txt(a, a.driverDetail, R(main.left + 108, main.top + 94, main.right - 220, main.top + 116),
        a.gfx.fSmall, a.theme.text2);

    D2D1_RECT_F rb = R(main.right - 200, main.top + 22, main.right - 18, main.top + 58);
    D2D1_RECT_F ob = R(main.right - 200, main.top + 66, main.right - 18, main.top + 102);
    button(a, ID_DRV_REFRESH, rb, L"刷新状态", false, false, true, L"\uE72C");
    button(a, ID_DRV_OPEN_DATA, ob, L"打开数据目录", false, false, true, L"\uE838");

    txt(a, L"驱动只做执行端：强制结束进程、强制删除文件、保护自身进程与文件。",
        R(main.left + 24, main.top + 130, main.right - 24, main.top + 154),
        a.gfx.fBody, a.theme.text2);
    txt(a, L"扫描判定始终在用户态；驱动不暴露任意内核读写，也不参与“是不是恶意”的判断。",
        R(main.left + 24, main.top + 158, main.right - 24, main.top + 182),
        a.gfx.fSmall, a.theme.text3);

    float gap = 16;
    float cw = (l.cw - gap * 2) / 3;
    const wchar_t *titles[3] = {L"强杀进程", L"强删文件", L"自我保护"};
    const wchar_t *desc[3] = {
        L"对普通进程可强制结束；PPL 进程受系统保护。",
        L"被映射/占用的文件可能只能重启后删除。",
        L"保护服务与驱动自身；挡不住内核级攻击。"
    };
    const wchar_t *glyphs[3] = {L"\uE71A", L"\uE74D", L"\uEA18"};
    for (int i = 0; i < 3; i++) {
        D2D1_RECT_F c = R(l.cx + i * (cw + gap), 296, l.cx + i * (cw + gap) + cw, 296 + 132);
        card(a, c);
        D2D1_RECT_F gi = R(c.left + 18, c.top + 18, c.left + 50, c.top + 50);
        fr(a, gi, 8.0f, a.theme.accentSoft);
        icon(a, glyphs[i], gi, a.theme.accent);
        txt(a, titles[i], R(c.left + 62, c.top + 17, c.right - 18, c.top + 39),
            a.gfx.fH3, a.theme.text);
        D2D1_RECT_F st2 = R(c.right - 86, c.top + 18, c.right - 18, c.top + 40);
        chip(a, st2, L"未提供", a.theme.text3, a.theme.hover);
        txt(a, desc[i], R(c.left + 18, c.top + 62, c.right - 18, c.top + 112),
            a.gfx.fSmall, a.theme.text2);
    }

    D2D1_RECT_F boundary = R(l.cx, 446, l.cx + l.cw, l.H - 26);
    card(a, boundary);
    txt(a, L"为什么现在不装驱动", R(boundary.left + 18, boundary.top + 14,
                                     boundary.right - 18, boundary.top + 38),
        a.gfx.fH2, a.theme.text);
    const wchar_t *lines[] = {
        L"• 驱动需要 WHQL/attestation 签名和 minifilter altitude，当前交付不含未签名驱动。",
        L"• 没有签名就加载内核驱动会触发系统策略，也可能破坏机器；不拿用户机做实验。",
        L"• 服务化后会先提供维护模式与卸载路径，再接入强杀/强删/自保护。",
        L"• 现阶段 GUI 的扫描、隔离、日志全部由用户态 scanner.dll 完成。"
    };
    float yy = boundary.top + 52;
    for (const wchar_t *s : lines) {
        if (yy + 24 > boundary.bottom - 10) break;
        txt(a, s, R(boundary.left + 18, yy, boundary.right - 18, yy + 24),
            a.gfx.fBody, a.theme.text2);
        yy += 30;
    }
}

/* ---------------- 设置 ---------------- */
static void draw_settings(App &a, const Layout &l) {
    draw_header(a, l, L"设置", L"外观、扫描限制、病毒库与数据位置");

    float gap = 16;
    float leftW = (l.cw - gap) * 0.55f;
    float rightW = l.cw - gap - leftW;
    float cardH = 150;

    /* 外观 */
    D2D1_RECT_F look = R(l.cx, 96, l.cx + leftW, 96 + cardH);
    card(a, look);
    txt(a, L"外观", R(look.left + 18, look.top + 14, look.right - 18, look.top + 38),
        a.gfx.fH2, a.theme.text);
    txt(a, L"主题跟随系统，或强制浅色/深色。", R(look.left + 18, look.top + 40, look.right - 18, look.top + 60),
        a.gfx.fSmall, a.theme.text3);
    D2D1_RECT_F seg = R(look.left + 18, look.top + 70, look.right - 18, look.top + 108);
    fr(a, seg, 9.0f, a.theme.input);
    sr(a, seg, 9.0f, a.theme.border, 1.0f);
    const wchar_t *tn[3] = {L"跟随系统", L"浅色", L"深色"};
    float segW = (seg.right - seg.left - 8) / 3.0f;
    for (int i = 0; i < 3; i++) {
        D2D1_RECT_F sb = R(seg.left + 4 + i * segW, seg.top + 4,
                           seg.left + 4 + (i + 1) * segW - 2, seg.bottom - 4);
        bool act = a.settings.theme == i;
        if (act) fr(a, sb, 7.0f, a.theme.accent);
        txt(a, tn[i], sb, a.gfx.fButton, act ? a.theme.white : a.theme.text2,
            DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        a.hits.push_back({ID_SET_THEME_SYS + i, sb});
    }
    txt(a, L"平滑过渡动画", R(look.left + 18, look.top + 120, look.right - 100, look.top + 146),
        a.gfx.fBody, a.theme.text2, DWRITE_TEXT_ALIGNMENT_LEADING,
        DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    D2D1_RECT_F at = R(look.right - 70, look.top + 122, look.right - 30, look.top + 142);
    toggle(a, at, a.settings.animations != 0, true);
    a.hits.push_back({ID_SET_ANIM, R(at.left - 8, at.top - 8, at.right + 8, at.bottom + 8)});

    /* 扫描限制 */
    D2D1_RECT_F scan = R(l.cx, 260, l.cx + leftW, 260 + cardH);
    card(a, scan);
    txt(a, L"扫描", R(scan.left + 18, scan.top + 14, scan.right - 18, scan.top + 38),
        a.gfx.fH2, a.theme.text);
    txt(a, L"超过大小限制的文件会跳过，不进入引擎。", R(scan.left + 18, scan.top + 40, scan.right - 18, scan.top + 60),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"最大扫描文件", R(scan.left + 18, scan.top + 74, scan.right - 190, scan.top + 102),
        a.gfx.fBody, a.theme.text2, DWRITE_TEXT_ALIGNMENT_LEADING,
        DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    D2D1_RECT_F minus = R(scan.right - 178, scan.top + 74, scan.right - 146, scan.top + 104);
    D2D1_RECT_F value = R(scan.right - 140, scan.top + 72, scan.right - 66, scan.top + 106);
    D2D1_RECT_F plus = R(scan.right - 60, scan.top + 74, scan.right - 28, scan.top + 104);
    auto smallbtn = [&](int id, const D2D1_RECT_F &r, const wchar_t *g) {
        bool hov = a.hoverId == id;
        fr(a, r, 7.0f, hov ? a.theme.cardHover : a.theme.card2);
        sr(a, r, 7.0f, a.theme.border, 1.0f);
        icon(a, g, r, a.theme.text2);
        a.hits.push_back({id, r});
    };
    smallbtn(ID_SET_MAX_MINUS, minus, L"\uE738");
    smallbtn(ID_SET_MAX_PLUS, plus, L"\uE710");
    fr(a, value, 7.0f, a.theme.card2);
    sr(a, value, 7.0f, a.theme.border, 1.0f);
    txt(a, std::to_wstring(a.settings.maxMb) + L" MB", value, a.gfx.fButton, a.theme.text,
        DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

    txt(a, L"扫描在线程中串行调用 scanner.dll；可在“扫描”页随时停止。",
        R(scan.left + 18, scan.top + 118, scan.right - 18, scan.top + 146),
        a.gfx.fSmall, a.theme.text3);

    /* 病毒库 */
    D2D1_RECT_F db = R(l.cx + leftW + gap, 96, l.cx + l.cw, 96 + cardH);
    card(a, db);
    txt(a, L"病毒库", R(db.left + 18, db.top + 14, db.right - 18, db.top + 38),
        a.gfx.fH2, a.theme.text);
    txt(a, std::to_wstring(a.dbCount), R(db.left + 18, db.top + 40, db.left + 110, db.top + 76),
        a.gfx.fStat, a.theme.text);
    txt(a, L"条特征", R(db.left + 18, db.top + 78, db.left + 110, db.top + 98),
        a.gfx.fSmall, a.theme.text3);
    std::wstring dp = a.dbPath.empty() ? L"未找到 signatures.db（使用 DLL 内置兜底表）" : a.dbPath;
    txt(a, dp, R(db.left + 18, db.top + 96, db.right - 18, db.top + 112),
        a.gfx.fSmall, a.dbPath.empty() ? a.theme.warning : a.theme.text3);
    D2D1_RECT_F rl = R(db.left + 18, db.bottom - 34, db.left + 128, db.bottom - 6);
    D2D1_RECT_F od = R(db.left + 136, db.bottom - 34, db.left + 240, db.bottom - 6);
    button(a, ID_SET_RELOAD, rl, L"重新加载", false, false, true, L"\uE72C");
    button(a, ID_SET_OPEN, od, L"打开目录", false, false, true, L"\uE838");

    /* 关于 */
    D2D1_RECT_F about = R(l.cx + leftW + gap, 260, l.cx + l.cw, 260 + cardH);
    card(a, about);
    txt(a, L"关于", R(about.left + 18, about.top + 14, about.right - 18, about.top + 38),
        a.gfx.fH2, a.theme.text);
    txt(a, L"恶意软件扫描器 · 静态扫描 GUI", R(about.left + 18, about.top + 42, about.right - 18, about.top + 62),
        a.gfx.fBody, a.theme.text2);
    txt(a, L"引擎 " + a.engineVersion + L"  ·  ABI " + std::to_wstring(a.abiVersion),
        R(about.left + 18, about.top + 70, about.right - 18, about.top + 92),
        a.gfx.fSmall, a.theme.text3);
    txt(a, L"判定阈值：≥ 80 高危，≥ 50 疑似；样本绝不执行。",
        R(about.left + 18, about.top + 90, about.right - 18, about.top + 108),
        a.gfx.fSmall, a.theme.text3);
    D2D1_RECT_F ab = R(about.left + 18, about.bottom - 34, about.left + 148, about.bottom - 6);
    button(a, ID_SET_OPEN, ab, L"打开数据目录", false, false, true, L"\uE838");

    /* 数据与边界 */
    float ny = 260 + cardH + gap;
    D2D1_RECT_F note = R(l.cx, ny, l.cx + l.cw, l.H - 26);
    card(a, note);
    txt(a, L"数据与边界", R(note.left + 18, note.top + 14, note.right - 18, note.top + 38),
        a.gfx.fH2, a.theme.text);
    std::wstring data = scanner_data_dir();
    txt(a, L"数据目录  " + data, R(note.left + 18, note.top + 42, note.right - 18, note.top + 62),
        a.gfx.fSmall, a.theme.text2);
    txt(a, L"日志  logs\\history.tsv    ·    隔离区  quarantine\\index.tsv    ·    设置  config\\settings.ini",
        R(note.left + 18, note.top + 64, note.right - 18, note.top + 84),
        a.gfx.fSmall, a.theme.text3);
    if (note.bottom - note.top >= 240) {
        line(a, note.left + 18, note.top + 104, note.right - 18, note.top + 104, a.theme.border, 1.0f);
        const wchar_t *notes[] = {
            L"• 当前版本不安装驱动、不常驻监控、不修改系统策略；扫描与隔离均为用户主动操作。",
            L"• 外部 signatures.db 优先；缺失时使用 DLL 内置 53 条特征表兜底。",
            L"• 隔离是移动文件，不加密、不压缩；系统文件可能因权限或占用而失败。",
            L"• 静态扫描不执行样本；加壳判定使用熵与节区特征，不等同于恶意。"
        };
        float yy = note.top + 118;
        for (const wchar_t *s : notes) {
            txt(a, s, R(note.left + 18, yy, note.right - 18, yy + 24),
                a.gfx.fBody, a.theme.text2);
            yy += 30;
        }
    } else {
        txt(a, L"• 当前版本不安装驱动、不常驻监控；扫描与隔离为用户主动操作。",
            R(note.left + 18, note.top + 90, note.right - 18, note.top + 110),
            a.gfx.fSmall, a.theme.text2);
        txt(a, L"• 静态扫描不执行样本；隔离是移动文件，可恢复或永久删除。",
            R(note.left + 18, note.top + 110, note.right - 18, note.top + 130),
            a.gfx.fSmall, a.theme.text2);
    }
}

/* ---------------- 页面调度 / 提示 ---------------- */
static void draw_toast(App &a, const Layout &l) {
    ULONGLONG now = GetTickCount64();
    if (a.toast.empty() || now >= a.toastUntil) return;
    float remain = (float)(a.toastUntil - now);
    float alpha = (remain < 260.0f) ? remain / 260.0f : 1.0f;
    float w = std::min(520.0f, l.cw - 40.0f);
    D2D1_RECT_F r = R(l.cx + l.cw - w, l.H - 82, l.cx + l.cw - 8, l.H - 34);
    fr(a, r, 10.0f, C(0x1B1B1B, 0.92f * alpha));
    D2D1_RECT_F ic = R(r.left + 12, r.top + 9, r.left + 38, r.bottom - 9);
    icon(a, L"\uE946", ic, C(0xFFFFFF, alpha), a.gfx.fIcon);
    txt(a, a.toast, R(r.left + 44, r.top, r.right - 14, r.bottom), a.gfx.fBody,
        C(0xFFFFFF, alpha), DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
}

void ui_draw(App &a) {
    a.hits.clear();
    a.gfx.begin();
    if (!a.gfx.rt) { a.gfx.end(); return; }

    Layout l = layout_of(a);
    a.gfx.rt->Clear(a.theme.bg1);
    rect(a, R(0, 0, l.W, l.H), a.theme.bg1);
    D2D1_ELLIPSE e1 = D2D1::Ellipse(D2D1::Point2F(l.W - 40, 20), 360, 260);
    a.gfx.brush->SetColor(C(0x0078D4, a.theme.dark ? 0.035f : 0.045f));
    a.gfx.rt->FillEllipse(e1, a.gfx.brush);
    D2D1_ELLIPSE e2 = D2D1::Ellipse(D2D1::Point2F(l.sb + 120, l.H - 20), 300, 220);
    a.gfx.brush->SetColor(C(0x4CC2FF, a.theme.dark ? 0.025f : 0.035f));
    a.gfx.rt->FillEllipse(e2, a.gfx.brush);

    draw_sidebar(a, l);

    float t = 1.0f;
    if (a.animating && a.settings.animations) {
        t = (float)(GetTickCount64() - a.pageAnimStart) / 190.0f;
        if (t >= 1.0f) { t = 1.0f; a.animating = false; }
    } else {
        a.animating = false;
    }
    float ease = 1.0f - std::pow(1.0f - t, 3.0f);
    float off = (1.0f - ease) * 10.0f;
    a.gfx.rt->SetTransform(D2D1::Matrix3x2F::Translation(off, 0));

    switch (a.page) {
        case Page::Home: draw_home(a, l); break;
        case Page::Scan: draw_scan(a, l); break;
        case Page::Protection: draw_protection(a, l); break;
        case Page::Quarantine: draw_quarantine(a, l); break;
        case Page::Logs: draw_logs(a, l); break;
        case Page::Driver: draw_driver(a, l); break;
        case Page::Settings: draw_settings(a, l); break;
        default: draw_home(a, l); break;
    }
    a.gfx.rt->SetTransform(D2D1::Matrix3x2F::Identity());
    draw_toast(a, l);
    a.gfx.end();
}

/* ---------------- 交互 ---------------- */
static void open_path(const std::wstring &path, bool select) {
    if (path.empty()) return;
    if (select) {
        std::wstring args = L"/select,\"" + path + L"\"";
        ShellExecuteW(NULL, L"open", L"explorer.exe", args.c_str(), NULL, SW_SHOWNORMAL);
    } else {
        ShellExecuteW(NULL, L"open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }
}

static void open_selected_result(App &a) {
    if (a.selectedResult < 0 || a.selectedResult >= (int)a.results.size()) return;
    open_path(a.results[(size_t)a.selectedResult].path, true);
}

static void open_logs_dir() {
    std::wstring d = scanner_data_dir() + L"\\logs";
    CreateDirectoryW(d.c_str(), NULL);
    ShellExecuteW(NULL, L"open", d.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

static void cycle_max_mb(App &a, int dir) {
    static const int vals[] = {64, 128, 256, 512, 1024, 2048};
    int n = (int)(sizeof(vals) / sizeof(vals[0]));
    int idx = 0;
    int best = 0x7fffffff;
    for (int i = 0; i < n; i++) {
        int d = vals[i] - a.settings.maxMb;
        if (d < 0) d = -d;
        if (d < best) { best = d; idx = i; }
    }
    idx += dir;
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    a.settings.maxMb = vals[idx];
    scanner_save_settings();
    a.show_toast(L"最大扫描文件：" + std::to_wstring(a.settings.maxMb) + L" MB");
}

void ui_on_click(App &a, int id, float, float) {
    if (id >= ID_NAV_HOME && id <= ID_NAV_SETTINGS) {
        a.page = (Page)(id - ID_NAV_HOME);
        if (a.page == Page::Quarantine && a.selectedQuar < 0 && !a.quarantine.empty())
            a.selectedQuar = 0;
        a.start_page_anim();
        a.hoverId = 0;
        InvalidateRect(a.hwnd, NULL, FALSE);
        return;
    }

    switch (id) {
        case ID_HEADER_STATUS:
            a.page = Page::Protection;
            a.start_page_anim();
            break;
        case ID_HOME_QUICK:
            a.page = Page::Scan;
            a.start_page_anim();
            scan_quick();
            break;
        case ID_HOME_CUSTOM:
            a.page = Page::Scan;
            a.start_page_anim();
            pick_and_scan_folder();
            break;
        case ID_HOME_VIEW_LOGS:
            a.page = Page::Logs;
            a.start_page_anim();
            break;
        case ID_HOME_PROTECT:
            a.page = Page::Protection;
            a.start_page_anim();
            break;

        case ID_SCAN_FILE:
            pick_and_scan_file();
            break;
        case ID_SCAN_DIR:
            pick_and_scan_folder();
            break;
        case ID_SCAN_QUICK:
            scan_quick();
            break;
        case ID_SCAN_START:
            if (a.scanning.load()) {
                scanner_cancel();
            } else if (a.scanPath.empty()) {
                scan_quick();
            } else {
                scan_path_async(a.scanPath);
            }
            break;
        case ID_SCAN_CLEAR:
            if (a.scanning.load()) {
                a.show_toast(L"扫描进行中，请先停止再清空");
            } else {
                a.results.clear();
                a.stats = ScanStats();
                a.selectedResult = -1;
                a.scrollScan = 0;
                a.scanFinished = false;
                a.scanCanceled = false;
                a.show_toast(L"已清空本次结果");
            }
            break;
        case ID_SCAN_QUARANTINE:
            scanner_quarantine_selected();
            break;
        case ID_SCAN_OPEN:
            open_selected_result(a);
            break;

        case ID_PROT_DRIVER:
            a.page = Page::Driver;
            a.start_page_anim();
            break;

        case ID_QUAR_REFRESH:
            scanner_load_quarantine();
            a.selectedQuar = a.quarantine.empty() ? -1 : 0;
            a.scrollQuar = 0;
            a.show_toast(L"隔离区已刷新");
            break;
        case ID_QUAR_RESTORE:
            scanner_restore_selected();
            break;
        case ID_QUAR_DELETE:
            scanner_delete_selected();
            break;

        case ID_LOG_REFRESH:
            scanner_load_history();
            a.selectedLog = -1;
            a.scrollLog = 0;
            a.show_toast(L"日志已刷新");
            break;
        case ID_LOG_CLEAR:
            scanner_clear_history();
            break;
        case ID_LOG_OPEN:
            open_logs_dir();
            break;

        case ID_DRV_REFRESH:
            scanner_refresh_driver();
            a.show_toast(L"驱动状态：" + a.driverState);
            break;
        case ID_DRV_OPEN_DATA:
            open_data_dir();
            break;

        case ID_SET_THEME_SYS:
        case ID_SET_THEME_LIGHT:
        case ID_SET_THEME_DARK: {
            int mode = id - ID_SET_THEME_SYS;
            a.settings.theme = mode;
            a.themeMode = (ThemeMode)mode;
            apply_theme(true);
            scanner_save_settings();
            a.show_toast(L"外观：" + theme_name(mode));
            break;
        }
        case ID_SET_MAX_MINUS:
            cycle_max_mb(a, -1);
            break;
        case ID_SET_MAX_PLUS:
            cycle_max_mb(a, 1);
            break;
        case ID_SET_ANIM:
            a.settings.animations = a.settings.animations ? 0 : 1;
            if (!a.settings.animations) a.animating = false;
            scanner_save_settings();
            a.show_toast(a.settings.animations ? L"已开启平滑动画" : L"已关闭平滑动画");
            break;
        case ID_SET_RELOAD:
            scanner_db_reload();
            break;
        case ID_SET_OPEN:
            open_data_dir();
            break;

        default:
            if (id >= ID_ROW_RESULT && id < ID_ROW_QUAR) {
                int i = id - ID_ROW_RESULT;
                if (i >= 0 && i < (int)a.results.size()) {
                    a.selectedResult = i;
                    a.show_toast(L"已选择：" + base_name(a.results[(size_t)i].path));
                }
            } else if (id >= ID_ROW_QUAR && id < ID_ROW_LOG) {
                int i = id - ID_ROW_QUAR;
                if (i >= 0 && i < (int)a.quarantine.size()) {
                    a.selectedQuar = i;
                }
            } else if (id >= ID_ROW_LOG) {
                int i = id - ID_ROW_LOG;
                if (i >= 0 && i < (int)a.history.size()) {
                    a.selectedLog = i;
                }
            }
            break;
    }
    InvalidateRect(a.hwnd, NULL, FALSE);
}

void ui_on_move(App &a, float x, float y) {
    int id = a.hit_test(x, y);
    if (id != a.hoverId) {
        a.hoverId = id;
        InvalidateRect(a.hwnd, NULL, FALSE);
    }
    SetCursor(LoadCursorW(NULL, id ? IDC_HAND : IDC_ARROW));
}

void ui_on_wheel(App &a, float, float, int delta) {
    float step = (float)delta / 120.0f * 56.0f;
    if (a.page == Page::Scan) {
        a.scrollScan = std::max(0.0f, a.scrollScan - step);
    } else if (a.page == Page::Quarantine) {
        a.scrollQuar = std::max(0.0f, a.scrollQuar - step);
    } else if (a.page == Page::Logs) {
        a.scrollLog = std::max(0.0f, a.scrollLog - step);
    }
    InvalidateRect(a.hwnd, NULL, FALSE);
}

void ui_on_key(App &a, WPARAM key) {
    bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    if (ctrl && (key == 'O' || key == 'o')) {
        a.page = Page::Scan;
        a.start_page_anim();
        if (shift) pick_and_scan_folder();
        else pick_and_scan_file();
    }
}





