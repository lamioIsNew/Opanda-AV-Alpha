/* theme.h -- WD 风格配色与尺寸 */
#pragma once

#include <d2d1.h>
#include <d2d1helper.h>

inline D2D1_COLOR_F C(unsigned int rgb, float a = 1.0f) {
    return D2D1::ColorF(
        (float)((rgb >> 16) & 0xFF) / 255.0f,
        (float)((rgb >> 8) & 0xFF) / 255.0f,
        (float)(rgb & 0xFF) / 255.0f,
        a);
}

inline D2D1_COLOR_F mixc(const D2D1_COLOR_F &a, const D2D1_COLOR_F &b, float t) {
    return D2D1::ColorF(
        a.r + (b.r - a.r) * t,
        a.g + (b.g - a.g) * t,
        a.b + (b.b - a.b) * t,
        a.a + (b.a - a.a) * t);
}

struct Theme {
    bool dark = false;
    D2D1_COLOR_F bg1, bg2, sidebar, sidebar2, card, card2, cardHover;
    D2D1_COLOR_F border, borderStrong;
    D2D1_COLOR_F text, text2, text3;
    D2D1_COLOR_F accent, accent2, accentSoft, accentSoft2;
    D2D1_COLOR_F success, successSoft;
    D2D1_COLOR_F warning, warningSoft;
    D2D1_COLOR_F danger, dangerSoft;
    D2D1_COLOR_F white, black, shadow, input, track, hover;
};

/* 任务 1：全局只允许黑/白/灰，不再出现彩色文字或彩色强调。 */
inline Theme make_theme(bool dark) {
    Theme t;
    t.dark = dark;
    if (!dark) {
        t.bg1 = C(0xF7F7F7);
        t.bg2 = C(0xEDEDED);
        t.sidebar = C(0xF2F2F2, 0.96f);
        t.sidebar2 = C(0xE8E8E8, 0.96f);
        t.card = C(0xFFFFFF, 0.98f);
        t.card2 = C(0xFAFAFA, 0.98f);
        t.cardHover = C(0xF0F0F0);
        t.border = C(0xDCDCDC);
        t.borderStrong = C(0xBFBFBF);
        t.text = C(0x111111);
        t.text2 = C(0x555555);
        t.text3 = C(0x808080);
        t.accent = C(0x1A1A1A);
        t.accent2 = C(0x333333);
        t.accentSoft = C(0xE6E6E6);
        t.accentSoft2 = C(0xD6D6D6);
        t.success = C(0x1A1A1A);
        t.successSoft = C(0xE8E8E8);
        t.warning = C(0x4D4D4D);
        t.warningSoft = C(0xEFEFEF);
        t.danger = C(0x000000);
        t.dangerSoft = C(0xE0E0E0);
        t.white = C(0xFFFFFF);
        t.black = C(0x000000);
        t.shadow = C(0x000000, 0.08f);
        t.input = C(0xFFFFFF, 0.96f);
        t.track = C(0xDDDDDD);
        t.hover = C(0x000000, 0.05f);
    } else {
        t.bg1 = C(0x1A1A1A);
        t.bg2 = C(0x121212);
        t.sidebar = C(0x1F1F1F, 0.96f);
        t.sidebar2 = C(0x262626, 0.96f);
        t.card = C(0x242424, 0.98f);
        t.card2 = C(0x2A2A2A, 0.98f);
        t.cardHover = C(0x303030);
        t.border = C(0x3A3A3A);
        t.borderStrong = C(0x505050);
        t.text = C(0xF5F5F5);
        t.text2 = C(0xB5B5B5);
        t.text3 = C(0x808080);
        t.accent = C(0xF0F0F0);
        t.accent2 = C(0xD0D0D0);
        t.accentSoft = C(0x333333);
        t.accentSoft2 = C(0x3D3D3D);
        t.success = C(0xE0E0E0);
        t.successSoft = C(0x2E2E2E);
        t.warning = C(0xC0C0C0);
        t.warningSoft = C(0x333333);
        t.danger = C(0xFFFFFF);
        t.dangerSoft = C(0x3A3A3A);
        t.white = C(0xFFFFFF);
        t.black = C(0x000000);
        t.shadow = C(0x000000, 0.35f);
        t.input = C(0x202020, 0.96f);
        t.track = C(0x3A3A3A);
        t.hover = C(0xFFFFFF, 0.06f);
    }
    return t;
}
