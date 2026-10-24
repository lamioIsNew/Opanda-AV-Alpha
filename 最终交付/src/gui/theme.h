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

inline Theme make_theme(bool dark) {
    Theme t;
    t.dark = dark;
    if (!dark) {
        t.bg1 = C(0xF7F8FA);
        t.bg2 = C(0xEDF1F5);
        t.sidebar = C(0xF2F4F7, 0.94f);
        t.sidebar2 = C(0xE9EDF2, 0.94f);
        t.card = C(0xFFFFFF, 0.96f);
        t.card2 = C(0xFAFBFC, 0.96f);
        t.cardHover = C(0xF3F6F9);
        t.border = C(0xE1E6EB);
        t.borderStrong = C(0xD0D7DE);
        t.text = C(0x1B1B1B);
        t.text2 = C(0x5D6670);
        t.text3 = C(0x8A939D);
        t.accent = C(0x0078D4);
        t.accent2 = C(0x2B88D8);
        t.accentSoft = C(0xE5F1FB);
        t.accentSoft2 = C(0xD2E8F8);
        t.success = C(0x107C10);
        t.successSoft = C(0xDFF6DD);
        t.warning = C(0xB77900);
        t.warningSoft = C(0xFFF4CE);
        t.danger = C(0xD13438);
        t.dangerSoft = C(0xFDE7E9);
        t.white = C(0xFFFFFF);
        t.black = C(0x000000);
        t.shadow = C(0x1B1B1B, 0.10f);
        t.input = C(0xFFFFFF, 0.92f);
        t.track = C(0xE3E8ED);
        t.hover = C(0x000000, 0.045f);
    } else {
        t.bg1 = C(0x202124);
        t.bg2 = C(0x18191C);
        t.sidebar = C(0x1B1C1F, 0.94f);
        t.sidebar2 = C(0x24262A, 0.94f);
        t.card = C(0x2B2D31, 0.96f);
        t.card2 = C(0x313338, 0.96f);
        t.cardHover = C(0x35383D);
        t.border = C(0x3A3D42);
        t.borderStrong = C(0x4A4E55);
        t.text = C(0xF5F6F7);
        t.text2 = C(0xB2B8C0);
        t.text3 = C(0x828A94);
        t.accent = C(0x4CC2FF);
        t.accent2 = C(0x7CD4FF);
        t.accentSoft = C(0x1E3A4D);
        t.accentSoft2 = C(0x254A63);
        t.success = C(0x6CCB5F);
        t.successSoft = C(0x1E3A1E);
        t.warning = C(0xFCE100);
        t.warningSoft = C(0x3D3A1A);
        t.danger = C(0xFF99A4);
        t.dangerSoft = C(0x442326);
        t.white = C(0xFFFFFF);
        t.black = C(0x000000);
        t.shadow = C(0x000000, 0.35f);
        t.input = C(0x232529, 0.92f);
        t.track = C(0x3A3D42);
        t.hover = C(0xFFFFFF, 0.055f);
    }
    return t;
}
