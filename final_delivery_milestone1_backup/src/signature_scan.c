/* signature_scan.c -- 特征码扫描（字符串/魔数匹配）
 * 每条特征码带：严重度（0=100 恶意 / 60=PUA）与 CARO 命名规范检测名
 * （类型.平台.家族，如 Ransom.Win32.Phobos）。
 */
#include "signature_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *pattern;
    int is_hex;
    unsigned char hex_pattern[16];
    int hex_len;
    int severity;     /* 0 视为 100（恶意）；60 = PUA（潜在不受欢迎应用） */
    const char *caro; /* CARO 检测名（输出用，可空） */
} Signature;

/* 注意：命中即返回（first-match-wins），因此"组合/精确"特征必须排在其"单关键词"之前。 */
static Signature sig_db[] = {
    /* ---- 勒索（家族精确名）---- */
    {"Phobos_VSSADMIN",  "vssadmin delete shadows", 0, {0}, 0, 0, "Ransom.Win32.Phobos"},
    {"Phobos_Ext",       ".phobos",                 0, {0}, 0, 0, "Ransom.Win32.Phobos"},
    {"Phobos_Note",      "HOW_TO_DECRYPT",          0, {0}, 0, 0, "Ransom.Win32.Phobos"},
    /* 魔数（之前分析出的） */
    {"Phobos_Magic_S",   "", 1, {0x12, 0x5E, 0xA7, 0xF0}, 4, 0, "Ransom.Win32.Phobos"},
    {"Phobos_Magic_L",   "", 1, {0x0F, 0xBC, 0x77, 0xAF}, 4, 0, "Ransom.Win32.Phobos"},

    /* ---- Browser Fleet：Go 编译的驻留/投放体（动态沙箱确认：自拷贝 + Run 键 + 看门狗 + 远程拉包）---- */
    {"BrowserFleet_Module",  "github.com/serhat/browser-fleet", 0, {0}, 0, 0, "Trojan.Win32.BrowserFleet"},
    {"BrowserFleet_RunKey",  "BrowserFleetRescue",              0, {0}, 0, 0, "Trojan.Win32.BrowserFleet"},
    {"BrowserFleet_Boot",    "fleet-rescue-bootstrap",          0, {0}, 0, 0, "Trojan.Win32.BrowserFleet"},
    {"BrowserFleet_Watchdog","--rescue-watchdog",               0, {0}, 0, 0, "Trojan.Win32.BrowserFleet"},

    /* ---- 本轮"细颗粒度"补充：家族精确名（依据样本集内实测字符串，逐条都能在真样本里对上）---- */
    /* njRAT 后门：样本集内 njRAT.exe 实测含 "njRAT" / "njRAT.exe" / "Project : njRat Version 0.6.4 Coded By : njq8" */
    {"njRAT_Artifact",   "njRAT",                   0, {0}, 0, 0, "Backdoor.Win32.NjRAT"},
    {"njRAT_Author",     "njq8",                    0, {0}, 0, 0, "Backdoor.Win32.NjRAT"},
    {"njRAT_Alt",        "bladabindi",              0, {0}, 0, 0, "Backdoor.Win32.NjRAT"},
    /* KeyPass 勒索：样本集内 Win32.KeyPass.bin 实测含勒索信／扩展名／联系邮箱 */
    {"KeyPass_Note",     "DECRYPTION__KEYPASS__INFO", 0, {0}, 0, 0, "Ransom.Win32.KeyPass"},
    {"KeyPass_Ext",      ".KEYPASS",                0, {0}, 0, 0, "Ransom.Win32.KeyPass"},
    {"KeyPass_Mail",     "keypassdecrypt@",         0, {0}, 0, 0, "Ransom.Win32.KeyPass"},
    /* 经典勒索家族（标记辨识度极高，误报风险低） */
    {"WannaCry_Ext",     ".WNCRY",                  0, {0}, 0, 0, "Ransom.Win32.WannaCry"},
    {"WannaCry_Note",    "WanaDecryptor",           0, {0}, 0, 0, "Ransom.Win32.WannaCry"},
    {"WannaCry_Task",    "tasksche.exe",            0, {0}, 0, 0, "Ransom.Win32.WannaCry"},
    {"LockBit_Ext",      ".lockbit",                0, {0}, 0, 0, "Ransom.Win32.LockBit"},
    {"Conti_Note",       "CONTI_README",            0, {0}, 0, 0, "Ransom.Win32.Conti"},
    {"REvil_Mark",       "sodinokibi",              0, {0}, 0, 0, "Ransom.Win32.REvil"},
    {"GandCrab_Mark",    "gandcrab",                0, {0}, 0, 0, "Ransom.Win32.GandCrab"},
    {"StopDjvu_Note",    "STOPDecryptor",           0, {0}, 0, 0, "Ransom.Win32.StopDjvu"},
    /* 后门／RAT／窃密（家族自带标识串） */
    {"AsyncRAT",         "AsyncRAT",                0, {0}, 0, 0, "Backdoor.Win32.AsyncRAT"},
    {"QuasarRAT",        "QuasarRAT",               0, {0}, 0, 0, "Backdoor.Win32.Quasar"},
    {"Remcos",           "Remcos",                  0, {0}, 0, 0, "Backdoor.Win32.Remcos"},
    {"NanoCore",         "NanoCore",                0, {0}, 0, 0, "Backdoor.Win32.NanoCore"},
    {"DarkComet",        "DarkComet",               0, {0}, 0, 0, "Backdoor.Win32.DarkComet"},
    {"Gh0st",            "Gh0st",                   0, {0}, 0, 0, "Backdoor.Win32.Gh0st"},
    {"AgentTesla",       "AgentTesla",              0, {0}, 0, 0, "Trojan.Win32.AgentTesla"},
    {"Formbook",         "Formbook",                0, {0}, 0, 0, "Trojan.Win32.Formbook"},
    {"LokiBot",          "LokiBot",                 0, {0}, 0, 0, "Trojan.Win32.LokiBot"},
    /* 攻击/渗透工具：用 HackTool 命名，避免和"恶意软件"混为一谈 */
    {"Mimikatz_Cmd",     "sekurlsa::logonpasswords",0, {0}, 0, 0, "HackTool.Win32.Mimikatz"},
    {"Mimikatz",         "mimikatz",                0, {0}, 0, 0, "HackTool.Win32.Mimikatz"},
    {"Meterpreter",      "meterpreter",             0, {0}, 0, 0, "Backdoor.Win32.Meterpreter"},
    {"CobaltStrike",     "cobaltstrike",            0, {0}, 0, 0, "Trojan.Win32.CobaltStrike"},
    /* 挖矿（RiskWare，按 60 分「疑似」报，避免把山寨/误装当高危） */
    {"Miner_XMRig",      "xmrig",                   0, {0}, 0, 60, "RiskWare.Win32.Miner"},
    {"Miner_Stratum",    "stratum+tcp://",          0, {0}, 0, 60, "RiskWare.Win32.Miner"},

    /* ---- 组合特征（必须排在下面 Generic_Cmd / Generic_PowerShell 之前）---- */
    {"ShellLoader_Cmd_PsEnc", "cmd.exe /c powershell -enc", 0, {0}, 0, 0, "Trojan.Win32.ShellLoader"},

    /* ---- HTA 载体 ---- */
    {"HTA_Mshta",        "mshta.exe",               0, {0}, 0, 0, "Trojan.Win32.HTA"},

    /* ---- 通用行为（兜底；下调为 70 分「疑似」，减少正常安装包误报）---- */
    {"Generic_Cmd",      "cmd.exe /c",              0, {0}, 0, 70, "Trojan.Win32.Generic"},
    {"Generic_PowerShell", "powershell -enc",       0, {0}, 0, 0, "Trojan.Win32.Generic"},
    {"Generic_VSS",      "vssadmin",                0, {0}, 0, 0, "Ransom.Win32.Generic"},
    {"Generic_Bcdedit",  "bcdedit",                 0, {0}, 0, 0, "Ransom.Win32.Generic"},

    /* ---- PUA（潜在不受欢迎应用）：命中以 60 分（SUSPICIOUS - PUA）报告 ---- */
    {"PUA_OpenCandy",    "OpenCandy",               0, {0}, 0, 60, "PUA.Win32.OpenCandy"},
    {"PUA_InstallCore",  "InstallCore",             0, {0}, 0, 60, "PUA.Win32.InstallCore"},
    {"PUA_DealPly",      "DealPly",                 0, {0}, 0, 60, "PUA.Win32.DealPly"},
    {"PUA_BrowseFox",    "BrowseFox",               0, {0}, 0, 60, "PUA.Win32.BrowseFox"},
    {"PUA_Crossrider",   "Crossrider",              0, {0}, 0, 60, "PUA.Win32.Crossrider"},
    {"PUA_Wajam",        "Wajam",                   0, {0}, 0, 60, "PUA.Win32.Wajam"},
    {"PUA_SearchProtect","SearchProtect",           0, {0}, 0, 60, "PUA.Win32.SearchProtect"},
    {"PUA_Yontoo",       "Yontoo",                  0, {0}, 0, 60, "PUA.Win32.Yontoo"},
    {"PUA_Hao123",       "hao123",                  0, {0}, 0, 60, "PUA.Win32.Hao123"},
};
static int sig_db_count = sizeof(sig_db) / sizeof(sig_db[0]);

/* ---------- 外部特征库（signatures.db） ---------- */
typedef struct {
    char *name;
    char *pattern;                 /* 文本特征；hex 特征为 NULL */
    int   is_hex;
    unsigned char hex_pattern[64];
    int   hex_len;
    int   severity;
    char *caro;
} DynSignature;

static DynSignature *g_ext = NULL;
static int g_ext_count = 0;
static int g_ext_cap   = 0;

static char *dup_str(const char *s) {
    size_t n;
    char *p;
    if (!s) s = "";
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void trim_field(char *s) {
    size_t n;
    if (!s) return;
    while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 把一条特征与缓冲区匹配；命中时填输出并返回 1 */
static int match_one(const unsigned char *buf, long fsize,
                     const char *name, const char *pattern, int is_hex,
                     const unsigned char *hex, int hex_len,
                     int severity, const char *caro,
                     char *matched_name, int max_name_len,
                     int *out_sev, char *out_caro, int caro_len) {
    int hit = 0;
    if (is_hex) {
        if (!hex || hex_len <= 0) return 0;
        for (long k = 0; k <= fsize - hex_len; k++) {
            if (memcmp(buf + k, hex, (size_t)hex_len) == 0) { hit = 1; break; }
        }
    } else {
        size_t len;
        if (!pattern) return 0;
        len = strlen(pattern);
        if (len == 0 || (long)len > fsize) return 0;
        for (long k = 0; k <= fsize - (long)len; k++) {
            if (memcmp(buf + k, pattern, len) == 0) { hit = 1; break; }
        }
    }
    if (!hit) return 0;
    if (matched_name && max_name_len > 0) {
        strncpy(matched_name, name ? name : "", max_name_len - 1);
        matched_name[max_name_len - 1] = '\0';
    }
    if (out_sev) *out_sev = (severity > 0) ? severity : 100;
    if (out_caro && caro_len > 0) {
        strncpy(out_caro, caro ? caro : "", caro_len - 1);
        out_caro[caro_len - 1] = '\0';
    }
    return 1;
}

int signature_db_load(const char *path) {
    FILE *fp;
    char line[8192];
    int added = 0;
    if (!path) return 0;
    fp = fopen(path, "rb");
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *fields[5];
        int nf = 0;
        char *p = line;
        size_t len = strlen(line);
        DynSignature d;
        int sev;
        int is_hex;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len >= 3 && (unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
            p = line + 3;
        if (!*p || *p == '#') continue;
        fields[nf++] = p;
        while (*p && nf < 5) {
            if (*p == '\t') { *p = '\0'; p++; fields[nf++] = p; }
            else p++;
        }
        if (nf < 5) continue;
        for (int i = 0; i < 4; i++) trim_field(fields[i]);
        if (!fields[0][0] || !fields[4][0]) continue;
        is_hex = atoi(fields[1]) ? 1 : 0;
        sev = atoi(fields[2]);
        if (sev <= 0) sev = 100;
        memset(&d, 0, sizeof(d));
        d.name = dup_str(fields[0]);
        d.caro = dup_str(fields[3]);
        d.severity = sev;
        d.is_hex = is_hex;
        if (!d.name || !d.caro) { free(d.name); free(d.caro); continue; }
        if (is_hex) {
            size_t hl = strlen(fields[4]);
            if (hl == 0 || (hl & 1) || hl / 2 > sizeof(d.hex_pattern)) {
                free(d.name); free(d.caro); continue;
            }
            d.hex_len = (int)(hl / 2);
            for (int i = 0; i < d.hex_len; i++) {
                int hi = hex_nibble((unsigned char)fields[4][i * 2]);
                int lo = hex_nibble((unsigned char)fields[4][i * 2 + 1]);
                if (hi < 0 || lo < 0) { d.hex_len = 0; break; }
                d.hex_pattern[i] = (unsigned char)((hi << 4) | lo);
            }
            if (d.hex_len <= 0) { free(d.name); free(d.caro); continue; }
        } else {
            d.pattern = dup_str(fields[4]);
            if (!d.pattern) { free(d.name); free(d.caro); continue; }
        }
        if (g_ext_count >= g_ext_cap) {
            int nc = g_ext_cap ? g_ext_cap * 2 : 64;
            DynSignature *np = (DynSignature *)realloc(g_ext, (size_t)nc * sizeof(DynSignature));
            if (!np) { free(d.name); free(d.caro); free(d.pattern); continue; }
            g_ext = np;
            g_ext_cap = nc;
        }
        g_ext[g_ext_count++] = d;
        added++;
    }
    fclose(fp);
    return added;
}

int signature_db_count(void) {
    return g_ext_count;
}

void signature_db_clear(void) {
    for (int i = 0; i < g_ext_count; i++) {
        free(g_ext[i].name);
        free(g_ext[i].pattern);
        free(g_ext[i].caro);
    }
    free(g_ext);
    g_ext = NULL;
    g_ext_count = 0;
    g_ext_cap = 0;
}

int signature_db_dump(const char *path) {
    FILE *fp;
    if (!path) return 0;
    fp = fopen(path, "wb");
    if (!fp) return 0;
    fputs("# SCANNER_SIGDB 1\n", fp);
    fputs("# name\tis_hex\tseverity\tcaro\tpattern\n", fp);
    for (int i = 0; i < sig_db_count; i++) {
        Signature *s = &sig_db[i];
        fprintf(fp, "%s\t%d\t%d\t%s\t", s->name, s->is_hex ? 1 : 0,
                (s->severity > 0) ? s->severity : 100, s->caro ? s->caro : "");
        if (s->is_hex) {
            for (int k = 0; k < s->hex_len; k++) fprintf(fp, "%02X", s->hex_pattern[k]);
        } else {
            fputs(s->pattern ? s->pattern : "", fp);
        }
        fputc('\n', fp);
    }
    fclose(fp);
    return sig_db_count;
}

int signature_scan(const char *filepath, char *matched_name, int max_name_len) {
    return signature_scan_ex(filepath, matched_name, max_name_len, NULL, NULL, 0);
}

int signature_scan_ex(const char *filepath, char *matched_name, int max_name_len, int *severity, char *caro_name, int caro_len) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0) { fclose(fp); return 0; }
    unsigned char *buf = (unsigned char *)malloc(fsize);
    if (!buf) { fclose(fp); return 0; }
    fread(buf, 1, fsize, fp);
    fclose(fp);

    int hit = signature_scan_buf_ex(buf, fsize, matched_name, max_name_len, severity, caro_name, caro_len);
    free(buf);
    return hit;
}

int signature_scan_buf(const unsigned char *buf, long fsize, char *matched_name, int max_name_len) {
    return signature_scan_buf_ex(buf, fsize, matched_name, max_name_len, NULL, NULL, 0);
}

/* 内存缓冲版特征码扫描（与文件版逻辑一致；额外输出严重度与 CARO 检测名）
 * 顺序：外部 signatures.db 优先（便于热更新/覆盖），内置表兜底。 */
int signature_scan_buf_ex(const unsigned char *buf, long fsize, char *matched_name, int max_name_len, int *severity, char *caro_name, int caro_len) {
    if (!buf || fsize <= 0) return 0;
    for (int i = 0; i < g_ext_count; i++) {
        DynSignature *s = &g_ext[i];
        if (match_one(buf, fsize, s->name, s->pattern, s->is_hex,
                      s->hex_pattern, s->hex_len, s->severity, s->caro,
                      matched_name, max_name_len, severity, caro_name, caro_len))
            return 1;
    }
    for (int i = 0; i < sig_db_count; i++) {
        Signature *s = &sig_db[i];
        if (match_one(buf, fsize, s->name, s->is_hex ? NULL : s->pattern, s->is_hex,
                      s->hex_pattern, s->hex_len, s->severity, s->caro,
                      matched_name, max_name_len, severity, caro_name, caro_len))
            return 1;
    }
    return 0;
}
