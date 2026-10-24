#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp
#else
#  include <strings.h>
#endif
#include <math.h>
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <time.h>

#include "feature_extractor.h"
#include "signature_scan.h"
#include "script_scan.h"
#include "lnk_scan.h"
#include "trust_check.h"
#include "verdict_cache.h"
#include "detector.h"
#include "risk_name.h"
#include "scanner_api.h"
#include "scan_output.h"

/* DLL 构建时把引擎里的 printf 全部汇到 scan_output：
 * CLI 默认写 stdout（排版不变），DLL 模式由 scanner_api.c 关闭。 */
#define printf scan_out

#define MAX_PATH_LEN 1024

static void wchar_to_char(const wchar_t *w, char *c, int n) {
    WideCharToMultiByte(CP_ACP, 0, w, -1, c, n, NULL, NULL);
}

/* 交互式窗口下把控制台“输出”代码页切到 UTF-8（退出时恢复）；
 * 被脚本以管道/重定向方式捕获时没有控制台，本函数无副作用 */
static UINT g_old_cp = 0;
static void restore_console_cp(void) { if (g_old_cp) SetConsoleOutputCP(g_old_cp); }
static void setup_console_utf8(void) {
    g_old_cp = GetConsoleOutputCP();
    if (g_old_cp && SetConsoleOutputCP(65001)) atexit(restore_console_cp);
}

int pick_file_dialog(wchar_t *out, int max_len) {
    OPENFILENAMEW ofn;
    out[0] = L'\0';
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = out;
    ofn.nMaxFile = max_len;
    ofn.lpstrFilter = L"Executables\0*.exe;*.dll;*.sys;*.scr\0Scripts (bat/cmd/ps1/vbs/js)\0*.bat;*.cmd;*.ps1;*.vbs;*.js;*.wsf;*.hta\0Shortcuts (*.lnk)\0*.lnk\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&ofn) ? 1 : 0;
}

int pick_dir_dialog(wchar_t *out, int max_len) {
    BROWSEINFOW bi = {0};
    bi.lpszTitle = L"Select a directory to scan";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return 0;
    SHGetPathFromIDListW(pidl, out);
    CoTaskMemFree(pidl);
    return 1;
}

/* 缓存命中：按统一格式输出（type_line 为中文类型描述；NULL 表示 PE/模型类） */
static void print_cached_result(const char *disp_name, const char *type_line, const VCacheHit *h) {
    pr_result_header(disp_name);
    if (type_line) printf("【类型】%s\n", type_line);
    else           printf("【熵值】%.4f\n", h->entropy);
    printf("【缓存】已于 %s 分析过，直接采用上次结论（免重复计算）\n", h->ts);
    if (type_line && h->caro[0]) printf("【检测名】%s\n", h->caro);
    printf("【风险评分】%.2f / 100\n", h->score);
    pr_line_verdict(h->bracket);
    pr_line_risk(h->caro);
    pr_line_advice(h->bracket);
    pr_result_end();
}

/* ---------- 扫描上下文：供目录统计与上下文日志导出使用 ---------- */
/* 结构体定义移到 scanner_api.h，保证 DLL 导出布局与 CLI 内部布局一致 */
typedef ScannerResult ScanOutcome;
static ScanOutcome g_last;

static void outcome_reset(void) {
    memset(&g_last, 0, sizeof(g_last));
    g_last.score = -1.0;
}

static void outcome_set(const char *bracket, const char *kind, const char *layer,
                        double score, const char *caro, const char *detail,
                        const char *sha) {
    snprintf(g_last.bracket, sizeof(g_last.bracket), "%s", bracket ? bracket : "");
    snprintf(g_last.kind, sizeof(g_last.kind), "%s", kind ? kind : "");
    snprintf(g_last.layer, sizeof(g_last.layer), "%s", layer ? layer : "");
    g_last.score = score;
    snprintf(g_last.caro, sizeof(g_last.caro), "%s", caro ? caro : "");
    snprintf(g_last.detail, sizeof(g_last.detail), "%s", detail ? detail : "");
    if (sha && sha[0]) snprintf(g_last.sha, sizeof(g_last.sha), "%s", sha);
}

/* DLL 导出层调用：把最近一次扫描结果整体拷出 */
void scan_get_outcome(ScannerResult *out) {
    if (out) *out = g_last;
}

/* ---------- PE 虚拟执行（pe_vm 联动；用户态 x86 解释器） ----------
 * 一般扫描流程里发现 [PACKED] 的 PE 后，交给 沙箱\PE虚拟执行沙盒\虚拟执行.ps1，
 * 由 pe_vm.exe 在进程内做 x86-32 解释执行：镜像虚拟装载、内存访问逐次校验、
 * Windows API 全部假实现 —— 不落真机、不加载真 DLL、不碰真注册表/网络。
 * 动态结论用独立标记 [VM: ...] 输出，不参与上面的机器标记与汇总统计。 */
static void utf8_to_acp(const char *u8, char *out, int outsz); /* 前置声明（定义见后） */

#define PEVM_MAXLIST 4096
static char *g_pevm_paths[PEVM_MAXLIST];
static int   g_pevm_n  = 0;
static int   g_pevm_on = 1;

/* DLL 模式：1=库模式（静默、禁虚拟执行），0=CLI 模式 */
void scan_set_lib_mode(int on) {
    g_pevm_on = on ? 0 : 1;
    scan_out_set_enabled(on ? 0 : 1);
}

static void pevm_reset(void) {
    for (int i = 0; i < g_pevm_n; i++) {
        free(g_pevm_paths[i]);
        g_pevm_paths[i] = NULL;
    }
    g_pevm_n = 0;
}

static void pevm_collect(const char *path) {
    if (!g_pevm_on || !path || !path[0]) return;
    if (g_pevm_n >= PEVM_MAXLIST) return;
    for (int i = 0; i < g_pevm_n; i++)
        if (strcmp(g_pevm_paths[i], path) == 0) return;
    g_pevm_paths[g_pevm_n++] = _strdup(path);
}

/* 系统 ANSI(GBK) -> UTF-8：清单文件按 UTF-8 写，PowerShell 才认得出中文路径 */
static int acp_to_utf8(const char *in, char *out, int outsz) {
    wchar_t w[MAX_PATH_LEN];
    if (MultiByteToWideChar(CP_ACP, 0, in, -1, w, MAX_PATH_LEN) <= 0) return 0;
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outsz, NULL, NULL) > 0;
}

/* 扫描收尾：把本轮收集到的加壳 PE 交给虚拟执行驱动脚本。
 * 返回 0 表示未触发/正常，非 0 为子进程返回码。 */
static int run_pe_virtual_exec(const char *target) {
    if (!g_pevm_on) { g_pevm_n = 0; return 0; }
    if (g_pevm_n == 0) return 0;

    char exe_dir[MAX_PATH_LEN] = {0};
    if (!GetModuleFileNameA(NULL, exe_dir, MAX_PATH_LEN)) { g_pevm_n = 0; return -1; }
    char *slash = strrchr(exe_dir, '\\');
    if (slash) *slash = '\0';

    char d_sbox[64], d_pev[64], f_ps1[64];
    utf8_to_acp("沙箱", d_sbox, sizeof(d_sbox));
    utf8_to_acp("PE虚拟执行沙盒", d_pev, sizeof(d_pev));
    utf8_to_acp("虚拟执行.ps1", f_ps1, sizeof(f_ps1));

    char script[MAX_PATH_LEN];
    snprintf(script, sizeof(script), "%s\\%s\\%s\\%s", exe_dir, d_sbox, d_pev, f_ps1);
    char script_u8[4096];
    path_to_utf8(script, script_u8, sizeof(script_u8));
    if (GetFileAttributesA(script) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[虚拟执行] 未找到联动脚本 %s，本次跳过。\n", script_u8);
        g_pevm_n = 0;
        return 0;
    }

    /* 清单：UTF-8 + BOM（避免中文路径被按 GBK 误读） */
    char tmpdir[MAX_PATH_LEN] = {0};
    if (!GetTempPathA(MAX_PATH_LEN, tmpdir)) snprintf(tmpdir, sizeof(tmpdir), ".\\");
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%sscan_pevm_%lu.txt", tmpdir, (unsigned long)GetCurrentProcessId());
    FILE *fp = fopen(tmp, "wb");
    if (!fp) { printf("\n[虚拟执行] 临时清单写入失败，本次跳过。\n"); g_pevm_n = 0; return 0; }
    fputs("\xEF\xBB\xBF", fp);
    for (int i = 0; i < g_pevm_n; i++) {
        char u8[MAX_PATH_LEN * 3];
        if (acp_to_utf8(g_pevm_paths[i], u8, sizeof(u8))) { fputs(u8, fp); fputs("\r\n", fp); }
    }
    fclose(fp);

    /* 产物目录：目录目标放其下；单文件放同级 */
    char out_sub[64];
    utf8_to_acp("_虚拟执行", out_sub, sizeof(out_sub));
    char outdir[MAX_PATH_LEN] = {0};
    DWORD tattr = GetFileAttributesA(target);
    if (target && tattr != INVALID_FILE_ATTRIBUTES && (tattr & FILE_ATTRIBUTE_DIRECTORY)) {
        snprintf(outdir, sizeof(outdir), "%s\\%s", target, out_sub);
    } else {
        snprintf(outdir, sizeof(outdir), "%s", target ? target : ".");
        char *p2 = strrchr(outdir, '\\');
        if (p2) *p2 = '\0'; else snprintf(outdir, sizeof(outdir), ".");
        size_t l = strlen(outdir);
        snprintf(outdir + l, sizeof(outdir) - l, "\\%s", out_sub);
    }
    char out_u8[4096];
    path_to_utf8(outdir, out_u8, sizeof(out_u8));

    char cmd[MAX_PATH_LEN * 4];
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\" -ListFile \"%s\" -OutDir \"%s\"",
        script, tmp, outdir);

    printf("\n[虚拟执行] 本轮发现 %d 个加壳 PE，交给用户态 x86 解释器虚拟执行\n", g_pevm_n);
    printf("           （镜像虚拟装载 + 内存逐次校验 + API 假实现；不落真机、不调真 API）\n\n");
    fflush(stdout);

    int rc = system(cmd);
    DeleteFileA(tmp);
    printf("\n[虚拟执行] 结束（返回码 %d）。解壳产物与报告目录：%s\n", rc, out_u8);
    g_pevm_n = 0;
    return rc;
}

/* 多类型检测：PE（签名信任→特征码→加壳→模型）/ LNK / 文本脚本 */
void scan_one_file(const char *path) {
    outcome_reset();

    /* 显示名：argv/路径为 ANSI(GBK) 字节，转 UTF-8 后控制台才不乱码 */
    char disp[4096];
    path_to_utf8(path, disp, sizeof(disp));

    /* 层1：PE 合法性检查；非 PE 时依次尝试 LNK、脚本 */
    if (!is_valid_pe(path)) {
        /* LNK 优先（其 UTF-16 字符串形态可能被脚本引擎误判） */
        double lscore = 0.0;
        char ldetail[256] = {0};
        char lcaro[64] = {0};
        char ltarget[512] = {0};
        char largs[256] = {0};
        int lrules = lnk_scan_file(path, &lscore, ldetail, sizeof(ldetail),
                                   lcaro, sizeof(lcaro),
                                   ltarget, sizeof(ltarget), largs, sizeof(largs));
        if (lrules >= 0) {
            char sha[65] = {0};
            int have_sha = vcache_sha256_file(path, sha);
            if (have_sha) {
                VCacheHit h;
                if (vcache_lookup(sha, "LNK", &h)) {
                    print_cached_result(disp, "快捷方式（.lnk）", &h);
                    outcome_set(h.bracket, "快捷方式", "缓存", h.score, h.caro,
                                "命中判决缓存（此前结论）", sha);
                    return;
                }
            }
            const char *br;
            if (lscore >= 80)      br = "[HIGH RISK - LNK]";
            else if (lscore >= 50) br = "[SUSPICIOUS - LNK]";
            else                   br = "[NORMAL]";
            pr_result_header(disp);
            printf("【类型】快捷方式（.lnk）\n");
            if (lcaro[0]) printf("【检测名】%s\n", lcaro);
            printf("【风险评分】%.2f / 100\n", lscore);
            pr_line_verdict(br);
            pr_line_risk(lcaro);
            if (ltarget[0]) printf("【目标程序】%s\n", ltarget);
            if (largs[0])   printf("【命令行参数】%s\n", largs);
            if (lrules > 0 && ldetail[0]) printf("【触发规则】%s\n", ldetail);
            pr_line_advice(br);
            pr_result_end();
            if (have_sha) vcache_add(sha, "LNK", lscore, 0.0, lcaro, br);
            outcome_set(br, "快捷方式", "LNK启发", lscore, lcaro, ldetail,
                        have_sha ? sha : "");
            return;
        }

        double sscore = 0.0;
        char sdetail[256] = {0};
        char scaro[64] = {0};
        int srules = script_scan_file(path, &sscore, sdetail, sizeof(sdetail), scaro, sizeof(scaro));
        if (srules >= 0) {
            char sha[65] = {0};
            int have_sha = vcache_sha256_file(path, sha);
            if (have_sha) {
                VCacheHit h;
                if (vcache_lookup(sha, "SCRIPT", &h)) {
                    print_cached_result(disp, "文本脚本", &h);
                    outcome_set(h.bracket, "文本脚本", "缓存", h.score, h.caro,
                                "命中判决缓存（此前结论）", sha);
                    return;
                }
            }
            const char *br;
            if (sscore >= 80)      br = "[HIGH RISK - SCRIPT]";
            else if (sscore >= 50) br = "[SUSPICIOUS - SCRIPT]";
            else                   br = "[NORMAL]";
            pr_result_header(disp);
            printf("【类型】文本脚本\n");
            if (scaro[0]) printf("【检测名】%s\n", scaro);
            printf("【风险评分】%.2f / 100\n", sscore);
            pr_line_verdict(br);
            pr_line_risk(scaro);
            if (srules > 0 && sdetail[0]) printf("【触发规则】%s\n", sdetail);
            pr_line_advice(br);
            pr_result_end();
            if (have_sha) vcache_add(sha, "SCRIPT", sscore, 0.0, scaro, br);
            outcome_set(br, "文本脚本", "脚本启发", sscore, scaro, sdetail,
                        have_sha ? sha : "");
        } else {
            printf("[SKIP] 不是可识别的 PE / 脚本 / 快捷方式文件: %s\n", disp);
            outcome_set("[SKIP]", "未知", "跳过", -1.0, "",
                        "不是可识别的 PE / 脚本 / 快捷方式", "");
        }
        return;
    }

    /* 层2：数字签名信任（有效签名 + 已知大厂 => 直接可信，压误报）
     * 白名单优先（同火绒）：放在特征码之前，避免对正规软件误报 */
    char signer[256] = {0};
    int tv = trust_check_file(path, signer, sizeof(signer));
    if (tv == 2) {
        pr_result_header(disp);
        printf("【数字签名】%s（可信发布者）\n", signer[0] ? signer : "未知发布者");
        pr_line_verdict("[TRUSTED]");
        pr_line_advice("[TRUSTED]");
        pr_result_end();
        {
            char td[400];
            snprintf(td, sizeof(td), "数字签名有效且发布者可信：%s",
                     signer[0] ? signer : "未知发布者");
            outcome_set("[TRUSTED]", "PE", "信任", -1.0, "", td, "");
        }
        return;
    }

    /* 层3：特征码扫描（含 PUA 类别） */
    char match[128] = {0};
    char caro[64] = {0};
    int sigsev = 100;
    if (signature_scan_ex(path, match, sizeof(match), &sigsev, caro, sizeof(caro))) {
        const char *br = (sigsev >= 100) ? "[HIGH RISK - SIGNATURE]" : "[SUSPICIOUS - PUA]";
        pr_result_header(disp);
        printf("【命中特征】%s\n", match);
        if (caro[0]) printf("【检测名】%s\n", caro);
        printf("【风险评分】%d / 100\n", sigsev);
        pr_line_verdict(br);
        pr_line_risk(caro);
        pr_line_advice(br);
        pr_result_end();
        char sha[65] = {0};
        int have_sha = vcache_sha256_file(path, sha);
        outcome_set(br, "PE", "特征码", (double)sigsev, caro, match, have_sha ? sha : "");
        return;
    }

    /* 层4：加壳检测 */
    double entropy = calc_file_entropy(path);
    if (entropy > 7.0) {
        pr_result_header(disp);
        printf("【熵值】%.4f（高于 7.0，疑似加密或压缩）\n", entropy);
        pr_line_verdict("[PACKED]");
        pr_line_risk("Packed.Win32.Generic");
        printf("【说明】File appears to be PACKED. 加壳会隐藏真实代码与字符串，静态特征不可靠。\n");
        pr_line_advice("[PACKED]");
        pr_result_end();
        {
            char pd[128];
            snprintf(pd, sizeof(pd), "熵值 %.4f，疑似加密或压缩（File appears to be PACKED）", entropy);
            char sha[65] = {0};
            int have_sha = vcache_sha256_file(path, sha);
            outcome_set("[PACKED]", "PE", "加壳", -1.0, "", pd, have_sha ? sha : "");
        }
        pevm_collect(path);   /* 记下来，扫描收尾时统一做虚拟执行（见 run_pe_virtual_exec） */
        return;
    }

    /* 层5：EMBER 特征提取 + LightGBM 推理（带判决缓存） */
    char sha[65] = {0};
    int have_sha = vcache_sha256_file(path, sha);
    if (have_sha) {
        VCacheHit h;
        if (vcache_lookup(sha, "MODEL", &h)) {
            print_cached_result(disp, NULL, &h);
            outcome_set(h.bracket, "PE", "缓存", h.score, h.caro,
                        "命中判决缓存（此前结论）", sha);
            return;
        }
    }
    double features[FEATURE_DIM];
    if (!extract_features(path, features)) {
        printf("[错误] 无法提取特征: %s\n", disp);
        outcome_set("", "PE", "错误", -1.0, "", "特征提取失败，无法评估", have_sha ? sha : "");
        return;
    }
    double s = predict_score(features);
    const char *br = (s >= 80) ? "[HIGH RISK]" : (s >= 50) ? "[SUSPICIOUS]" : "[NORMAL]";
    const char *det = (s >= 80) ? "Trojan.Win32.Generic!ml" : (s >= 50) ? "RiskWare.Win32.Generic!ml" : "";
    pr_result_header(disp);
    printf("【熵值】%.4f\n", entropy);
    if (tv == 1 && signer[0])
        printf("【数字签名】%s（签名有效，但发布者不在信任名单）\n", signer);
    printf("【风险评分】%.2f / 100\n", s);
    pr_line_verdict(br);
    if (det[0]) pr_line_risk(det);
    pr_line_advice(br);
    pr_result_end();
    if (have_sha) vcache_add(sha, "MODEL", s, entropy, det, br);
    {
        char md[160];
        snprintf(md, sizeof(md), "熵值 %.4f", entropy);
        outcome_set(br, "PE", "模型", s, det, md, have_sha ? sha : "");
    }
}

/* ---------- 目录扫描：递归遍历 + 报毒率统计 + 上下文日志导出 ---------- */

typedef struct {
    int total, high, susp, normal, trust, packed, skip, error;
} DirStats;
static DirStats g_stats;

static FILE *g_log_fp = NULL;
static char g_log_disp[4096] = {0};

/* 跳过自身产物：上下文日志 / scan_any 日志 / 判决缓存 */
static int is_own_artifact(const char *name) {
    size_t n = strlen(name);
    if (n > 13 && strncmp(name, "scan_log_", 9) == 0 &&
        strcasecmp(name + n - 4, ".csv") == 0) return 1;
    if (n > 12 && strcasecmp(name + n - 12, ".scanlog.txt") == 0) return 1;
    if (strcasecmp(name, "verdict_cache.txt") == 0) return 1;
    return 0;
}

static void csv_field(FILE *fp, const char *s) {
    fputc('"', fp);
    if (s) {
        for (; *s; s++) {
            if (*s == '"') fputc('"', fp);
            if ((unsigned char)*s >= 0x20) fputc(*s, fp);
            else fputc(' ', fp);
        }
    }
    fputc('"', fp);
}
static void csv_sep(FILE *fp) { fputc(',', fp); }

/* 写一行上下文日志（每个被扫描文件一行） */
static void log_write_row(const char *path) {
    if (!g_log_fp) return;

    WIN32_FILE_ATTRIBUTE_DATA fad;
    unsigned long long fsize = 0;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        fsize = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

    char path_utf8[4096];
    path_to_utf8(path, path_utf8, sizeof(path_utf8));
    const char *base = strrchr(path_utf8, '\\');
    base = base ? base + 1 : path_utf8;

    char sha[65] = {0};
    if (g_last.sha[0]) snprintf(sha, sizeof(sha), "%s", g_last.sha);
    else if (fsize <= 512ULL * 1024 * 1024) vcache_sha256_file(path, sha);

    char ts[32] = {0};
    time_t t = time(NULL);
    struct tm *tmv = localtime(&t);
    if (tmv) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tmv);

    char sizebuf[32], scorebuf[32];
    snprintf(sizebuf, sizeof(sizebuf), "%llu", fsize);
    if (g_last.score >= 0.0) snprintf(scorebuf, sizeof(scorebuf), "%.2f", g_last.score);
    else scorebuf[0] = '\0';

    csv_field(g_log_fp, ts);             csv_sep(g_log_fp);
    csv_field(g_log_fp, path_utf8);      csv_sep(g_log_fp);
    csv_field(g_log_fp, base);           csv_sep(g_log_fp);
    csv_field(g_log_fp, sizebuf);        csv_sep(g_log_fp);
    csv_field(g_log_fp, sha);            csv_sep(g_log_fp);
    csv_field(g_log_fp, g_last.kind);    csv_sep(g_log_fp);
    csv_field(g_log_fp, g_last.bracket); csv_sep(g_log_fp);
    csv_field(g_log_fp, scorebuf);       csv_sep(g_log_fp);
    csv_field(g_log_fp, g_last.layer);   csv_sep(g_log_fp);
    csv_field(g_log_fp, g_last.caro);    csv_sep(g_log_fp);
    csv_field(g_log_fp, g_last.detail);
    fputc('\n', g_log_fp);
}

static void stats_add(void) {
    g_stats.total++;
    const char *b = g_last.bracket;
    if (strncmp(b, "[HIGH RISK", 10) == 0)       g_stats.high++;
    else if (strncmp(b, "[SUSPICIOUS", 11) == 0) g_stats.susp++;
    else if (strncmp(b, "[NORMAL]", 8) == 0)     g_stats.normal++;
    else if (strncmp(b, "[TRUSTED", 8) == 0)     g_stats.trust++;
    else if (strncmp(b, "[PACKED", 7) == 0)      g_stats.packed++;
    else if (strncmp(b, "[SKIP]", 6) == 0)       g_stats.skip++;
    else                                          g_stats.error++;
}

static void scan_dir_walk(const char *dir, int depth) {
    if (depth > 32) return;
    char pat[MAX_PATH_LEN];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        char dp[4096];
        path_to_utf8(dir, dp, sizeof(dp));
        printf("[警告] 无法读取目录: %s\n", dp);
        return;
    }
    do {
        const char *name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (is_own_artifact(name)) continue;

        char full[MAX_PATH_LEN];
        snprintf(full, sizeof(full), "%s\\%s", dir, name);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                scan_dir_walk(full, depth + 1);
            continue;
        }

        unsigned long long fsz = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        char nu[4096];
        path_to_utf8(name, nu, sizeof(nu));

        if (fsz > 512ULL * 1024 * 1024) {
            printf("[%3d] %s\n    [跳过] 文件过大（超过 512MB 上限），未静态扫描\n", g_stats.total + 1, nu);
            outcome_set("[SKIP]", "未知", "跳过", -1.0, "", "文件过大（超过 512MB 上限）", "");
            stats_add();
            log_write_row(full);
            continue;
        }

        printf("[%3d] %s\n", g_stats.total + 1, nu);
        scan_one_file(full);
        stats_add();
        log_write_row(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void scan_directory(const char *dir, const char *log_path) {
    memset(&g_stats, 0, sizeof(g_stats));
    g_log_fp = NULL;
    g_log_disp[0] = '\0';

    char root[MAX_PATH_LEN];
    snprintf(root, sizeof(root), "%s", dir);
    size_t rl = strlen(root);
    while (rl > 1 && (root[rl - 1] == '\\' || root[rl - 1] == '/')) root[--rl] = '\0';

    char auto_log[MAX_PATH_LEN];
    if (!log_path || !log_path[0]) {
        time_t t = time(NULL);
        struct tm *tmv = localtime(&t);
        if (tmv) {
            snprintf(auto_log, sizeof(auto_log),
                     "%s\\scan_log_%04d%02d%02d_%02d%02d%02d.csv", root,
                     tmv->tm_year + 1900, tmv->tm_mon + 1, tmv->tm_mday,
                     tmv->tm_hour, tmv->tm_min, tmv->tm_sec);
        } else {
            snprintf(auto_log, sizeof(auto_log), "%s\\scan_log.csv", root);
        }
        log_path = auto_log;
    }

    g_log_fp = fopen(log_path, "wb");
    if (g_log_fp) {
        fputs("\xEF\xBB\xBF", g_log_fp); /* UTF-8 BOM：Excel 双击打开不乱码 */
        fputs("时间,完整路径,文件名,大小(字节),SHA256,类型,判定,评分,层级,检测名,细节\n", g_log_fp);
        path_to_utf8(log_path, g_log_disp, sizeof(g_log_disp));
    } else {
        char dp[4096];
        path_to_utf8((char *)log_path, dp, sizeof(dp));
        printf("[提示] 无法写入上下文日志，本次仅做统计: %s\n", dp);
    }

    char dp0[4096];
    path_to_utf8(root, dp0, sizeof(dp0));
    printf("开始扫描目录: %s\n\n", dp0);
    scan_dir_walk(root, 0);

    int judged = g_stats.total - g_stats.skip - g_stats.error;
    if (judged < 0) judged = 0;
    double rate_j = judged ? (100.0 * (g_stats.high + g_stats.susp) / judged) : 0.0;
    double rate_a = g_stats.total ? (100.0 * (g_stats.high + g_stats.susp) / g_stats.total) : 0.0;

    printf("\n============================================\n");
    printf("扫描统计（报毒率）\n");
    printf("  目标      : %s\n", dp0);
    printf("  文件总数  : %d\n", g_stats.total);
    printf("  高危      : %d\n", g_stats.high);
    printf("  疑似      : %d\n", g_stats.susp);
    printf("  正常      : %d\n", g_stats.normal);
    printf("  可信      : %d（数字签名已信任）\n", g_stats.trust);
    printf("  加壳      : %d\n", g_stats.packed);
    printf("  跳过      : %d（无法识别 / 过大）\n", g_stats.skip);
    printf("  失败      : %d\n", g_stats.error);
    printf("  报毒率    : (高危+疑似)/可判定 = %d/%d = %.1f%%\n",
           g_stats.high + g_stats.susp, judged, rate_j);
    printf("  报毒率    : (高危+疑似)/全部文件 = %d/%d = %.1f%%\n",
           g_stats.high + g_stats.susp, g_stats.total, rate_a);
    if (g_log_fp) printf("  上下文日志: %s\n", g_log_disp);
    printf("============================================\n");

    if (g_log_fp) {
        fprintf(g_log_fp,
                "\n# 汇总,文件总数,%d,高危,%d,疑似,%d,正常,%d,可信,%d,加壳,%d,跳过,%d,失败,%d\n",
                g_stats.total, g_stats.high, g_stats.susp, g_stats.normal,
                g_stats.trust, g_stats.packed, g_stats.skip, g_stats.error);
        fprintf(g_log_fp, "# 报毒率(高危+疑似)/可判定,%d/%d,%.1f%%\n",
                g_stats.high + g_stats.susp, judged, rate_j);
        fclose(g_log_fp);
        g_log_fp = NULL;
    }
}

void show_menu() {
    printf("\n------------ 主菜单 ------------\n");
    printf("1. 选择文件扫描（含加壳 PE 虚拟执行）\n");
    printf("2. 选择文件夹扫描（递归 + 报毒率统计 + 上下文日志 + 加壳 PE 虚拟执行）\n");
    printf("3. 手动输入文件路径\n");
    printf("4. 行为沙箱分析（自动化：静态选靶 → 沙箱动态观察 → 合并结论）\n");
    printf("5. 加壳 PE 虚拟执行：%s\n", g_pevm_on ? "开（推荐）" : "关");
    printf("6. 退出\n");
    printf("--------------------------------\n");
    printf("请输入选项 (1-6): ");
}

/* UTF-8 -> 系统 ANSI(ACP) 转换：源码里的中文串是 UTF-8，而 GetModuleFileNameA/argv
 * 给的是 ANSI（中文系统为 GBK），拼路径前必须统一成 ANSI。 */
static void utf8_to_acp(const char *u8, char *out, int outsz) {
    wchar_t w[512];
    out[0] = '\0';
    if (MultiByteToWideChar(CP_UTF8, 0, u8, -1, w, 512) <= 0) return;
    WideCharToMultiByte(CP_ACP, 0, w, -1, out, outsz, NULL, NULL);
}

/* 行为沙箱联动：定位 auto_analyze.ps1，交给 PowerShell 自动跑一遍。
 * 返回 0 表示已调用或已给出提示；非 0 为子进程返回码。 */
int run_behavior_sandbox(const char *target) {
    char exe_dir[MAX_PATH_LEN] = {0};
    if (!GetModuleFileNameA(NULL, exe_dir, MAX_PATH_LEN)) return -1;
    char *slash = strrchr(exe_dir, '\\');
    if (slash) *slash = '\0';

    char sub_cn[64];
    utf8_to_acp("行为沙箱", sub_cn, sizeof(sub_cn));
    const char *subs[3];
    subs[0] = sub_cn; subs[1] = "behavior"; subs[2] = "..\\behavior";

    char script[MAX_PATH_LEN] = {0};
    for (int i = 0; i < 3; i++) {
        char cand[MAX_PATH_LEN];
        snprintf(cand, sizeof(cand), "%s\\%s\\auto_analyze.ps1", exe_dir, subs[i]);
        if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
            strncpy(script, cand, sizeof(script) - 1);
            break;
        }
    }
    if (script[0] == '\0') {
        printf("[提示] 未找到 auto_analyze.ps1。\n");
        printf("       应在「%s\\行为沙箱\\」或「%s\\behavior\\」目录下。\n", exe_dir, exe_dir);
        return 0;
    }

    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\" -Target \"%s\" -Top 5",
        script, target);

    printf("\n[行为沙箱] 正在启动自动化行为分析：先静态选靶，再逐个丢进 Windows 沙箱真跑，\n");
    printf("            最后合并成最终结论。每个样本约需 1-2 分钟，期间会弹出沙箱窗口，\n");
    printf("            请勿关闭本控制台。\n\n");
    fflush(stdout);

    int rc = system(cmd);
    printf("\n[行为沙箱] 分析结束（返回码 %d）。报告见“行为沙箱\\分析结果”目录。\n", rc);
    return rc;
}

int main(int argc, char **argv) {
    setup_console_utf8();

    printf("\n============================================\n");
    printf("             恶意软件扫描器\n");
    printf("     特征码 · 机器学习 · 查壳 · 签名信任\n");
    printf("============================================\n");
    printf("判定阈值: 风险评分 >= 80 判高危, >= 50 判疑似\n\n");

    const char *scaler_path = (argc >= 2) ? argv[1] : "scaler.txt";
    char sp[4096];
    path_to_utf8(scaler_path, sp, sizeof(sp));
    printf("正在加载模型参数: %s\n", sp);
    if (!load_scaler(scaler_path)) {
        printf("[错误] 无法加载 scaler.txt，请确认它与程序在同一目录。\n");
        system("pause");
        return 1;
    }
    printf("模型参数加载完成，就绪。\n");

    vcache_load();
    printf("判决缓存: 已关闭（每次均重新分析，不跳过已扫描文件）。\n");

    /* 命令行模式：
     *   scan.exe scaler.txt <文件>                       单文件扫描
     *   scan.exe scaler.txt <目录>                       目录扫描（递归 + 报毒率统计 + 自动导出上下文日志）
     *   scan.exe scaler.txt <目标> --log <日志.csv>       指定上下文日志保存路径
     */
    if (argc >= 3) {
        const char *target = argv[2];
        const char *log_path = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) log_path = argv[++i];
            else if (strcmp(argv[i], "--no-pevm") == 0) g_pevm_on = 0;
        }
        pevm_reset();
        DWORD attr = GetFileAttributesA(target);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            scan_directory(target, log_path);
            run_pe_virtual_exec(target);
        } else {
            scan_one_file(target);
            if (log_path) {
                FILE *fp = fopen(log_path, "wb");
                if (fp) {
                    fputs("\xEF\xBB\xBF", fp);
                    fputs("时间,完整路径,文件名,大小(字节),SHA256,类型,判定,评分,层级,检测名,细节\n", fp);
                    g_log_fp = fp;
                    log_write_row(target);
                    g_log_fp = NULL;
                    fclose(fp);
                    char lp[4096];
                    path_to_utf8(log_path, lp, sizeof(lp));
                    printf("上下文日志已导出: %s\n", lp);
                } else {
                    char lp[4096];
                    path_to_utf8((char *)log_path, lp, sizeof(lp));
                    printf("[提示] 无法写入上下文日志: %s\n", lp);
                }
            }
            run_pe_virtual_exec(target);
        }
        return 0;
    }

    while (1) {
        show_menu();
        char buf[16];
        if (!fgets(buf, 16, stdin)) break;
        int c = atoi(buf);

        if (c == 1) {
            wchar_t wp[MAX_PATH_LEN];
            if (!pick_file_dialog(wp, MAX_PATH_LEN)) { printf("已取消。\n"); continue; }
            char p[MAX_PATH_LEN];
            wchar_to_char(wp, p, MAX_PATH_LEN);
            pevm_reset();
            scan_one_file(p);
            run_pe_virtual_exec(p);
        } else if (c == 2) {
            wchar_t wd[MAX_PATH_LEN];
            if (!pick_dir_dialog(wd, MAX_PATH_LEN)) { printf("已取消。\n"); continue; }
            char d[MAX_PATH_LEN];
            wchar_to_char(wd, d, MAX_PATH_LEN);
            pevm_reset();
            scan_directory(d, NULL);
            run_pe_virtual_exec(d);
        } else if (c == 3) {
            char p[MAX_PATH_LEN];
            printf("请输入文件路径: ");
            if (!fgets(p, MAX_PATH_LEN, stdin)) continue;
            p[strcspn(p, "\r\n")] = '\0';
            if (strlen(p) == 0) continue;
            pevm_reset();
            scan_one_file(p);
            run_pe_virtual_exec(p);
        } else if (c == 4) {
            char p[MAX_PATH_LEN];
            printf("请输入要分析的 文件 或 目录 路径（直接回车取消）: ");
            if (!fgets(p, MAX_PATH_LEN, stdin)) continue;
            p[strcspn(p, "\r\n")] = '\0';
            /* 去掉拖拽/复制时可能带上的首尾引号与空白 */
            char *s = p;
            while (*s == ' ' || *s == '\t' || *s == '"') s++;
            size_t n = strlen(s);
            while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '"')) s[--n] = '\0';
            if (n == 0) continue;
            run_behavior_sandbox(s);
        } else if (c == 5) {
            g_pevm_on = !g_pevm_on;
            printf("加壳 PE 虚拟执行已%s。\n", g_pevm_on ? "开启（推荐）" : "关闭");
        } else if (c == 6) {
            break;
        } else {
            printf("无效的选项。\n");
        }
    }
    return 0;
}
