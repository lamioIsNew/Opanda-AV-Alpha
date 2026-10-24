/* risk_name.c -- 中文人性化输出辅助（见 risk_name.h） */
#include "risk_name.h"
#include "scan_output.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* 与 scan_main.c 共用同一输出出口；CLI 默认 stdout，DLL 模式关闭 */
#define printf scan_out

/* ---------------- 检测名 -> 中文风险名称 ---------------- */

typedef struct { const char *caro; const char *cn; } RiskExact;

/* 精确匹配优先（覆盖本工具全部内置检测名） */
static const RiskExact exact_map[] = {
    /* LNK 启发式引擎 */
    { "Rogue.LNK.Promotion",       "推广诱骗快捷方式" },
    { "Trojan.LNK.Generic",        "恶意快捷方式" },
    /* 脚本启发式引擎 */
    { "Ransom.Script.Generic",     "勒索软件脚本" },
    { "Trojan.Script.Dropper",     "脚本木马投放器" },
    { "Trojan.Script.Downloader",  "脚本下载器木马" },
    { "Trojan.Script.Generic",     "恶意脚本" },
    /* 特征码 */
    { "Ransom.Win32.Phobos",       "Phobos 勒索软件" },
    /* 机器学习 / 加壳 */
    { "Trojan.Win32.Generic!ml",   "疑似木马" },
    { "RiskWare.Win32.Generic!ml", "疑似风险软件" },
    { "Packed.Win32.Generic",      "加壳程序" },
};

/* 前缀兜底（覆盖未来新增的同类检测名） */
typedef struct { const char *prefix; const char *cn; } RiskPrefix;

static const RiskPrefix prefix_map[] = {
    { "Ransom.",     "勒索软件" },
    { "Trojan.",     "木马程序" },
    { "Backdoor.",   "远控后门木马" },
    { "Worm.",       "蠕虫病毒" },
    { "Virus.",      "感染型病毒" },
    { "PUA.",        "潜在不受欢迎软件" },
    { "Rogue.",      "流氓推广软件" },
    { "RiskWare.",   "风险软件" },
    { "Spyware.",    "间谍软件" },
    { "Downloader.", "下载器木马" },
    { "Dropper.",    "投放器木马" },
    { "HackTool.",   "黑客工具" },
    { "Miner.",      "挖矿木马" },
    { "CoinMiner.",  "挖矿木马" },
    { "Packed.",     "加壳程序" },
};

const char *risk_cn_name(const char *caro) {
    size_t i;
    if (!caro || !caro[0]) return "";
    for (i = 0; i < sizeof(exact_map) / sizeof(exact_map[0]); i++)
        if (strcmp(caro, exact_map[i].caro) == 0) return exact_map[i].cn;
    for (i = 0; i < sizeof(prefix_map) / sizeof(prefix_map[0]); i++) {
        size_t pl = strlen(prefix_map[i].prefix);
        if (strncmp(caro, prefix_map[i].prefix, pl) == 0) return prefix_map[i].cn;
    }
    return "";
}

/* ---------------- 结论括号 -> 中文判定 / 建议 ---------------- */

#define ADV_HIGH   "请勿双击运行！建议立即隔离（压缩打包存放）或删除该文件。"
#define ADV_SUS    "建议谨慎使用：不要随意双击运行；可上传至 VirusTotal 等在线沙箱进一步确认。"
#define ADV_PUA    "该软件可能捆绑推广或篡改浏览器设置，建议卸载或不要安装。"
#define ADV_NORMAL "未发现明显恶意特征，可正常使用；静态扫描不能保证 100% 安全，请保持杀毒软件开启。"
#define ADV_TRUST  "数字签名有效且发布者受信任，可放心使用。"
#define ADV_PACKED "文件内容经过加壳/加密，静态无法看清；如需使用，请先在沙箱中运行观察。"

typedef struct { const char *br; const char *verdict; const char *advice; } VerdictItem;

static const VerdictItem vdb[] = {
    { "[TRUSTED]",               "安全可信 - 数字签名验证通过",         ADV_TRUST  },
    { "[HIGH RISK - SIGNATURE]", "高危 - 恶意文件（特征码命中）",       ADV_HIGH   },
    { "[HIGH RISK - SCRIPT]",    "高危 - 恶意脚本",                     ADV_HIGH   },
    { "[HIGH RISK - LNK]",       "高危 - 恶意快捷方式",                 ADV_HIGH   },
    { "[HIGH RISK]",             "高危 - 疑似恶意文件（机器学习判定）", ADV_HIGH   },
    { "[SUSPICIOUS - PUA]",      "疑似 - 潜在不受欢迎软件（PUA）",      ADV_PUA    },
    { "[SUSPICIOUS - SCRIPT]",   "疑似 - 可疑脚本",                     ADV_SUS    },
    { "[SUSPICIOUS - LNK]",      "疑似 - 可疑快捷方式",                 ADV_SUS    },
    { "[SUSPICIOUS]",            "疑似 - 需要人工确认（机器学习判定）", ADV_SUS    },
    { "[NORMAL]",                "未发现恶意特征",                      ADV_NORMAL },
    { "[PACKED]",                "无法静态判定 - 文件已加壳",           ADV_PACKED },
};

static const VerdictItem *find_verdict(const char *bracket) {
    size_t i;
    if (!bracket) return NULL;
    for (i = 0; i < sizeof(vdb) / sizeof(vdb[0]); i++)
        if (strcmp(bracket, vdb[i].br) == 0) return &vdb[i];
    return NULL;
}

const char *verdict_cn(const char *bracket) {
    const VerdictItem *v = find_verdict(bracket);
    return v ? v->verdict : "已完成分析";
}

const char *advice_cn(const char *bracket) {
    const VerdictItem *v = find_verdict(bracket);
    return v ? v->advice : "请结合其他安全工具进一步判断。";
}

/* ---------------- 路径编码转换 ---------------- */

void path_to_utf8(const char *ansi, char *out, int out_len) {
    wchar_t wbuf[2048];
    int n;
    if (!out || out_len <= 0) return;
    out[0] = '\0';
    if (!ansi) return;
    n = MultiByteToWideChar(CP_ACP, 0, ansi, -1, wbuf, 2048);
    if (n <= 0) {
        snprintf(out, (size_t)out_len, "%s", ansi);   /* 转换失败则原样输出 */
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out, out_len, NULL, NULL);
}

/* ---------------- 结果块排版 ---------------- */

void pr_result_header(const char *name) {
    printf("\n----------------------------------------\n");
    printf("【文件】%s\n", name);
}

void pr_result_end(void) {
    printf("----------------------------------------\n");
}

void pr_line_verdict(const char *bracket) {
    printf("【判定】%s    %s\n", verdict_cn(bracket), bracket ? bracket : "");
}

void pr_line_risk(const char *caro) {
    const char *cn;
    if (!caro || !caro[0]) return;
    cn = risk_cn_name(caro);
    if (cn[0]) printf("【风险名称】%s（%s）\n", cn, caro);
    else       printf("【风险名称】%s\n", caro);
}

void pr_line_advice(const char *bracket) {
    printf("【建议】%s\n", advice_cn(bracket));
}
