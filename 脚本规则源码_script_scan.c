/* script_scan.c -- 脚本类启发式扫描（bat/cmd/ps1/vbs/js/wsf/hta 等文本文件）
 * 思路：脚本没有可训练的 EMBER 特征，采用“规则词表 + 权重累计”启发式评分：
 *         >=80 [HIGH RISK - SCRIPT] / >=50 [SUSPICIOUS] / <50 [NORMAL]
 * 规则表可自由扩充（见 k_rules）。命中类别用于生成 CARO 检测名：
 *   勒索类命中 -> Ransom.Script.Generic；含高危 COM(写文件) -> Trojan.Script.Dropper；
 *   下载/执行类 -> Trojan.Script.Downloader；其余 -> Trojan.Script.Generic
 */
#include "script_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 规则类别（用于归类 CARO 检测名） */
enum {
    CAT_RANSOM = 1, /* 勒索/破坏行为 */
    CAT_EXEC   = 2, /* 下载/远程执行 */
    CAT_COM    = 3, /* VBS/JS 高危 COM 对象（落文件/执行） */
    CAT_PERS   = 4, /* 持久化/系统修改 */
    CAT_OBF    = 5, /* 混淆 */
    CAT_RECON  = 6  /* 侦察 */
};

typedef struct {
    const char *key;    /* 在“折叠文本”（小写 ASCII）中做子串查找 */
    int weight;         /* 命中加分 */
    const char *label;  /* 输出说明 */
    int cat;            /* 类别 */
} ScriptRule;

static const ScriptRule k_rules[] = {
    /* —— 勒索/破坏行为（高权重） —— */
    {"vssadmin delete shadows", 55, "删除卷影备份", CAT_RANSOM},
    {"vssadmin resize shadowstorage", 50, "调整卷影存储", CAT_RANSOM},
    {"wmic shadowcopy delete",     55, "删除卷影(WMI)", CAT_RANSOM},
    {"wbadmin delete catalog",     55, "删除备份目录", CAT_RANSOM},
    {"wbadmin delete systemstatebackup", 50, "删除系统状态备份", CAT_RANSOM},
    {"bcdedit /set {default} recoveryenabled no", 50, "关闭恢复环境", CAT_RANSOM},
    {"bootstatuspolicy ignoreallfailures", 35, "忽略启动失败", CAT_RANSOM},
    {"cipher /w",                  25, "擦除磁盘空闲空间", CAT_RANSOM},
    {"format c:",                  40, "格式化系统盘", CAT_RANSOM},
    {"bootrec /fixmbr",            30, "重写主引导记录", CAT_RANSOM},
    {"diskpart",                   20, "磁盘分区操作", CAT_RANSOM},
    {"wevtutil cl",                35, "清除系统日志", CAT_RANSOM},
    {"schtasks /delete",           20, "删除计划任务", CAT_RANSOM},
    /* —— 下载/远程执行 —— */
    {"powershell -enc",            55, "PowerShell编码命令", CAT_EXEC},
    {"-encodedcommand",            55, "PowerShell编码命令", CAT_EXEC},
    {"certutil -urlcache",         45, "certutil下载", CAT_EXEC},
    {"certutil -decode",           45, "certutil解码", CAT_EXEC},
    {"bitsadmin /transfer",        45, "bitsadmin下载", CAT_EXEC},
    {"mshta http",                 55, "mshta远程执行", CAT_EXEC},
    {"mshta vbscript",             35, "mshta执行脚本", CAT_EXEC},
    {"regsvr32 /s /u /i:http",     55, "regsvr32远程执行", CAT_EXEC},
    {"rundll32 javascript:",       55, "rundll32脚本执行", CAT_EXEC},
    {"downloadstring",             35, "下载字符串", CAT_EXEC},
    {"downloadfile",               35, "下载文件", CAT_EXEC},
    {"new-object net.webclient",   30, "WebClient下载", CAT_EXEC},
    {"frombase64string",           30, "Base64解码", CAT_EXEC},
    {"invoke-expression",          25, "动态执行表达式", CAT_EXEC},
    {"invoke-webrequest",          20, "网络请求(IWR)", CAT_EXEC},
    {"start-bitstransfer",         25, "BITS传输", CAT_EXEC},
    {"xmlhttp",                    30, "XMLHTTP请求", CAT_EXEC},
    {"winhttp",                    15, "WinHTTP请求", CAT_EXEC},
    {"tftp ",                      15, "TFTP传输", CAT_EXEC},
    {"ftp://",                     10, "FTP地址", CAT_EXEC},
    {"http://",                     5, "包含URL", CAT_EXEC},
    {"https://",                    5, "包含URL", CAT_EXEC},
    /* —— 混淆 —— */
    {"fromcharcode",               25, "字符编码构造", CAT_OBF},
    {"chrw(",                      15, "字符构造", CAT_OBF},
    {"chr(",                       10, "字符构造", CAT_OBF},
    {"unescape(",                  15, "unescape解码", CAT_OBF},
    {"string.reverse",             15, "字符串反转", CAT_OBF},
    {"eval(",                      20, "eval动态执行", CAT_OBF},
    {"execute(",                   15, "execute动态执行", CAT_OBF},
    {"execscript",                 25, "execScript执行", CAT_OBF},
    {"%comspec%",                  10, "COMSPEC间接调用", CAT_OBF},
    /* —— 持久化/系统修改 —— */
    {"currentversion\\run",        25, "注册表自启动", CAT_PERS},
    {"schtasks /create",           20, "创建计划任务", CAT_PERS},
    {"sc create",                  20, "创建服务", CAT_PERS},
    {"net user",                   15, "账户操作", CAT_PERS},
    {"net localgroup administrators", 30, "提权到管理员组", CAT_PERS},
    {"net stop",                   10, "停止服务", CAT_PERS},
    {"netsh advfirewall set",      30, "修改防火墙", CAT_PERS},
    {"set-mppreference -disablerealtimemonitoring", 55, "关闭Defender实时防护", CAT_PERS},
    {"add-mppreference -exclusionpath", 30, "添加Defender排除项", CAT_PERS},
    {"taskkill /f /im",            15, "强杀进程", CAT_PERS},
    {"attrib +h",                  10, "隐藏文件", CAT_PERS},
    {"del /f /q",                  10, "强制删除", CAT_PERS},
    {"del /s /q",                  10, "递归强删", CAT_PERS},
    {"rd /s /q",                    8, "递归删目录", CAT_PERS},
    {"%temp%",                      5, "使用临时目录", CAT_PERS},
    {"%appdata%",                   8, "使用AppData目录", CAT_PERS},
    /* —— VBS/JS 高危对象 —— */
    {"wscript.shell",              25, "WScript.Shell对象", CAT_COM},
    {"activexobject",              20, "ActiveX对象", CAT_COM},
    {"createobject",               20, "创建COM对象", CAT_COM},
    {"adodb.stream",               25, "ADODB.Stream写文件", CAT_COM},
    {"savetofile",                 20, "保存文件", CAT_COM},
    {"shell.application",          20, "Shell.Application对象", CAT_COM},
    {"shellexecute",               20, "ShellExecute执行", CAT_COM},
    /* —— 侦察 —— */
    {"whoami",                      5, "用户侦察", CAT_RECON},
    {"systeminfo",                  5, "系统侦察", CAT_RECON},
    {"ipconfig /all",               5, "网络侦察", CAT_RECON},
    {"net view",                   10, "共享侦察", CAT_RECON},
    {"nslookup",                    5, "DNS查询", CAT_RECON},
    {"ping -n",                     5, "延时探测", CAT_RECON},

    /* ===== 2026-10 漏报整改：补充规则 ===== */
    /* —— 执行链 —— */
    {"powershell -",               25, "调用PowerShell", CAT_EXEC},
    {"powershell.exe",             20, "调用PowerShell", CAT_EXEC},
    {"windowstyle hidden",         25, "隐藏窗口执行", CAT_EXEC},
    {"-w hidden",                  25, "隐藏窗口执行", CAT_EXEC},
    {"executionpolicy bypass",     25, "绕过执行策略", CAT_EXEC},
    {"-ep bypass",                 25, "绕过执行策略", CAT_EXEC},
    {"-nop",                       15, "跳过配置加载", CAT_EXEC},
    {"iex(",                       30, "IEX别名执行", CAT_EXEC},
    {"iex $",                      30, "IEX别名执行", CAT_EXEC},
    {"start-process",              15, "启动进程", CAT_EXEC},
    {"-outfile",                   20, "下载并保存文件", CAT_EXEC},
    {"expand-archive",             15, "解压压缩包", CAT_EXEC},
    {"net.webclient",              30, "WebClient网络对象", CAT_EXEC},
    {"downloaddata",               20, "下载数据", CAT_EXEC},
    {"curl -",                     15, "curl下载", CAT_EXEC},
    {"certutil",                   25, "certutil滥用", CAT_EXEC},
    {"extrac32",                   40, "extrac32解压执行", CAT_EXEC},
    {"responsebody",               20, "读取HTTP响应体", CAT_EXEC},
    {"window.location",            10, "页面跳转", CAT_EXEC},
    {"start \"\"",                 10, "启动程序", CAT_EXEC},
    {".run(",                      25, "Shell.Run执行", CAT_EXEC},
    {".exec(",                     25, "Shell.Exec执行", CAT_EXEC},
    /* —— 混淆/编码 —— */
    {"#@~^",                       55, "微软脚本加密(VBE/JSE)", CAT_OBF},
    {"-bxor",                      25, "XOR运算(解密)", CAT_OBF},
    {"[char[]]",                   20, "字符数组构造", CAT_OBF},
    {"[byte[]]",                   10, "字节数组构造", CAT_OBF},
    {"hextostr",                   20, "十六进制字符串解码", CAT_OBF},
    {"sal '",                      20, "别名混淆", CAT_OBF},
    {"set-alias",                  15, "别名定义", CAT_OBF},
    {"&$",                         15, "动态调用命令", CAT_OBF},
    {"77,90,144",                  45, "十进制MZ头(内嵌PE)", CAT_OBF},
    {"del \"%~f0\"",               25, "脚本自删除", CAT_OBF},
    {"%~f0",                       15, "自引用(自解压)", CAT_OBF},
    /* —— 环境侦察/反沙箱 —— */
    {"wmic ",                      10, "WMI查询", CAT_RECON},
    {"wmic computersystem",        20, "系统信息侦察", CAT_RECON},
    {"wmic bios",                  15, "BIOS信息侦察", CAT_RECON},
    {"vmware",                     20, "VMware检测", CAT_RECON},
    {"virtualbox",                 20, "VirtualBox检测", CAT_RECON},
    {"vbox",                       15, "VBox检测", CAT_RECON},
    {"qemu",                       15, "QEMU检测", CAT_RECON},
    {"sandboxie",                  20, "沙箱检测", CAT_RECON},
    {"cuckoo",                     20, "沙箱检测", CAT_RECON},
    /* ===== 2026-10 漏报整改：第二轮 ===== */
    {"davwwwroot",                 55, "远程WebDAV脚本加载", CAT_EXEC},
    {"child_process",              30, "Node子进程执行", CAT_EXEC},
    {"socks5",                     25, "SOCKS5代理隧道", CAT_EXEC},
    {"reverse socks",              30, "反向代理隧道", CAT_EXEC},
    {"mshta",                      20, "mshta调用", CAT_EXEC},
    {"chrw(",                      15, "字符构造(chrw)", CAT_OBF},

    /* ===== 2026-10 第三轮：多级加载链 / 内容伪装 / 代理凭据下载 ===== */
    {"tar -xf",                    15, "tar解压载荷", CAT_EXEC},
    {"unzip",                      10, "unzip解压", CAT_EXEC},
    {"7z x",                       15, "7z解压", CAT_EXEC},
    {"--proxy-negotiate",          20, "代理凭据下载(--proxy-negotiate)", CAT_EXEC},
    {"--proxy-ntlm",               20, "代理NTLM下载(--proxy-ntlm)", CAT_EXEC},
    {"tregsvr",                    30, "BPL插件加载器(TRegSvr)", CAT_EXEC},
    {".bpl",                       15, "BPL插件模块", CAT_EXEC},
    {"start /b",                   10, "后台静默启动", CAT_EXEC},
};
static const int k_rule_count = sizeof(k_rules) / sizeof(k_rules[0]);

/* 极简“折叠”：只保留 ASCII 可打印+常用空白并转小写
 * （顺带兼容 UTF-16：双字节中夹的 0x00 被丢弃后字符自然连起来）
 */
static char *make_folded(const unsigned char *buf, long size, long *out_len) {
    char *f = (char *)malloc((size_t)size + 1);
    if (!f) return NULL;
    long j = 0;
    for (long i = 0; i < size; i++) {
        unsigned char c = buf[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        if ((c >= 32 && c < 127) || c == 9 || c == 10 || c == 13) f[j++] = (char)c;
    }
    f[j] = '\0';
    *out_len = j;
    return f;
}

static int has_long_base64(const unsigned char *buf, long size, long threshold) {
    long run = 0;
    for (long i = 0; i < size; i++) {
        unsigned char c = buf[i];
        int isb64 = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=');
        if (isb64) { if (++run >= threshold) return 1; }
        else run = 0;
    }
    return 0;
}

static int count_hex_escapes(const unsigned char *buf, long size) {
    int cnt = 0;
    for (long i = 0; i + 1 < size; i++) {
        if (buf[i] == '\\' && (buf[i + 1] == 'x' || buf[i + 1] == 'X' ||
                               buf[i + 1] == 'u' || buf[i + 1] == 'U')) cnt++;
    }
    return cnt;
}

static int has_long_line(const unsigned char *buf, long size, long threshold) {
    long cur = 0;
    for (long i = 0; i < size; i++) {
        if (buf[i] == '\n' || buf[i] == '\r') cur = 0;
        else if (++cur >= threshold) return 1;
    }
    return 0;
}

static int count_substr(const unsigned char *buf, long size, const char *needle) {
    size_t nl = strlen(needle);
    int cnt = 0;
    if (nl == 0 || size < (long)nl) return 0;
    for (long i = 0; i <= size - (long)nl; i++) {
        if (memcmp(buf + i, needle, nl) == 0) { cnt++; i += (long)nl - 1; }
    }
    return cnt;
}

/* 长十六进制字符串（十六进制负载，如 $hex='dd27...' / HexToString 载荷） */
static int has_long_hex(const unsigned char *buf, long size, long threshold) {
    long run = 0;
    for (long i = 0; i < size; i++) {
        unsigned char c = buf[i];
        int ishex = ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        if (ishex) { if (++run >= threshold) return 1; }
        else run = 0;
    }
    return 0;
}

/* 非 ASCII 占比过高：Unicode 怪字符拼接混淆（恶意文本脚本常见手法） */
static int non_ascii_ratio_high(const unsigned char *buf, long size) {
    if (size < 8192) return 0;
    long na = 0;
    for (long i = 0; i < size; i++) if (buf[i] >= 128) na++;
    return (na * 100 >= size * 70);
}

/* 指定大小门槛下的非 ASCII 占比判断（用于超大脚本的 Unicode 填充混淆） */
static int non_ascii_pct_ge(const unsigned char *buf, long size, long minsize, int pct) {
    if (size < minsize) return 0;
    long na = 0;
    for (long i = 0; i < size; i++) if (buf[i] >= 128) na++;
    return (na * 100 >= size * (long)pct);
}

int is_script_buf(const unsigned char *buf, long size) {
    if (!buf || size < 4) return 0;
    /* 排除已知二进制格式 */
    if (buf[0] == 'M' && buf[1] == 'Z') return 0;
    if (size >= 4 && memcmp(buf, "PK\x03\x04", 4) == 0) return 0;
    if (size >= 4 && memcmp(buf, "Rar!", 4) == 0) return 0;
    if (size >= 6 && memcmp(buf, "7z\xBC\xAF\x27\x1C", 6) == 0) return 0;
    if (buf[0] == 0x1F && buf[1] == 0x8B) return 0;
    if (size >= 4 && memcmp(buf, "%PDF", 4) == 0) return 0;
    if (size >= 4 && memcmp(buf, "\x89PNG", 4) == 0) return 0;
    if (size >= 4 && memcmp(buf, "\x7f" "ELF", 4) == 0) return 0;
    if (size >= 262 && memcmp(buf + 257, "ustar", 5) == 0) return 0;

    int utf16bom = (size >= 2 && ((buf[0] == 0xFF && buf[1] == 0xFE) ||
                                  (buf[0] == 0xFE && buf[1] == 0xFF)));
    long n = size > (1L << 20) ? (1L << 20) : size; /* 判定只看前 1MB */
    long printable = 0;
    for (long i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if ((c >= 32 && c < 127) || c == 9 || c == 10 || c == 13 || c >= 128) printable++;
    }
    if (utf16bom) return 1;
    if (printable * 100 >= n * 90) return 1;
    /* 无 BOM 的 UTF-16 猜测：零字节约占三成且多在奇数位 */
    long zeros = 0;
    for (long i = 0; i < n; i++) if (buf[i] == 0) zeros++;
    if (zeros * 10 >= n * 3) {
        long oddtot = 0, oddzero = 0;
        for (long i = 1; i < n; i += 2) { oddtot++; if (buf[i] == 0) oddzero++; }
        if (oddtot && oddzero * 100 >= oddtot * 80) return 1;
    }
    return 0;
}

int script_scan_buf(const unsigned char *buf, long size, double *score, char *details, int details_len, char *caro_name, int caro_len) {
    long scanlen = size > (8L << 20) ? (8L << 20) : size;
    long flen = 0;
    char *fold = make_folded(buf, scanlen, &flen);
    if (!fold) {
        if (score) *score = 0;
        if (details && details_len > 0) details[0] = '\0';
        if (caro_name && caro_len > 0) caro_name[0] = '\0';
        return 0;
    }

    double total = 0.0;
    int hits = 0;
    int has_ransom = 0, has_exec = 0, has_com = 0, has_obf = 0;
    int hitw[64];
    const char *hitl[64];
    int nh = 0;

    for (int i = 0; i < k_rule_count; i++) {
        if (strstr(fold, k_rules[i].key)) {
            total += k_rules[i].weight;
            hits++;
            if (k_rules[i].cat == CAT_RANSOM) has_ransom = 1;
            else if (k_rules[i].cat == CAT_EXEC) has_exec = 1;
            else if (k_rules[i].cat == CAT_COM) has_com = 1;
            else if (k_rules[i].cat == CAT_OBF) has_obf = 1;
            if (nh < 64) { hitw[nh] = k_rules[i].weight; hitl[nh] = k_rules[i].label; nh++; }
        }
    }
    int rndcnt = count_substr((const unsigned char *)fold, flen, "%random%");
    int chrcnt = count_substr((const unsigned char *)fold, flen, "chr(");
    int hx = count_hex_escapes(buf, scanlen);
    int has_b64 = has_long_base64(buf, scanlen, 200);
    int has_hexblob = has_long_hex(buf, scanlen, 200);
    int long_line = has_long_line(buf, scanlen, 3000);
    int nonascii = non_ascii_ratio_high(buf, scanlen);
    int big1 = (size >= (1L << 20));
    int big2 = (size >= (128L << 10));
    int uni2 = non_ascii_pct_ge(buf, size, (256L << 10), 25);

    /* 多级加载链的三要素（下载 / 解压 / 执行），以及"从临时目录拉起脚本"形态 */
    int dl_x = 0, ex_x = 0, run_x = 0, tmp_run = 0;
    if (strstr(fold, "curl -") || strstr(fold, "-outfile") || strstr(fold, "downloadstring") ||
        strstr(fold, "downloadfile") || strstr(fold, "downloaddata") || strstr(fold, "invoke-webrequest") ||
        strstr(fold, "bitsadmin /transfer") || strstr(fold, "certutil -urlcache") ||
        strstr(fold, "certutil -decode") || strstr(fold, "new-object net.webclient") ||
        strstr(fold, "net.webclient") || strstr(fold, "xmlhttp") || strstr(fold, "winhttp")) dl_x = 1;
    if (strstr(fold, "tar -xf") || strstr(fold, "expand-archive") || strstr(fold, "extrac32") ||
        strstr(fold, "unzip") || strstr(fold, "7z x")) ex_x = 1;
    if (strstr(fold, "start /b") || strstr(fold, "start \"\"") || strstr(fold, "start-process") ||
        strstr(fold, ".run(") || strstr(fold, ".exec(") || strstr(fold, "iex(") ||
        strstr(fold, "iex $") || strstr(fold, "mshta") || strstr(fold, "rundll32") ||
        strstr(fold, "regsvr32") || strstr(fold, "tregsvr") || strstr(fold, "call ")) run_x = 1;
    if ((strstr(fold, ".run(") || strstr(fold, ".exec(")) &&
        (strstr(fold, "\\temp\\") || strstr(fold, "%temp%") || strstr(fold, "\\appdata\\"))) tmp_run = 1;

    /* “eval 塔”族指纹：把全局 eval 用 \uXXXX 转义藏起来，再用 (0,this)[...] 间接调用。
     * 形态如 (0,this)["\u0065"+"\u0076\u0061\u006c"]("<下一层密文>")。
     * 正常代码几乎不会用“逗号表达式取全局 this，再取属性做调用”这种写法，
     * 配上大量转义，就是作者在刻意对抗静态分析。
     * （样本集里 ff587b56…js / 9ed811ef…js 即此族，静态侧只看得见“一堆转义”，）
     * （真实功能全在里层——所以这条指纹的意义是：看到它就该上脚本虚拟沙盒。） */
    int ind_global = (strstr(fold, "(0,this)[") != NULL) || (strstr(fold, "(0, this)[") != NULL);
    free(fold);

    if (has_b64) {
        total += 35; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 35; hitl[nh] = "长Base64串"; nh++; }
    }
    if (has_hexblob) {
        total += 35; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 35; hitl[nh] = "十六进制负载"; nh++; }
    }
    if (hx >= 200) {
        total += 45; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 45; hitl[nh] = "大量转义混淆"; nh++; }
    } else if (hx >= 30) {
        total += 35; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 35; hitl[nh] = "十六进制转义混淆"; nh++; }
    } else if (hx >= 10) {
        total += 10; hits++;
        if (nh < 64) { hitw[nh] = 10; hitl[nh] = "十六进制转义"; nh++; }
    }
    /* eval 塔：间接调用全局 eval（配合整篇转义）——变形脚本的固定指纹 */
    if (ind_global && hx >= 100) {
        total += 45; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 45; hitl[nh] = "eval塔(转义+间接调用)"; nh++; }
    } else if (ind_global) {
        total += 25; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 25; hitl[nh] = "间接调用全局函数"; nh++; }
    }
    if (chrcnt >= 10) {
        total += 25; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 25; hitl[nh] = "大量Chr字符构造"; nh++; }
    }
    if (long_line) {
        total += 15; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 15; hitl[nh] = "超长单行"; nh++; }
    }
    if (nonascii) {
        total += 50; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 50; hitl[nh] = "Unicode字符混淆"; nh++; }
    }
    if (big1) {
        total += 30; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 30; hitl[nh] = "超大脚本文件"; nh++; }
    } else if (big2) {
        total += 15; hits++;
        if (nh < 64) { hitw[nh] = 15; hitl[nh] = "较大脚本文件"; nh++; }
    }
    if (uni2) {
        total += 35; hits++; has_obf = 1;
        if (nh < 64) { hitw[nh] = 35; hitl[nh] = "超大Unicode填充混淆"; nh++; }
    }
    if (rndcnt >= 2) {
        total += 10; hits++;
        if (nh < 64) { hitw[nh] = 10; hitl[nh] = "随机变量混淆"; nh++; }
    }

    /* 组合加权：同时具备“载荷落地”+“执行”+“混淆”，典型投递器
     * （加“混淆”条件，避免把正常管理脚本里的 ShellExecute+Start-Process 误报） */
    if (has_com && has_exec && has_obf) {
        total += 15; hits++;
        if (nh < 64) { hitw[nh] = 15; hitl[nh] = "落地+执行组合"; nh++; }
    }
    if (has_obf && has_exec) {
        total += 10; hits++;
        if (nh < 64) { hitw[nh] = 10; hitl[nh] = "混淆+执行组合"; nh++; }
    }
    /* 下载 → 解压 → 执行：三段齐全才是"多级加载链"，单独任何一段都不给分，
     * 以免把正常"从网上装个工具"的安装脚本误升为高危 */
    if (dl_x && ex_x && run_x) {
        total += 25; hits++;
        if (nh < 64) { hitw[nh] = 25; hitl[nh] = "下载→解压→执行 多级加载链"; nh++; }
    }
    /* 用 .Run/.Exec 直接拉起临时/AppData 目录里的脚本：小体积 VBS/JS 投递器的典型形态 */
    if (tmp_run) {
        total += 15; hits++;
        if (nh < 64) { hitw[nh] = 15; hitl[nh] = "从临时目录执行脚本"; nh++; }
    }

    if (total > 100.0) total = 100.0;
    if (score) *score = total;

    /* CARO 检测名（得分 >= 50 才输出） */
    if (caro_name && caro_len > 0) {
        caro_name[0] = '\0';
        if (total >= 50.0) {
            const char *n = "Trojan.Script.Generic";
            if (has_ransom) n = "Ransom.Script.Generic";
            else if (has_com) n = "Trojan.Script.Dropper";
            else if (has_exec) n = "Trojan.Script.Downloader";
            strncpy(caro_name, n, caro_len - 1);
            caro_name[caro_len - 1] = '\0';
        }
    }

    if (details && details_len > 0) {
        details[0] = '\0';
        /* 按权重降序插入排序，输出前 6 条 */
        for (int a = 1; a < nh; a++) {
            int kw = hitw[a]; const char *kl = hitl[a];
            int b = a - 1;
            while (b >= 0 && hitw[b] < kw) { hitw[b + 1] = hitw[b]; hitl[b + 1] = hitl[b]; b--; }
            hitw[b + 1] = kw; hitl[b + 1] = kl;
        }
        int used = 0;
        int cap = nh > 6 ? 6 : nh;
        for (int a = 0; a < cap; a++) {
            int wr = snprintf(details + used, (size_t)(details_len - used), "%s%s(+%d)",
                              a ? "; " : "", hitl[a], hitw[a]);
            if (wr < 0 || used + wr >= details_len) break;
            used += wr;
        }
    }
    return hits;
}

/* 文本脚本常见扩展名（用于识别“伪装成脚本的自解压包”等） */
static int is_script_ext(const char *filepath) {
    static const char *exts[] = { ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
                                  ".jse", ".wsf", ".wsh", ".hta", NULL };
    size_t n = strlen(filepath);
    for (int i = 0; exts[i]; i++) {
        size_t el = strlen(exts[i]);
        if (n >= el && _stricmp(filepath + n - el, exts[i]) == 0) return 1;
    }
    return 0;
}

/* 文件是否以某扩展名结尾（大小写不敏感） */
static int has_ext_of(const char *filepath, const char *ext) {
    size_t n = strlen(filepath), el = strlen(ext);
    return (n >= el && _stricmp(filepath + n - el, ext) == 0);
}

/* 正文是不是典型 cmd/bat 批处理（识别"扩展名与内容不符"的换壳伪装）：
 * 批处理特征累计 >=3，且不含 PowerShell / VBScript 特有语法才算。 */
static int looks_like_batch(const unsigned char *buf, long size) {
    long n = size > (1L << 20) ? (1L << 20) : size;
    long fl = 0;
    char *f = make_folded(buf, n, &fl);
    if (!f) return 0;
    int bs = 0;
    if (strstr(f, "@echo off"))                                                 bs += 2;
    if (strstr(f, "for /f"))                                                    bs += 2;
    if (strstr(f, ">nul 2>&1"))                                                 bs += 1;
    if (strstr(f, "%~dp0") || strstr(f, "%~f0"))                                bs += 1;
    if (strstr(f, "if exist"))                                                  bs += 1;
    if (strstr(f, "%appdata%") || strstr(f, "%temp%") || strstr(f, "%comspec%")) bs += 1;
    if (strstr(f, "set /p") || strstr(f, "goto ") || strstr(f, "del /q"))        bs += 1;
    int ps  = (strstr(f, "$env:") || strstr(f, "[convert]") || strstr(f, "new-object") ||
               strstr(f, "write-host") || strstr(f, "param(") || strstr(f, "set-variable"));
    int vbs = (strstr(f, "wscript") || strstr(f, "createobject") || strstr(f, "vbscript"));
    free(f);
    return (bs >= 3 && !ps && !vbs);
}

int script_scan_file(const char *filepath, double *score, char *details, int details_len, char *caro_name, int caro_len) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (64L << 20)) { fclose(fp); return -1; }
    unsigned char *buf = (unsigned char *)malloc((size_t)fsize);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)fsize, fp) != (size_t)fsize) { free(buf); fclose(fp); return -1; }
    fclose(fp);

    /* 自解压 CAB 伪装的脚本（MSCF 头）：典型投毒手法
     * 内容形如：cls && extrac32 /y "%~f0" "%tmp%\x.exe" && start "" "%tmp%\x.exe" */
    if (fsize >= 4 && memcmp(buf, "MSCF", 4) == 0 && is_script_ext(filepath)) {
        if (score) *score = 90.0;
        if (details && details_len > 0)
            snprintf(details, details_len, "自解压CAB伪装为脚本(extrac32/内嵌落地执行)");
        if (caro_name && caro_len > 0)
            snprintf(caro_name, caro_len, "Trojan.Script.SelfExtract");
        free(buf);
        return 1;
    }

    int r;
    if (!is_script_buf(buf, fsize)) r = -1;
    else r = script_scan_buf(buf, fsize, score, details, details_len, caro_name, caro_len);

    /* 扩展名与内容不符：挂着 .ps1/.vbs/.js/.hta… 的壳，正文其实是 cmd/bat 批处理。
     * 正常人不会这么写，而"只看扩展名"的检查会直接放过 —— 属换壳规避，+30。 */
    if (r >= 0 && score && !has_ext_of(filepath, ".bat") && !has_ext_of(filepath, ".cmd")) {
        if (looks_like_batch(buf, fsize)) {
            *score += 30.0;
            if (*score > 100.0) *score = 100.0;
            if (details && details_len > 0) {
                size_t dl = strlen(details);
                if (dl + 40 < (size_t)details_len)
                    snprintf(details + dl, (size_t)details_len - dl,
                             "%s扩展名与内容不符(批处理伪装)(+30)", dl ? "; " : "");
            }
            if (caro_name && caro_len > 0 && caro_name[0] == '\0' && *score >= 50.0)
                snprintf(caro_name, caro_len, "Trojan.Script.Dropper");
        }
    }
    free(buf);
    return r;
}
