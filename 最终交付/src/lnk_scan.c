/* lnk_scan.c -- LNK 快捷方式启发式扫描
 *
 * 背景：国内 U 盘蠕虫 / 桌面推广常用 .lnk 伪装成文件夹或文档，
 *       实际指向 cmd.exe / powershell 等解释器并携带恶意参数。
 *       本模块按 Shell Link 格式解析（MS-SHLLINK），再做关键词打分。
 * 解析三级：
 *   1) LinkInfo 的 LocalBasePath(+CommonPathSuffix) —— 最准确的目标路径；
 *   2) StringData 段（Name/RelativePath/WorkingDir/Arguments/IconLocation，
 *      按 IsUnicode 标志区分 UTF-16LE / ANSI）；
 *   3) 全文扫描宽字符与 ANSI 字符串作为兜底（严格筛选目标候选）。
 */
#include "lnk_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int rd_u16(const unsigned char *b, long size, long off, unsigned *v) {
    if (off < 0 || off + 2 > size) return 0;
    *v = (unsigned)b[off] | ((unsigned)b[off + 1] << 8);
    return 1;
}

static int rd_u32(const unsigned char *b, long size, long off, unsigned *v) {
    if (off < 0 || off + 4 > size) return 0;
    *v = (unsigned)b[off] | ((unsigned)b[off + 1] << 8) |
         ((unsigned)b[off + 2] << 16) | ((unsigned)b[off + 3] << 24);
    return 1;
}

int is_lnk_buf(const unsigned char *buf, long size) {
    static const unsigned char guid[16] = {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };
    if (!buf || size < 76) return 0;
    if (buf[0] != 0x4C || buf[1] != 0 || buf[2] != 0 || buf[3] != 0) return 0;
    return memcmp(buf + 4, guid, 16) == 0;
}

static void utf16_to_asc(const unsigned char *buf, long size, long off,
                         unsigned cnt, char *out, int outlen) {
    int j = 0;
    unsigned i;
    for (i = 0; i < cnt && j < outlen - 1; i++) {
        long p = off + (long)i * 2;
        unsigned wc;
        char c;
        if (!rd_u16(buf, size, p, &wc)) break;
        if (wc >= 32 && wc < 127) c = (char)wc;
        else if (wc == 9 || wc == 10 || wc == 13) c = ' ';
        else c = '?';
        out[j++] = c;
    }
    out[j] = '\0';
}

/* 以 NUL 结尾的 UTF-16LE 字符串（上限 outlen） */
static void utf16_cstr(const unsigned char *buf, long size, long off,
                       char *out, int outlen) {
    int j = 0;
    long p = off;
    while (j < outlen - 1) {
        unsigned wc;
        if (!rd_u16(buf, size, p, &wc)) break;
        if (wc == 0) break;
        out[j++] = (wc >= 32 && wc < 127) ? (char)wc : '?';
        p += 2;
    }
    out[j] = '\0';
}

/* 以 NUL 结尾的 ANSI 字符串（上限 outlen） */
static void ansi_cstr(const unsigned char *buf, long size, long off,
                      char *out, int outlen) {
    int j = 0;
    long p = off;
    while (j < outlen - 1 && p < size) {
        unsigned char c = buf[p++];
        if (c == 0) break;
        out[j++] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    out[j] = '\0';
}

static void lower_str(const char *src, char *dst, int dstlen) {
    int i = 0;
    for (; src[i] && i < dstlen - 1; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

/* 字符串是否以可执行/脚本/快捷方式后缀结尾（允许结尾有引号或空格） */
static int ends_with_exec_ext(const char *s) {
    static const char *exts[] = { ".exe", ".com", ".bat", ".cmd", ".ps1",
                                  ".vbs", ".vbe", ".js", ".jse", ".hta",
                                  ".lnk", ".msi", ".scr", NULL };
    int n = (int)strlen(s);
    int i;
    while (n > 0 && (s[n - 1] == '"' || s[n - 1] == ' ')) n--;
    for (i = 0; exts[i]; i++) {
        int el = (int)strlen(exts[i]);
        if (n >= el && _strnicmp(s + n - el, exts[i], (size_t)el) == 0)
            return 1;
    }
    return 0;
}

/* 是否像路径：含反斜杠，或盘符开头（X:） */
static int looks_like_path(const char *s) {
    int i, n = (int)strlen(s);
    for (i = 0; i < n; i++)
        if (s[i] == '\\') return 1;
    if (n >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':')
        return 1;
    return 0;
}

/* 全文收集字符串（UTF-16LE + ANSI），拼接进 blob；严格筛选第一个目标候选 */
static void collect_strings(const unsigned char *buf, long size,
                            char *blob, int bloblen,
                            char *target, int targetlen) {
    int j = 0;
    long i = 0;
    if (target && targetlen > 0) target[0] = '\0';
    if (bloblen > 0) blob[0] = '\0';

#define COLLECT_ONE(tmp, k) do { \
        if (k >= 4) { \
            if (j + (k) + 2 <= bloblen) { \
                memcpy(blob + j, tmp, (size_t)(k)); \
                j += (k); blob[j++] = ' '; blob[j] = '\0'; \
            } \
            if (target && targetlen > 1 && target[0] == '\0' && (k) >= 5) { \
                char lowc[512]; \
                lower_str(tmp, lowc, sizeof(lowc)); \
                if (ends_with_exec_ext(lowc) && looks_like_path(tmp)) \
                    snprintf(target, (size_t)targetlen, "%s", tmp); \
            } \
        } \
    } while (0)

    /* 1) UTF-16LE 可打印串 */
    while (i + 1 < size && j < bloblen - 2) {
        unsigned char c = buf[i];
        if (c >= 32 && c < 127 && buf[i + 1] == 0) {
            char tmp[512];
            int k = 0;
            while (i + 1 < size && k < 511) {
                unsigned char d = buf[i];
                if (!(d >= 32 && d < 127) || buf[i + 1] != 0) break;
                tmp[k++] = (char)d;
                i += 2;
            }
            tmp[k] = '\0';
            COLLECT_ONE(tmp, k);
        } else {
            i += 1;
        }
    }

    /* 2) ANSI 可打印串（LinkInfo 路径、ANSI 参数等） */
    i = 0;
    while (i < size && j < bloblen - 2) {
        unsigned char c = buf[i];
        if (c >= 32 && c < 127) {
            char tmp[512];
            int k = 0;
            while (i < size && k < 511) {
                unsigned char d = buf[i];
                if (d < 32 || d >= 127) break;
                tmp[k++] = (char)d;
                i += 1;
            }
            tmp[k] = '\0';
            COLLECT_ONE(tmp, k);
        } else {
            i += 1;
        }
    }
#undef COLLECT_ONE
}

/* 读取 StringData 段（unicode=1 时 UTF-16LE，否则 ANSI），推进 *cur */
static void read_str_section(const unsigned char *buf, long size, long *cur,
                             int unicode, char *out, int outlen) {
    unsigned cnt;
    if (outlen > 0) out[0] = '\0';
    if (!rd_u16(buf, size, *cur, &cnt)) { *cur = size; return; }
    if (unicode) {
        utf16_to_asc(buf, size, *cur + 2, cnt, out, outlen);
        *cur += 2 + (long)cnt * 2;
    } else {
        int j = 0;
        unsigned i;
        for (i = 0; i < cnt && j < outlen - 1; i++) {
            long p = *cur + 2 + (long)i;
            if (p >= size) break;
            {
                unsigned char c = buf[p];
                out[j++] = (c >= 32 && c < 127) ? (char)c : '?';
            }
        }
        out[j] = '\0';
        *cur += 2 + (long)cnt;
    }
}

/* 解析 LinkInfo 得到最准确的目标路径（ANSI 与 Unicode 两种变体） */
static void parse_linkinfo_target(const unsigned char *buf, long size, long li,
                                  unsigned li_size, char *out, int outlen) {
    unsigned hdr_size = 0, li_flags = 0;
    char path[768] = {0};
    char suffix[256] = {0};
    int n;

    if (outlen > 0) out[0] = '\0';
    if (li_size < 0x1C || li + (long)li_size > size) return;
    rd_u32(buf, size, li + 4, &hdr_size);
    rd_u32(buf, size, li + 8, &li_flags);
    if (!(li_flags & 0x1)) return;          /* 无 VolumeIDAndLocalBasePath */

    /* Unicode 变体（LinkInfoHeaderSize >= 0x24） */
    if (hdr_size >= 0x24) {
        unsigned ubase = 0, usuf = 0;
        rd_u32(buf, size, li + 28, &ubase);
        rd_u32(buf, size, li + 32, &usuf);
        if (ubase > 0 && ubase < li_size)
            utf16_cstr(buf, size, li + (long)ubase, path, sizeof(path));
        if (usuf > 0 && usuf < li_size)
            utf16_cstr(buf, size, li + (long)usuf, suffix, sizeof(suffix));
    }
    /* ANSI 变体 */
    if (!path[0]) {
        unsigned base_off = 0, suf_off = 0;
        rd_u32(buf, size, li + 16, &base_off);
        rd_u32(buf, size, li + 24, &suf_off);
        if (base_off > 0 && base_off < li_size)
            ansi_cstr(buf, size, li + (long)base_off, path, sizeof(path));
        if (suf_off > 0 && suf_off < li_size)
            ansi_cstr(buf, size, li + (long)suf_off, suffix, sizeof(suffix));
    }

    snprintf(out, (size_t)outlen, "%s%s", path, suffix);
    /* 去掉结尾的引号/空格（WScript 会遗留 CommonPathSuffix 引号） */
    n = (int)strlen(out);
    while (n > 0 && (out[n - 1] == '"' || out[n - 1] == ' ')) out[--n] = '\0';
}

int lnk_scan_buf(const unsigned char *buf, long size,
                 double *score, char *details, int details_len,
                 char *caro_name, int caro_len,
                 char *target, int target_len,
                 char *args_out, int args_len) {
    char rel[512] = {0}, nm[256] = {0}, wdir[512] = {0};
    char args[512] = {0}, icon[512] = {0};
    char linktarget[768] = {0};
    char blob[8192] = {0}, blobtarget[512] = {0};
    char tgt[1024] = {0}, targ[2048] = {0};
    char fold[16384];
    char a1[512];
    unsigned flags = 0;
    long cur;
    long lnk_start;
    int unicode;
    int fj = 0;
    int part;
    int nh = 0;
    int hitw[64];
    const char *hitl[64];
    double total = 0.0;
    int t_cmd, t_ps, t_host, t_browser, t_explorer;
    int url_hit, start_hit, ext_hit;

    if (details && details_len > 0) details[0] = '\0';
    if (caro_name && caro_len > 0) caro_name[0] = '\0';
    if (target && target_len > 0) target[0] = '\0';
    if (args_out && args_len > 0) args_out[0] = '\0';
    if (!is_lnk_buf(buf, size)) return -1;

    /* ---- 头部 ---- */
    rd_u32(buf, size, 0x14, &flags);
    unicode = (flags & 0x80) ? 1 : 0;
    cur = 76;

    /* 跳过 IDList */
    if (flags & 0x1) {
        unsigned il;
        if (rd_u16(buf, size, cur, &il) && cur + 2 + (long)il <= size)
            cur += 2 + (long)il;
        else
            cur = size;
    }
    /* LinkInfo：先取目标路径，再整体跳过 */
    if (flags & 0x2) {
        unsigned li;
        if (rd_u32(buf, size, cur, &li) && li >= 0x1C && cur + (long)li <= size) {
            lnk_start = cur;
            parse_linkinfo_target(buf, size, lnk_start, li, linktarget, sizeof(linktarget));
            cur += (long)li;
        } else {
            cur = size;
        }
    }
    /* StringData 段（按标志位顺序） */
    if ((flags & 0x4) && cur < size)   read_str_section(buf, size, &cur, unicode, nm, sizeof(nm));
    if ((flags & 0x8) && cur < size)   read_str_section(buf, size, &cur, unicode, rel, sizeof(rel));
    if ((flags & 0x10) && cur < size)  read_str_section(buf, size, &cur, unicode, wdir, sizeof(wdir));
    if ((flags & 0x20) && cur < size)  read_str_section(buf, size, &cur, unicode, args, sizeof(args));
    if ((flags & 0x40) && cur < size)  read_str_section(buf, size, &cur, unicode, icon, sizeof(icon));

    collect_strings(buf, size, blob, sizeof(blob), blobtarget, sizeof(blobtarget));

    /* ---- 折叠小写，供关键词搜索 ---- */
    {
        const char *parts[6];
        parts[0] = rel; parts[1] = nm; parts[2] = wdir;
        parts[3] = args; parts[4] = icon; parts[5] = blob;
        for (part = 0; part < 6; part++) {
            const char *s;
            for (s = parts[part]; *s && fj < (int)sizeof(fold) - 2; s++) {
                fold[fj++] = (char)tolower((unsigned char)*s);
            }
            if (fj < (int)sizeof(fold) - 2) fold[fj++] = ' ';
        }
        fold[fj] = '\0';
    }

    /* ---- 目标程序判定：LinkInfo > 全文候选 > 相对路径 > 名称 ---- */
    if (linktarget[0])     snprintf(tgt, sizeof(tgt), "%s", linktarget);
    else if (blobtarget[0]) snprintf(tgt, sizeof(tgt), "%s", blobtarget);
    else if (rel[0])        snprintf(tgt, sizeof(tgt), "%s", rel);
    else if (nm[0])         snprintf(tgt, sizeof(tgt), "%s", nm);

    lower_str(tgt, a1, sizeof(a1));
    snprintf(targ, sizeof(targ), "%s", a1);
    lower_str(rel, a1, sizeof(a1));
    strncat(targ, " ", sizeof(targ) - strlen(targ) - 1);
    strncat(targ, a1, sizeof(targ) - strlen(targ) - 1);
    lower_str(nm, a1, sizeof(a1));
    strncat(targ, " ", sizeof(targ) - strlen(targ) - 1);
    strncat(targ, a1, sizeof(targ) - strlen(targ) - 1);

    t_cmd      = strstr(targ, "cmd.exe") != NULL || strstr(targ, "%comspec%") != NULL;
    t_ps       = strstr(targ, "powershell") != NULL || strstr(targ, "pwsh") != NULL;
    t_host     = strstr(targ, "wscript") != NULL || strstr(targ, "cscript") != NULL ||
                 strstr(targ, "mshta") != NULL || strstr(targ, "rundll32") != NULL ||
                 strstr(targ, "regsvr32") != NULL;
    t_browser  = strstr(targ, "iexplore") != NULL || strstr(targ, "chrome") != NULL ||
                 strstr(targ, "msedge") != NULL || strstr(targ, "firefox") != NULL ||
                 strstr(targ, "360se") != NULL || strstr(targ, "qqbrowser") != NULL ||
                 strstr(targ, "sogouexplorer") != NULL || strstr(targ, "ucbrowser") != NULL ||
                 strstr(targ, "quark") != NULL;
    t_explorer = strstr(targ, "explorer.exe") != NULL;

    url_hit   = strstr(fold, "http://") != NULL || strstr(fold, "https://") != NULL ||
                strstr(fold, "www.") != NULL;
    start_hit = strstr(fold, "start ") != NULL;
    ext_hit   = strstr(fold, ".vbs") != NULL || strstr(fold, ".bat") != NULL ||
                strstr(fold, ".cmd") != NULL || strstr(fold, ".ps1") != NULL ||
                strstr(fold, ".hta") != NULL || strstr(fold, ".jse") != NULL ||
                strstr(fold, ".vbe") != NULL || strstr(fold, ".js") != NULL;

    /* ---- 打分 ---- */
#define ADDRULE(w, lbl) do { \
        total += (double)(w); \
        if (nh < 64) { hitw[nh] = (w); hitl[nh] = (lbl); nh++; } \
    } while (0)

    if (t_cmd)                          ADDRULE(40, "目标为cmd.exe");
    if (t_ps)                           ADDRULE(45, "目标为PowerShell");
    if (t_host)                         ADDRULE(35, "目标为脚本宿主");
    if (t_browser)                      ADDRULE(10, "目标为浏览器");
    if (t_explorer)                     ADDRULE(5,  "目标为explorer");
    if (url_hit)                        ADDRULE(25, "含URL");
    if (url_hit && start_hit)           ADDRULE(20, "start打开URL");
    if (ext_hit)                        ADDRULE(25, "含脚本文件");
    if (strstr(fold, "-enc") || strstr(fold, "encodedcommand") ||
        strstr(fold, "frombase64"))    ADDRULE(35, "编码命令");
    if (strstr(fold, "hidden"))         ADDRULE(10, "隐藏窗口关键词");
    if (strstr(fold, "%temp%") || strstr(fold, "%appdata%") ||
        strstr(fold, "\\temp\\"))       ADDRULE(10, "临时目录");
    if (strstr(fold, "\\\\"))           ADDRULE(10, "UNC路径");

    if (total > 100.0) total = 100.0;

    /* ---- details：取权重最大的前 6 项 ---- */
    if (details && details_len > 0 && nh > 0) {
        int sel[6];
        int scount = 0;
        int used[64] = {0};
        int r, i, pos, best;
        for (r = 0; r < 6 && r < nh; r++) {
            best = -1;
            for (i = 0; i < nh; i++) {
                if (used[i]) continue;
                if (best < 0 || hitw[i] > hitw[best]) best = i;
            }
            if (best < 0) break;
            used[best] = 1;
            sel[scount++] = best;
        }
        pos = 0;
        for (i = 0; i < scount && pos < details_len - 1; i++) {
            pos += snprintf(details + pos, (size_t)(details_len - pos),
                            "%s%s(+%d)", (i > 0) ? "; " : "",
                            hitl[sel[i]], hitw[sel[i]]);
            if (pos < 0) { pos = 0; break; }
        }
    }
#undef ADDRULE

    /* ---- 检测名 ---- */
    if (caro_name && caro_len > 0 && total >= 50.0) {
        const char *n = "Trojan.LNK.Generic";
        if (url_hit && (start_hit || t_browser || t_explorer))
            n = "Rogue.LNK.Promotion";
        snprintf(caro_name, (size_t)caro_len, "%s", n);
    }
    if (score) *score = total;
    if (target && target_len > 0) snprintf(target, (size_t)target_len, "%s", tgt);
    if (args_out && args_len > 0) snprintf(args_out, (size_t)args_len, "%s", args);
    return nh;
}

int lnk_scan_file(const char *filepath,
                  double *score, char *details, int details_len,
                  char *caro_name, int caro_len,
                  char *target, int target_len,
                  char *args, int args_len) {
    FILE *fp;
    long fsize;
    unsigned char *buf;
    int r;

    if (details && details_len > 0) details[0] = '\0';
    if (caro_name && caro_len > 0) caro_name[0] = '\0';
    if (target && target_len > 0) target[0] = '\0';
    if (args && args_len > 0) args[0] = '\0';
    if (score) *score = 0.0;

    fp = fopen(filepath, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (2L << 20)) { fclose(fp); return -1; }
    buf = (unsigned char *)malloc((size_t)fsize);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)fsize, fp) != (size_t)fsize) {
        free(buf); fclose(fp); return -1;
    }
    fclose(fp);
    if (!is_lnk_buf(buf, fsize)) { free(buf); return -1; }
    r = lnk_scan_buf(buf, fsize, score, details, details_len,
                     caro_name, caro_len, target, target_len, args, args_len);
    free(buf);
    return r;
}
