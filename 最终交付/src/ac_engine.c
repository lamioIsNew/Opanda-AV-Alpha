/* ac_engine.c -- Aho-Corasick 特征码自动机（纯 C 实现）
 *
 * 结构：
 *   · Trie 节点使用 children[256] 指针数组，逐字节跳转，无哈希、无锁；
 *   · fail 指针按 BFS 构建；out 指针直接跳到最近的"有命中"后缀节点，
 *     扫描时不必沿 fail 链逐个回溯；
 *   · 所有节点指针登记在 g_nodes 中，节点池连续可重分配，ac_free() 逐个
 *     释放，避免 children 被改写后无法遍历回收。
 *
 * 语义（与 signature_scan.c 对齐）：
 *   · 逐字节、大小写敏感、不做 Unicode 归一化；
 *   · 同一模式在库中重复出现时，保留文件行序最靠前的那一条；
 *   · ac_scan_first_match 返回所有命中里行序最小的下标 —— 这正是现有
 *     "first-match-wins" 的语义，接入方按该下标回查元数据即可。
 */
#include "ac_engine.h"

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#pragma warning(disable : 4996)   /* fopen 仅用于读取受控的本地特征库路径 */
#endif

#define AC_CHILDREN 256
#define AC_LINE_MAX 8192
#define AC_MAX_HEX_BYTES 64   /* 与 signature_scan.c 的 hex_pattern[64] 一致 */

typedef struct AcNode {
    struct AcNode *children[AC_CHILDREN];
    struct AcNode *fail;
    struct AcNode *out;   /* 最近的、match_index >= 0 的 fail 祖先 */
    int match_index;      /* -1 = 非终态；否则为 g_pat 下标 */
} AcNode;

typedef struct {
    char *name;
    char *caro;
    int severity;
    unsigned char *bytes;
    size_t len;
} AcPattern;

static AcNode *g_root = NULL;
static AcNode **g_nodes = NULL;
static size_t g_node_count = 0;
static size_t g_node_cap = 0;

static AcPattern *g_pat = NULL;
static size_t g_pat_count = 0;
static size_t g_pat_cap = 0;

/* ---------------- 基础工具 ---------------- */

static char *ac_dup(const char *s) {
    size_t n;
    char *p;
    if (!s) s = "";
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void ac_trim(char *s) {
    size_t n;
    if (!s) return;
    while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
}

static int ac_hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ---------------- 节点池 ---------------- */

static AcNode *ac_new_node(void) {
    AcNode *n = (AcNode *)calloc(1, sizeof(AcNode));
    if (!n) return NULL;
    n->match_index = -1;
    if (g_node_count == g_node_cap) {
        size_t nc = g_node_cap ? g_node_cap * 2 : 256;
        AcNode **np = (AcNode **)realloc(g_nodes, nc * sizeof(AcNode *));
        if (!np) {
            free(n);
            return NULL;
        }
        g_nodes = np;
        g_node_cap = nc;
    }
    g_nodes[g_node_count++] = n;
    return n;
}

/* ---------------- Trie 插入 ---------------- */

static int ac_insert(const unsigned char *pat, size_t len, int index) {
    AcNode *cur = g_root;
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned c = pat[i];
        if (!cur->children[c]) {
            AcNode *n = ac_new_node();
            if (!n) return -1;
            cur->children[c] = n;
        }
        cur = cur->children[c];
    }
    /* 重复模式保留行序更靠前的一条。 */
    if (cur->match_index < 0 || index < cur->match_index)
        cur->match_index = index;
    return 0;
}

/* ---------------- fail / out 指针（BFS） ---------------- */

static int ac_build_fail(void) {
    AcNode **queue;
    size_t head = 0, tail = 0;
    int c;

    if (!g_root || g_node_count == 0) return 0;

    queue = (AcNode **)malloc(g_node_count * sizeof(AcNode *));
    if (!queue) return -1;

    for (c = 0; c < AC_CHILDREN; c++) {
        AcNode *ch = g_root->children[c];
        if (ch) {
            ch->fail = g_root;
            ch->out = NULL;   /* 根节点不是终态 */
            queue[tail++] = ch;
        }
    }

    while (head < tail) {
        AcNode *cur = queue[head++];
        for (c = 0; c < AC_CHILDREN; c++) {
            AcNode *ch = cur->children[c];
            AcNode *f;
            if (!ch) continue;
            f = cur->fail;
            while (f && !f->children[c]) f = f->fail;
            ch->fail = f ? f->children[c] : g_root;
            ch->out = (ch->fail->match_index >= 0) ? ch->fail : ch->fail->out;
            queue[tail++] = ch;
        }
    }

    free(queue);
    return 0;
}

/* ---------------- 扫描 ---------------- */

static int ac_find_first(const uint8_t *buffer, size_t size) {
    AcNode *state;
    int best = -1;
    size_t i;

    if (!g_root || !buffer || size == 0) return -1;

    state = g_root;
    for (i = 0; i < size; i++) {
        unsigned c = buffer[i];
        AcNode *t;

        while (state != g_root && !state->children[c]) state = state->fail;
        if (state->children[c]) state = state->children[c];

        /* state 及其 out 链覆盖了当前位置结束的全部模式。 */
        for (t = state; t; t = t->out) {
            if (t->match_index >= 0 &&
                (best < 0 || t->match_index < best)) {
                best = t->match_index;
                if (best == 0) return 0;   /* 行序最靠前，提前结束 */
            }
        }
    }
    return best;
}

/* ---------------- 生命周期 ---------------- */

void ac_free(void) {
    size_t i;
    for (i = 0; i < g_node_count; i++) free(g_nodes[i]);
    free(g_nodes);
    g_nodes = NULL;
    g_node_count = 0;
    g_node_cap = 0;
    g_root = NULL;

    for (i = 0; i < g_pat_count; i++) {
        free(g_pat[i].name);
        free(g_pat[i].caro);
        free(g_pat[i].bytes);
    }
    free(g_pat);
    g_pat = NULL;
    g_pat_count = 0;
    g_pat_cap = 0;
}

/* 解析一行；成功返回 1，跳过/格式错误返回 0，内存不足返回 -1。 */
static int ac_load_line(char *line, size_t len) {
    char *fields[5];
    char *p = line;
    int nf = 0;
    int is_hex, severity;
    AcPattern pat;
    unsigned char *bytes = NULL;
    size_t blen = 0;
    size_t i;
    char *name, *caro;

    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    if (len >= 3 && (unsigned char)line[0] == 0xEF &&
        (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
        p = line + 3;
    if (!*p || *p == '#') return 0;

    fields[nf++] = p;
    while (*p && nf < 5) {
        if (*p == '\t') {
            *p = '\0';
            p++;
            fields[nf++] = p;
        } else {
            p++;
        }
    }
    if (nf < 5) return 0;
    for (i = 0; i < 4; i++) ac_trim(fields[i]);
    if (!fields[0][0] || !fields[4][0]) return 0;

    is_hex = atoi(fields[1]) ? 1 : 0;
    severity = atoi(fields[2]);
    if (severity <= 0) severity = 100;

    if (is_hex) {
        size_t hl = strlen(fields[4]);
        if (hl == 0 || (hl & 1) || hl / 2 > AC_MAX_HEX_BYTES) return 0;
        blen = hl / 2;
        bytes = (unsigned char *)malloc(blen);
        if (!bytes) return -1;
        for (i = 0; i < blen; i++) {
            int hi = ac_hex_nibble((unsigned char)fields[4][i * 2]);
            int lo = ac_hex_nibble((unsigned char)fields[4][i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                free(bytes);
                return 0;
            }
            bytes[i] = (unsigned char)((hi << 4) | lo);
        }
    } else {
        blen = strlen(fields[4]);
        bytes = (unsigned char *)ac_dup(fields[4]);
        if (!bytes) return -1;
    }

    name = ac_dup(fields[0]);
    caro = ac_dup(fields[3]);
    if (!name || !caro) {
        free(name);
        free(caro);
        free(bytes);
        return -1;
    }

    if (g_pat_count == g_pat_cap) {
        size_t nc = g_pat_cap ? g_pat_cap * 2 : 64;
        AcPattern *np = (AcPattern *)realloc(g_pat, nc * sizeof(AcPattern));
        if (!np) {
            free(name);
            free(caro);
            free(bytes);
            return -1;
        }
        g_pat = np;
        g_pat_cap = nc;
    }

    memset(&pat, 0, sizeof(pat));
    pat.name = name;
    pat.caro = caro;
    pat.severity = severity;
    pat.bytes = bytes;
    pat.len = blen;

    {
        int index = (int)g_pat_count;
        g_pat[g_pat_count++] = pat;
        if (ac_insert(bytes, blen, index) != 0) return -1;
    }
    return 1;
}

/* 把已打开的 db 流加载完并构建自动机；成功返回 0，失败返回 -1（不关闭 fp）。 */
static int ac_init_file(FILE *fp) {
    char line[AC_LINE_MAX];
    int rc = 0;

    g_root = ac_new_node();
    if (!g_root) return -1;

    while (fgets(line, sizeof(line), fp)) {
        int r = ac_load_line(line, strlen(line));
        if (r < 0) {
            rc = -1;
            break;
        }
    }
    if (rc == 0 && ferror(fp)) rc = -1;
    if (rc == 0) rc = ac_build_fail();
    return rc;
}

int ac_init(const char *db_path) {
    FILE *fp;
    ac_free();
    if (!db_path) return -1;

    fp = fopen(db_path, "rb");
    if (!fp) return -1;
    {
        int rc = ac_init_file(fp);
        fclose(fp);
        if (rc != 0) {
            ac_free();
            return -1;
        }
    }
    return 0;
}

#ifdef _WIN32
/* 宽字符入口：项目路径含中文时，fopen 会按 ANSI 代码页解释而失败。 */
int ac_init_w(const wchar_t *db_path) {
    FILE *fp;
    ac_free();
    if (!db_path) return -1;

    fp = _wfopen(db_path, L"rb");
    if (!fp) return -1;
    {
        int rc = ac_init_file(fp);
        fclose(fp);
        if (rc != 0) {
            ac_free();
            return -1;
        }
    }
    return 0;
}
#endif

/* ---------------- 查询接口 ---------------- */

int ac_scan(const uint8_t *buffer, size_t size) {
    return ac_find_first(buffer, size) >= 0 ? 1 : 0;
}

int ac_scan_first_match(const uint8_t *buffer, size_t size, int *out_index) {
    int idx = ac_find_first(buffer, size);
    if (out_index) *out_index = (idx >= 0) ? idx : -1;
    return idx >= 0 ? 1 : 0;
}

int ac_pattern_count(void) {
    return (int)g_pat_count;
}

const char *ac_pattern_name(int index) {
    if (index < 0 || (size_t)index >= g_pat_count) return NULL;
    return g_pat[index].name;
}

const char *ac_pattern_caro(int index) {
    if (index < 0 || (size_t)index >= g_pat_count) return NULL;
    return g_pat[index].caro;
}

int ac_pattern_severity(int index) {
    if (index < 0 || (size_t)index >= g_pat_count) return -1;
    return g_pat[index].severity;
}

static void ac_copy_out(char *dst, size_t cap, const char *src) {
    size_t n;
    if (!dst || cap == 0) return;
    if (!src) src = "";
    n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

int ac_scan_ex(const uint8_t *buffer, size_t size,
               char *matched_name, size_t name_cap,
               int *severity, char *caro, size_t caro_cap) {
    int idx = -1;
    if (!ac_scan_first_match(buffer, size, &idx)) return 0;
    ac_copy_out(matched_name, name_cap, ac_pattern_name(idx));
    ac_copy_out(caro, caro_cap, ac_pattern_caro(idx));
    if (severity) *severity = ac_pattern_severity(idx);
    return 1;
}
