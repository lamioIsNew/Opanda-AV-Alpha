/* verdict_cache.c -- 判决缓存（SHA256 -> 结论）
 *
 * 思路源于火绒 HipsDaemon 的 "duplicate cache hit"：
 * 同一文件重复扫描直接复用旧判决，跳过模型推理与规则匹配。
 */
#include "verdict_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <wincrypt.h>

#define VCACHE_MAX 16384
#define VCACHE_FILE "verdict_cache.txt"

/* 用户要求：不再按缓存“跳过已扫描过的文件”——一律重新分析。
 * 设为 1 可恢复“重复文件复用旧结论”的行为（改规则/模型前务必关闭）。 */
#define VCACHE_ENABLE 0

/* 缓存文件固定写在 exe 所在目录（而不是进程当前工作目录），
 * 避免从受保护文件夹启动时误写 Documents 等位置触发系统拦截 */
static char g_vcache_path[1024] = {0};

static const char *vcache_path(void) {
    if (g_vcache_path[0]) return g_vcache_path;
    {
        char exe[MAX_PATH];
        DWORD n = GetModuleFileNameA(NULL, exe, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            char *p = strrchr(exe, '\\');
            if (p) p[1] = '\0';
            else exe[0] = '\0';
            snprintf(g_vcache_path, sizeof(g_vcache_path), "%s%s", exe, VCACHE_FILE);
        } else {
            snprintf(g_vcache_path, sizeof(g_vcache_path), "%s", VCACHE_FILE);
        }
    }
    return g_vcache_path;
}

typedef struct {
    char sha[65];
    char kind[16];
    double score;
    double entropy;
    char caro[64];
    char bracket[40];
    char ts[24];
} VCacheEntry;

static VCacheEntry *g_entries = NULL;
static int g_count = 0;

static void sanitize(char *s) {
    for (; *s; s++)
        if (*s == '\t' || *s == '\r' || *s == '\n') *s = ' ';
}

int vcache_load(void) {
    FILE *fp;
    char line[512];

    if (!VCACHE_ENABLE) return 0;
    if (g_entries) return g_count;
    g_entries = (VCacheEntry *)calloc(VCACHE_MAX, sizeof(VCacheEntry));
    if (!g_entries) return 0;

    fp = fopen(vcache_path(), "rb");
    if (!fp) return 0;

    while (g_count < VCACHE_MAX && fgets(line, sizeof(line), fp)) {
        char *f[7];
        int nf = 0;
        char *p = line;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (!line[0]) continue;
        f[nf++] = p;
        while (*p && nf < 7) {
            if (*p == '\t') { *p = '\0'; p++; f[nf++] = p; }
            else p++;
        }
        if (nf < 7) continue;
        {
            VCacheEntry *e = &g_entries[g_count];
            snprintf(e->sha, sizeof(e->sha), "%s", f[0]);
            snprintf(e->kind, sizeof(e->kind), "%s", f[1]);
            e->score = atof(f[2]);
            e->entropy = atof(f[3]);
            snprintf(e->caro, sizeof(e->caro), "%s", f[4]);
            snprintf(e->bracket, sizeof(e->bracket), "%s", f[5]);
            snprintf(e->ts, sizeof(e->ts), "%s", f[6]);
            g_count++;
        }
    }
    fclose(fp);
    return g_count;
}

int vcache_lookup(const char *sha, const char *kind, VCacheHit *hit) {
    int i;
    if (!VCACHE_ENABLE) return 0;
    if (!sha || !g_entries) return 0;
    for (i = g_count - 1; i >= 0; i--) {
        if (strcmp(g_entries[i].sha, sha) == 0 &&
            (kind == NULL || strcmp(g_entries[i].kind, kind) == 0)) {
            if (hit) {
                snprintf(hit->kind, sizeof(hit->kind), "%s", g_entries[i].kind);
                hit->score = g_entries[i].score;
                hit->entropy = g_entries[i].entropy;
                snprintf(hit->caro, sizeof(hit->caro), "%s", g_entries[i].caro);
                snprintf(hit->bracket, sizeof(hit->bracket), "%s", g_entries[i].bracket);
                snprintf(hit->ts, sizeof(hit->ts), "%s", g_entries[i].ts);
            }
            return 1;
        }
    }
    return 0;
}

void vcache_add(const char *sha, const char *kind, double score, double entropy,
                const char *caro, const char *bracket) {
    char ts[24];
    time_t t;
    struct tm *lt;
    FILE *fp;
    char c1[64], c2[40];
    VCacheEntry *e;

    if (!VCACHE_ENABLE) return;
    if (!sha || !kind) return;
    if (!g_entries) vcache_load();
    if (!g_entries) return;
    if (g_count >= VCACHE_MAX) return;   /* 满了不再追加，避免文件无限增长 */

    t = time(NULL);
    lt = localtime(&t);
    if (lt) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", lt);
    else ts[0] = '\0';

    e = &g_entries[g_count];
    snprintf(e->sha, sizeof(e->sha), "%s", sha);
    snprintf(e->kind, sizeof(e->kind), "%s", kind);
    e->score = score;
    e->entropy = entropy;
    snprintf(e->caro, sizeof(e->caro), "%s", caro ? caro : "");
    snprintf(e->bracket, sizeof(e->bracket), "%s", bracket ? bracket : "");
    snprintf(e->ts, sizeof(e->ts), "%s", ts);
    g_count++;

    fp = fopen(vcache_path(), "ab");
    if (fp) {
        snprintf(c1, sizeof(c1), "%s", caro ? caro : "");
        snprintf(c2, sizeof(c2), "%s", bracket ? bracket : "");
        sanitize(c1);
        sanitize(c2);
        fprintf(fp, "%s\t%s\t%.2f\t%.4f\t%s\t%s\t%s\n",
                sha, kind, score, entropy, c1, c2, ts);
        fclose(fp);
    }
}

int vcache_sha256_buf(const unsigned char *buf, long len, char hex[65]) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE rgb[32];
    DWORD cb = 32;
    int i;

    if (!hex) return 0;
    hex[0] = '\0';
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    if (len > 0 && !CryptHashData(hHash, buf, (DWORD)len, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgb, &cb, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    for (i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", rgb[i]);
    hex[64] = '\0';
    return 1;
}

int vcache_sha256_file(const char *path, char hex[65]) {
    FILE *fp;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    unsigned char chunk[65536];
    size_t n;
    BYTE rgb[32];
    DWORD cb = 32;
    int i;

    if (!hex) return 0;
    hex[0] = '\0';
    fp = fopen(path, "rb");
    if (!fp) return 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(fp);
        return 0;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        fclose(fp);
        return 0;
    }
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        if (!CryptHashData(hHash, chunk, (DWORD)n, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgb, &cb, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    for (i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", rgb[i]);
    hex[64] = '\0';
    return 1;
}
