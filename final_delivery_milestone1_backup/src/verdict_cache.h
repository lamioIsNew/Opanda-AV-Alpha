#ifndef VERDICT_CACHE_H
#define VERDICT_CACHE_H

/* 判决缓存：SHA256 -> 分析结论，避免重复扫描重复跑模型/规则
 *
 * 缓存文件固定在当前工作目录的 verdict_cache.txt（追加式）。
 * 只缓存三类“需要分析”的结论：MODEL（模型）、SCRIPT（脚本）、LNK（快捷方式）；
 * 特征码/加壳等快速路径不缓存。
 */

typedef struct {
    char kind[16];     /* MODEL / SCRIPT / LNK */
    double score;
    double entropy;
    char caro[64];     /* 检测名（可为空） */
    char bracket[40];  /* 结论括号，如 [HIGH RISK] / [NORMAL] */
    char ts[24];       /* 缓存时间 yyyy-mm-dd hh:mm */
} VCacheHit;

/* 启动时调用一次：载入缓存，返回载入条数 */
int vcache_load(void);
/* 按 SHA256 + 类型查缓存；命中返回 1 并填充 hit */
int vcache_lookup(const char *sha, const char *kind, VCacheHit *hit);
/* 追加一条判决（内存 + 文件） */
void vcache_add(const char *sha, const char *kind, double score, double entropy,
                const char *caro, const char *bracket);
/* SHA256（CryptoAPI），成功返回 1 并输出 64 位十六进制 */
int vcache_sha256_buf(const unsigned char *buf, long len, char hex[65]);
int vcache_sha256_file(const char *path, char hex[65]);

#endif
