#ifndef SIGNATURE_SCAN_H
#define SIGNATURE_SCAN_H

/* 特征码扫描，命中返回 1 并把特征名写入 matched_name；未命中返回 0 */
int signature_scan(const char *filepath, char *matched_name, int max_name_len);

/* 扩展版：额外输出严重度（100=恶意；<100 如 60=PUA）与 CARO 检测名称
 * severity / caro_name 均可为 NULL；caro 形如 Ransom.Win32.Phobos */
int signature_scan_ex(const char *filepath, char *matched_name, int max_name_len, int *severity, char *caro_name, int caro_len);

/* 内存缓冲版特征码扫描（流模式用） */
int signature_scan_buf(const unsigned char *buf, long size, char *matched_name, int max_name_len);

/* 内存缓冲扩展版（严重度 + CARO 检测名，流模式用） */
int signature_scan_buf_ex(const unsigned char *buf, long size, char *matched_name, int max_name_len, int *severity, char *caro_name, int caro_len);

/* ---- 外部特征库（signatures.db，UTF-8 文本，一行一条）----
 * 格式：name \t is_hex(0/1) \t severity \t caro \t pattern
 *   · is_hex=0 时 pattern 是原始文本（可含空格，不能含制表符/换行）
 *   · is_hex=1 时 pattern 是十六进制串，如 125EA7F0
 * 返回：成功加载的条数；文件不存在/格式错误返回 0。重复加载会追加。 */
int signature_db_load(const char *path);

/* 把内置特征导出为 .db 文本（用于生成初始库/迁移） */
int signature_db_dump(const char *path);

/* 外部库条数（不含内置） */
int signature_db_count(void);

/* 清空已加载的外部库（用于热重载） */
void signature_db_clear(void);

#endif
