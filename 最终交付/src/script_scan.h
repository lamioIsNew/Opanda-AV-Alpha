#ifndef SCRIPT_SCAN_H
#define SCRIPT_SCAN_H

/* 判断 buffer 是否为“文本脚本候选”
 * （排除 PE/压缩包/图片等二进制后，可打印比例高 或 UTF-16）
 */
int is_script_buf(const unsigned char *buf, long size);

/* 脚本启发式扫描（0-100 分）：规则词表+权重累计
 * 返回命中规则条数；details / caro_name 均可为 NULL
 * caro_name：得分 >= 50 时输出 CARO 检测名（如 Ransom.Script.Generic），否则为空串
 */
int script_scan_buf(const unsigned char *buf, long size, double *score, char *details, int details_len, char *caro_name, int caro_len);

/* 文件版：不是脚本返回 -1；否则返回命中条数（>=0） */
int script_scan_file(const char *filepath, double *score, char *details, int details_len, char *caro_name, int caro_len);

#endif
