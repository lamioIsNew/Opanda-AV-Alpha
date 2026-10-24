#ifndef LNK_SCAN_H
#define LNK_SCAN_H

/* LNK 快捷方式启发式扫描（Shell Link 二进制格式，MS-SHLLINK）
 *
 * is_lnk_buf: 按文件头魔数(4C 00 00 00 + CLSID)判断是否为 .lnk
 *
 * lnk_scan_buf / lnk_scan_file:
 *   返回命中规则条数（>=0），非 LNK 返回 -1
 *   score       输出 0~100 启发式总分
 *   details     输出命中项描述（"…(+40); …(+25)"），可为空
 *   caro_name   得分 >=50 时输出检测名：
 *                 Rogue.LNK.Promotion  （推广/引流类：指向 URL）
 *                 Trojan.LNK.Generic   （其他可疑命令类）
 *   target/args 输出从 LNK 中解析/提取的目标程序与命令行参数（可为空）
 */
int is_lnk_buf(const unsigned char *buf, long size);
int lnk_scan_buf(const unsigned char *buf, long size,
                 double *score, char *details, int details_len,
                 char *caro_name, int caro_len,
                 char *target, int target_len,
                 char *args, int args_len);
int lnk_scan_file(const char *filepath,
                  double *score, char *details, int details_len,
                  char *caro_name, int caro_len,
                  char *target, int target_len,
                  char *args, int args_len);

#endif
