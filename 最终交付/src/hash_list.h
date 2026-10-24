#ifndef HASH_LIST_H
#define HASH_LIST_H

/* hash_list.c -- 本地信任名单（哈希白名单，trusted_list.txt）
 *
 * 用途：把“确认安全但被模型误报”的文件按 SHA256 加入本地信任名单，
 *       扫描时直接判为可信（[TRUSTED - WHITELIST]），跳过全部查杀。
 * 格式：每行一条 "SHA256 [备注]"；# 或 ; 开头的行是注释；空行忽略。
 * 优先级：最高（文件模式与管道模式均生效，先于特征码 / 加壳 / 模型）。
 * 名单文件不存在或解析失败时静默返回 0，不影响正常扫描。
 */
int hash_list_load(const char *path);                               /* 返回载入条数，失败为 0 */
int hash_list_check(const char *sha_hex, char *note, int note_len); /* 命中返回 1，备注写入 note */

#endif
