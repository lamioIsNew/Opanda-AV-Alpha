#ifndef TRUST_CHECK_H
#define TRUST_CHECK_H

/* 数字签名信任检查（Windows Authenticode / WinVerifyTrust）
 *
 * 返回：
 *   2 = 有效签名，且签名者属于已知厂商白名单（可据此直接放行/降分）
 *   1 = 有效签名，但厂商不在白名单（仅展示签名者信息）
 *   0 = 无有效签名 / 验证失败（走常规扫描流程）
 * signer 输出签名者显示名（如 "Microsoft Windows"），可为空
 */
int trust_check_file(const char *filepath, char *signer, int signer_len);

#endif
