#ifndef RISK_NAME_H
#define RISK_NAME_H

/* risk_name.c -- 中文人性化输出辅助
 *  - 检测名（CARO 命名，如 Ransom.Win32.Phobos）-> 中文风险名称
 *  - 结论括号（如 [HIGH RISK - SIGNATURE]）-> 中文判定短语 / 处理建议
 *  - 控制台结果块排版（头部 / 判定 / 风险名称 / 建议 / 尾部）
 *  - ANSI(GBK) 路径 -> UTF-8 显示转换
 *
 * 注意：结论括号串（[HIGH RISK] 等）是脚本计数用的机器标记，
 *       必须原样输出，不要给它们加中文改写。
 */

/* 检测名 -> 中文风险名称；未归类返回空串 ""（调用方回退为仅显示技术名） */
const char *risk_cn_name(const char *caro);

/* 结论括号 -> 中文判定短语 */
const char *verdict_cn(const char *bracket);

/* 结论括号 -> 处理建议 */
const char *advice_cn(const char *bracket);

/* ANSI(系统代码页，中文系统=GBK) 字符串 -> UTF-8（仅用于控制台显示） */
void path_to_utf8(const char *ansi, char *out, int out_len);

/* 结果块排版（输出到 stdout；name 须为已转 UTF-8 的显示名） */
void pr_result_header(const char *name);
void pr_result_end(void);
void pr_line_verdict(const char *bracket);
void pr_line_risk(const char *caro);
void pr_line_advice(const char *bracket);

#endif
