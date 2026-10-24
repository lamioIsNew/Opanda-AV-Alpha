#ifndef FEATURE_EXTRACTOR_H
#define FEATURE_EXTRACTOR_H

#define FEATURE_DIM 549

/* 从 EXE 提取 549 维 EMBER 特征
 * 返回 1 成功，0 失败
 */
int extract_features(const char *filepath, double *features);

/* 检查文件是否是合法 PE */
int is_valid_pe(const char *filepath);

/* 检查内存缓冲是否是合法 PE（流模式用） */
int is_valid_pe_buf(const unsigned char *buf, long size);

/* 计算文件字节熵（用于加壳检测） */
double calc_file_entropy(const char *filepath);

/* 计算内存缓冲的字节熵（流模式用） */
double calc_entropy_buf(const unsigned char *buf, long size);

/* 从内存缓冲提取 549 维特征（流模式用，逻辑与 extract_features 一致） */
int extract_features_buf(const unsigned char *buf, long size, double *features);

#endif
