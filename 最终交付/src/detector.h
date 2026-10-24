#ifndef DETECTOR_H
#define DETECTOR_H

#include "feature_extractor.h"

/* 加载 scaler.txt */
int load_scaler(const char *path);

/* 对 549 维特征做预处理 + LightGBM 推理，返回 0~100 分 */
double predict_score(double *raw_features);

#endif
