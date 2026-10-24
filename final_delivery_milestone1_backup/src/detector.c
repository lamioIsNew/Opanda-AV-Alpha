#include "detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* m2cgen 导出的函数
 * ABI 约定（与 c_code/ensemble_score.c 验证过的约定一致）：
 *   output[0] = P(良性), output[1] = P(恶意)，模型内部已应用 sigmoid。
 * 注意：必须传 2 个 double 的输出缓冲，m2cgen 会写满两个元素。
 */
extern void score(double *input, double *output);

static double mean[FEATURE_DIM];
static double scale[FEATURE_DIM];

int load_scaler(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char line[65536];
    int got_mean = 0, got_scale = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "mean", 4) == 0) {
            char *p = line + 4;
            for (int i = 0; i < FEATURE_DIM; i++) mean[i] = strtod(p, &p);
            got_mean = 1;
        } else if (strncmp(line, "scale", 5) == 0) {
            char *p = line + 5;
            for (int i = 0; i < FEATURE_DIM; i++) scale[i] = strtod(p, &p);
            got_scale = 1;
        }
    }
    fclose(fp);
    return got_mean && got_scale;
}

double predict_score(double *raw) {
    double x[FEATURE_DIM];
    for (int i = 0; i < FEATURE_DIM; i++) {
        double v = log1p(fabs(raw[i]));
        v = (v - mean[i]) / scale[i];
        if (v > 5.0) v = 5.0;
        if (v < -5.0) v = -5.0;
        x[i] = v;
    }
    double output[2] = {0.0, 0.0};
    score(x, output);
    return output[1] * 100.0;   /* output[1]=P(恶意)*100；模型已含 sigmoid，不再套 sigmoid */
}
