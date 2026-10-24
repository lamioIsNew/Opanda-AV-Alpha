/* sigdb_builder.c -- 把内置特征表导出为 signatures.db（UTF-8 文本）
 * 用法：sigdb_builder.exe <输出文件>
 *
 * 生成后可直接编辑 db：一行一条，字段用制表符分隔：
 *   name <TAB> is_hex(0/1) <TAB> severity <TAB> caro <TAB> pattern
 * 扫描时外部 db 优先于 DLL 内置兜底表。
 */
#include "signature_scan.h"

#include <stdio.h>

int main(int argc, char **argv) {
    int n;
    if (argc < 2) {
        fprintf(stderr, "usage: sigdb_builder.exe <output.db>\n");
        return 2;
    }
    n = signature_db_dump(argv[1]);
    if (n <= 0) {
        fprintf(stderr, "failed: %s\n", argv[1]);
        return 1;
    }
    fprintf(stdout, "wrote %d signatures -> %s\n", n, argv[1]);
    return 0;
}
