#include "scanner_api.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wchar.h>

static void print_result(const ScannerResult *r, int rc) {
    printf("rc=%d level=%d\n", rc, scanner_result_level(r));
    printf("bracket=%s\n", r->bracket);
    printf("kind=%s\n", r->kind);
    printf("layer=%s\n", r->layer);
    printf("score=%.2f\n", r->score);
    printf("caro=%s\n", r->caro);
    printf("detail=%s\n", r->detail);
    printf("sha=%s\n", r->sha);
}

int wmain(int argc, wchar_t **argv) {
    ScannerResult r;
    int rc;
    if (argc < 2) {
        printf("usage: scanner_test.exe <file>\n");
        return 2;
    }
    printf("dll=%s abi=%u db=%d\n", scanner_version(), scanner_abi_version(), scanner_signature_db_count());
    memset(&r, 0, sizeof(r));
    rc = scanner_scan_file_w(argv[1], &r);
    print_result(&r, rc);
    return rc;
}
