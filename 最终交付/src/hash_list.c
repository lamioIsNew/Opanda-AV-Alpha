/* hash_list.c -- 本地信任名单（哈希白名单）实现（见 hash_list.h） */
#include "hash_list.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define HL_MAX   256
#define HL_NOTE  128

typedef struct {
    char sha[65];            /* 统一存小写十六进制 */
    char note[HL_NOTE];
} HLEntry;

static HLEntry g_entries[HL_MAX];
static int g_count = 0;

static int is_hex64(const char *s) {
    int i;
    for (i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

int hash_list_load(const char *path) {
    FILE *fp;
    char line[512];
    int first = 1;

    g_count = 0;
    if (!path) return 0;
    fp = fopen(path, "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *tok;
        char *note;
        char low[65];
        int i, n;

        if (first) {           /* 容忍记事本另存产生的 UTF-8 BOM */
            if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB &&
                (unsigned char)p[2] == 0xBF) {
                p += 3;
            }
            first = 0;
        }
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\r' || *p == '\n' || *p == '#' || *p == ';') continue;

        tok = p;
        i = 0;
        while (tok[i] && !isspace((unsigned char)tok[i])) i++;
        if (i != 64) continue;                 /* 只认 64 位完整哈希 */

        for (n = 0; n < 64; n++) low[n] = (char)tolower((unsigned char)tok[n]);
        low[64] = '\0';
        if (!is_hex64(low)) continue;

        strcpy(g_entries[g_count].sha, low);

        note = tok + i;
        while (*note == ' ' || *note == '\t') note++;
        n = (int)strlen(note);
        while (n > 0 && (note[n - 1] == '\n' || note[n - 1] == '\r')) n--;
        if (n >= HL_NOTE) n = HL_NOTE - 1;
        memcpy(g_entries[g_count].note, note, (size_t)n);
        g_entries[g_count].note[n] = '\0';

        g_count++;
        if (g_count >= HL_MAX) break;
    }
    fclose(fp);
    return g_count;
}

int hash_list_check(const char *sha_hex, char *note, int note_len) {
    char low[65];
    int i;

    if (!sha_hex || strlen(sha_hex) != 64) return 0;
    for (i = 0; i < 64; i++) low[i] = (char)tolower((unsigned char)sha_hex[i]);
    low[64] = '\0';
    if (!is_hex64(low)) return 0;

    for (i = 0; i < g_count; i++) {
        if (strcmp(low, g_entries[i].sha) == 0) {
            if (note && note_len > 0) {
                strncpy(note, g_entries[i].note, (size_t)(note_len - 1));
                note[note_len - 1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}
