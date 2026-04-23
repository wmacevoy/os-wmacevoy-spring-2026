#include "secure_random.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int random_index(size_t range, size_t *out_index) {
    unsigned char b = 0;
    unsigned char limit;

    if (range == 0 || range > 256) {
        return -1;
    }

    limit = (unsigned char)(256 - (256 % range));

    do {
        if (secure_random_bytes(&b, 1) != 0) {
            return -1;
        }
    } while (b >= limit);

    *out_index = (size_t)(b % range);
    return 0;
}

static int pick_from_set(const char *set, size_t set_len, char *out_ch) {
    size_t idx;

    if (random_index(set_len, &idx) != 0) {
        return -1;
    }

    *out_ch = set[idx];
    return 0;
}

static int pick_printable_ascii(char *out_ch) {
    size_t idx;
    const size_t count = 95; /* ASCII 32..126 inclusive */

    if (random_index(count, &idx) != 0) {
        return -1;
    }

    *out_ch = (char)(32 + idx);
    return 0;
}

int main(int argc, char **argv) {
    const char *pattern;
    size_t i;
    size_t n;
    char *out;

    static const char UPPER[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const char LOWER[] = "abcdefghijklmnopqrstuvwxyz";
    static const char LEET[] = "01345789@$!+-_";

    if (argc != 2) {
        fprintf(stderr, "usage: %s <pattern>\n", argv[0]);
        fprintf(stderr, "tokens: A=upper, a=lower, @=leet, .=printable ASCII, others=literal\n");
        return 2;
    }

    pattern = argv[1];
    n = strlen(pattern);
    out = (char *)malloc(n + 1);
    if (out == NULL) {
        fprintf(stderr, "mkpass: out of memory\n");
        return 1;
    }

    for (i = 0; i < n; ++i) {
        int ok = 0;

        switch (pattern[i]) {
            case 'A':
                ok = (pick_from_set(UPPER, sizeof(UPPER) - 1, &out[i]) == 0);
                break;
            case 'a':
                ok = (pick_from_set(LOWER, sizeof(LOWER) - 1, &out[i]) == 0);
                break;
            case '@':
                ok = (pick_from_set(LEET, sizeof(LEET) - 1, &out[i]) == 0);
                break;
            case '.':
                ok = (pick_printable_ascii(&out[i]) == 0);
                break;
            default:
                out[i] = pattern[i];
                ok = 1;
                break;
        }

        if (!ok) {
            free(out);
            fprintf(stderr, "mkpass: failed to generate secure random output\n");
            return 1;
        }
    }

    out[n] = '\0';
    puts(out);
    free(out);
    return 0;
}
