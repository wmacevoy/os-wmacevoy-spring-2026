#include "hash_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * hash_sha256_tool [-x] [message]
 *
 *   No arguments : read stdin until EOF, print hex digest.
 *   message      : hash the given string argument (no newline).
 *   -x message   : same but interpret message as hex bytes first.
 */

static void print_hex(const unsigned char *d, size_t len) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; ++i) {
        putchar(hex[(d[i] >> 4) & 0x0f]);
        putchar(hex[ d[i]       & 0x0f]);
    }
    putchar('\n');
}

static int hex_char(char c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

int main(int argc, char **argv) {
    unsigned char digest[HASH_SHA256_DIGEST_LEN];
    int hex_mode = 0;
    const char *msg_str = NULL;

    if (argc >= 2 && strcmp(argv[1], "-x") == 0) {
        hex_mode = 1;
        if (argc >= 3) { msg_str = argv[2]; }
    } else if (argc >= 2) {
        msg_str = argv[1];
    }

    if (msg_str != NULL) {
        /* Hash a string (or hex-decoded bytes) argument */
        if (!hex_mode) {
            if (hash_sha256(msg_str, strlen(msg_str), digest) != 0) {
                fprintf(stderr, "hash_sha256_tool: hashing failed\n");
                return 1;
            }
        } else {
            size_t hex_len = strlen(msg_str);
            size_t bin_len;
            unsigned char *bin;
            size_t i;

            if (hex_len % 2 != 0) {
                fprintf(stderr, "hash_sha256_tool: odd hex length\n");
                return 1;
            }
            bin_len = hex_len / 2;
            bin = (unsigned char *)malloc(bin_len ? bin_len : 1);
            if (!bin) {
                fprintf(stderr, "hash_sha256_tool: out of memory\n");
                return 1;
            }
            for (i = 0; i < bin_len; ++i) {
                int hi = hex_char(msg_str[i * 2]);
                int lo = hex_char(msg_str[i * 2 + 1]);
                if (hi < 0 || lo < 0) {
                    fprintf(stderr, "hash_sha256_tool: invalid hex input\n");
                    free(bin);
                    return 1;
                }
                bin[i] = (unsigned char)((hi << 4) | lo);
            }
            if (hash_sha256(bin, bin_len, digest) != 0) {
                fprintf(stderr, "hash_sha256_tool: hashing failed\n");
                free(bin);
                return 1;
            }
            free(bin);
        }
    } else {
        /* Read stdin */
        unsigned char buf[4096];
        size_t total_len = 0;
        unsigned char *data = NULL;
        size_t n;

        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            unsigned char *tmp = (unsigned char *)realloc(data, total_len + n);
            if (!tmp) {
                free(data);
                fprintf(stderr, "hash_sha256_tool: out of memory\n");
                return 1;
            }
            data = tmp;
            memcpy(data + total_len, buf, n);
            total_len += n;
        }
        if (ferror(stdin)) {
            free(data);
            fprintf(stderr, "hash_sha256_tool: read error\n");
            return 1;
        }
        if (hash_sha256(data ? data : (unsigned char *)"", total_len, digest) != 0) {
            free(data);
            fprintf(stderr, "hash_sha256_tool: hashing failed\n");
            return 1;
        }
        free(data);
    }

    print_hex(digest, HASH_SHA256_DIGEST_LEN);
    return 0;
}
