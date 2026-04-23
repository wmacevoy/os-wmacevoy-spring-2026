#include "hash_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *prog = "mksha256";

static void usage(void) {
    fprintf(stderr,
        "usage: %s [--hex] [--check <hexdigest>] [file ...]\n"
        "\n"
        "  Concatenates all file arguments (or stdin if none) and prints\n"
        "  the SHA-256 digest of the combined stream.\n"
        "\n"
        "  --hex              Print digest as lowercase hex (default: raw bytes)\n"
        "  --check <digest>   Exit 0 if digest matches, 1 otherwise (implies --hex)\n"
        "  file               Path to input file; use - for stdin\n",
        prog);
}

static int feed_file(hash_sha256_ctx *ctx, FILE *f) {
    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (hash_sha256_update(ctx, buf, n) != 0) {
            return -1;
        }
    }
    return ferror(f) ? -1 : 0;
}

static void print_hex(const unsigned char *d) {
    static const char hex[] = "0123456789abcdef";
    int i;
    for (i = 0; i < HASH_SHA256_DIGEST_LEN; ++i) {
        putchar(hex[(d[i] >> 4) & 0x0f]);
        putchar(hex[ d[i]       & 0x0f]);
    }
    putchar('\n');
}

static int parse_hex_digest(const char *s, unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    int i;
    if (strlen(s) != (size_t)(HASH_SHA256_DIGEST_LEN * 2)) {
        return -1;
    }
    for (i = 0; i < HASH_SHA256_DIGEST_LEN; ++i) {
        unsigned int hi, lo;
        char h = s[i * 2], l = s[i * 2 + 1];

#define HEXVAL(c) ((c) >= '0' && (c) <= '9' ? (unsigned int)((c)-'0') : \
                   (c) >= 'a' && (c) <= 'f' ? (unsigned int)((c)-'a'+10) : \
                   (c) >= 'A' && (c) <= 'F' ? (unsigned int)((c)-'A'+10) : 0xffu)

        hi = HEXVAL(h);
        lo = HEXVAL(l);
        if (hi == 0xffu || lo == 0xffu) { return -1; }
        out[i] = (unsigned char)((hi << 4) | lo);

#undef HEXVAL
    }
    return 0;
}

int main(int argc, char **argv) {
    int do_hex = 0;
    int do_check = 0;
    unsigned char expected[HASH_SHA256_DIGEST_LEN];
    unsigned char digest[HASH_SHA256_DIGEST_LEN];
    hash_sha256_ctx ctx;
    int i;
    int file_count = 0;

    prog = argv[0];

    /* Parse flags */
    i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--hex") == 0) {
            do_hex = 1;
            ++i;
        } else if (strcmp(argv[i], "--check") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: --check requires an argument\n", prog);
                usage();
                return 2;
            }
            do_check = 1;
            do_hex   = 1;
            if (parse_hex_digest(argv[i + 1], expected) != 0) {
                fprintf(stderr, "%s: invalid hex digest '%s'\n", prog, argv[i + 1]);
                return 2;
            }
            i += 2;
        } else if (strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", prog, argv[i]);
            usage();
            return 2;
        } else {
            break;
        }
    }

    if (hash_sha256_init(&ctx) != 0) {
        fprintf(stderr, "%s: failed to initialise SHA-256\n", prog);
        return 1;
    }

    if (i == argc) {
        /* No file arguments — read stdin */
        if (feed_file(&ctx, stdin) != 0) {
            fprintf(stderr, "%s: read error on stdin\n", prog);
            return 1;
        }
        file_count = 1;
    } else {
        for (; i < argc; ++i) {
            FILE *f;
            int err;

            if (strcmp(argv[i], "-") == 0) {
                f = stdin;
            } else {
                f = fopen(argv[i], "rb");
                if (!f) {
                    fprintf(stderr, "%s: cannot open '%s'\n", prog, argv[i]);
                    return 1;
                }
            }

            err = feed_file(&ctx, f);
            if (f != stdin) { fclose(f); }
            if (err != 0) {
                fprintf(stderr, "%s: read error on '%s'\n", prog, argv[i]);
                return 1;
            }
            ++file_count;
        }
    }
    (void)file_count;

    if (hash_sha256_final(&ctx, digest) != 0) {
        fprintf(stderr, "%s: failed to finalise SHA-256\n", prog);
        return 1;
    }

    if (do_check) {
        if (memcmp(digest, expected, HASH_SHA256_DIGEST_LEN) != 0) {
            fprintf(stderr, "%s: digest mismatch\n", prog);
            return 1;
        }
        return 0;
    }

    if (do_hex) {
        print_hex(digest);
    } else {
        fwrite(digest, 1, HASH_SHA256_DIGEST_LEN, stdout);
    }

    return 0;
}
