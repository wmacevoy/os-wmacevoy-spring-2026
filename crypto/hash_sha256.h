#ifndef HASH_SHA256_H
#define HASH_SHA256_H

#include <stddef.h>

#define HASH_SHA256_DIGEST_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque streaming context.  256 bytes is enough for all platform internals.
 */
typedef struct {
    _Alignas(max_align_t) unsigned char _opaque[256];
} hash_sha256_ctx;

/* Initialise.  Returns 0/-1. */
int hash_sha256_init(hash_sha256_ctx *ctx);

/* Feed data.  Returns 0/-1. */
int hash_sha256_update(hash_sha256_ctx *ctx, const void *data, size_t len);

/* Finalise; writes HASH_SHA256_DIGEST_LEN bytes to out.  Returns 0/-1. */
int hash_sha256_final(hash_sha256_ctx *ctx,
                      unsigned char out[HASH_SHA256_DIGEST_LEN]);

/* One-shot wrapper. */
int hash_sha256(const void *msg, size_t msg_len,
                unsigned char out[HASH_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* HASH_SHA256_H */
