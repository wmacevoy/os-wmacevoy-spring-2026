#include "hash_sha256.h"

#include <string.h>

/* ------------------------------------------------------------------ Windows */
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

/* Internal layout stored in _opaque: two HANDLEs + heap pointer + obj size */
typedef struct {
    BCRYPT_ALG_HANDLE  alg;
    BCRYPT_HASH_HANDLE hash;
    PBYTE              hash_obj;
} win_ctx;

int hash_sha256_init(hash_sha256_ctx *ctx) {
    win_ctx *w = (win_ctx *)ctx->_opaque;
    DWORD hash_obj_len = 0, result_len = 0;
    NTSTATUS st;

    memset(w, 0, sizeof(*w));
    st = BCryptOpenAlgorithmProvider(&w->alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) { return -1; }

    st = BCryptGetProperty(w->alg, BCRYPT_OBJECT_LENGTH,
                           (PBYTE)&hash_obj_len, sizeof(hash_obj_len),
                           &result_len, 0);
    if (!BCRYPT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(w->alg, 0); return -1; }

    w->hash_obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hash_obj_len);
    if (!w->hash_obj) { BCryptCloseAlgorithmProvider(w->alg, 0); return -1; }

    st = BCryptCreateHash(w->alg, &w->hash, w->hash_obj, hash_obj_len, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(st)) {
        HeapFree(GetProcessHeap(), 0, w->hash_obj);
        BCryptCloseAlgorithmProvider(w->alg, 0);
        return -1;
    }
    return 0;
}

int hash_sha256_update(hash_sha256_ctx *ctx, const void *data, size_t len) {
    win_ctx *w = (win_ctx *)ctx->_opaque;
    if (data == NULL && len != 0) { return -1; }
    if (len == 0) { return 0; }
    return BCRYPT_SUCCESS(BCryptHashData(w->hash, (PBYTE)data, (ULONG)len, 0))
               ? 0 : -1;
}

int hash_sha256_final(hash_sha256_ctx *ctx,
                      unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    win_ctx *w = (win_ctx *)ctx->_opaque;
    NTSTATUS st = BCryptFinishHash(w->hash, out, HASH_SHA256_DIGEST_LEN, 0);
    BCryptDestroyHash(w->hash);
    HeapFree(GetProcessHeap(), 0, w->hash_obj);
    BCryptCloseAlgorithmProvider(w->alg, 0);
    memset(w, 0, sizeof(*w));
    return BCRYPT_SUCCESS(st) ? 0 : -1;
}

/* ------------------------------------------------------------------- Apple */
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>

int hash_sha256_init(hash_sha256_ctx *ctx) {
    CC_SHA256_CTX *c = (CC_SHA256_CTX *)ctx->_opaque;
    return (CC_SHA256_Init(c) == 1) ? 0 : -1;
}

int hash_sha256_update(hash_sha256_ctx *ctx, const void *data, size_t len) {
    CC_SHA256_CTX *c = (CC_SHA256_CTX *)ctx->_opaque;
    if (data == NULL && len != 0) { return -1; }
    if (len == 0) { return 0; }
    return (CC_SHA256_Update(c, data, (CC_LONG)len) == 1) ? 0 : -1;
}

int hash_sha256_final(hash_sha256_ctx *ctx,
                      unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    CC_SHA256_CTX *c = (CC_SHA256_CTX *)ctx->_opaque;
    return (CC_SHA256_Final(out, c) == 1) ? 0 : -1;
}

/* ------------------------------------------------- Linux / Android / Others */
#else

/* --- Optional OpenSSL provider --- */
#if defined(HASH_SHA256_USE_OPENSSL)
#include <openssl/sha.h>

int hash_sha256_init(hash_sha256_ctx *ctx) {
    SHA256_CTX *c = (SHA256_CTX *)ctx->_opaque;
    return (SHA256_Init(c) == 1) ? 0 : -1;
}

int hash_sha256_update(hash_sha256_ctx *ctx, const void *data, size_t len) {
    SHA256_CTX *c = (SHA256_CTX *)ctx->_opaque;
    if (data == NULL && len != 0) { return -1; }
    if (len == 0) { return 0; }
    return (SHA256_Update(c, data, len) == 1) ? 0 : -1;
}

int hash_sha256_final(hash_sha256_ctx *ctx,
                      unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    SHA256_CTX *c = (SHA256_CTX *)ctx->_opaque;
    return (SHA256_Final(out, c) == 1) ? 0 : -1;
}

/* --- Pure-C fallback (no external dependencies) --- */
#else

/* Based on the public-domain SHA-256 specification. */

typedef unsigned int sha256_u32;

static const sha256_u32 K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROTR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)        (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)        (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)       (ROTR32(x,  7) ^ ROTR32(x, 18) ^ ((x) >>  3))
#define SIG1(x)       (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

typedef struct {
    unsigned char  data[64];
    sha256_u32     len_low;    /* bit length, low 32 bits  */
    sha256_u32     len_high;   /* bit length, high 32 bits */
    sha256_u32     state[8];
    unsigned int   data_len;
} sha256_ctx;

static void sha256_transform(sha256_ctx *ctx, const unsigned char *chunk) {
    sha256_u32 m[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((sha256_u32)chunk[i * 4    ] << 24) |
               ((sha256_u32)chunk[i * 4 + 1] << 16) |
               ((sha256_u32)chunk[i * 4 + 2] <<  8) |
               ((sha256_u32)chunk[i * 4 + 3]      );
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->data_len  = 0;
    ctx->len_low   = 0;
    ctx->len_high  = 0;
    ctx->state[0]  = 0x6a09e667u;
    ctx->state[1]  = 0xbb67ae85u;
    ctx->state[2]  = 0x3c6ef372u;
    ctx->state[3]  = 0xa54ff53au;
    ctx->state[4]  = 0x510e527fu;
    ctx->state[5]  = 0x9b05688cu;
    ctx->state[6]  = 0x1f83d9abu;
    ctx->state[7]  = 0x5be0cd19u;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->data_len++] = data[i];
        /* Accumulate bit count, guarding overflow into high word */
        ctx->len_low += 8;
        if (ctx->len_low == 0) { ctx->len_high++; }
        if (ctx->data_len == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->data_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    unsigned int i = ctx->data_len;

    /* Pad to 56 bytes mod 64 */
    ctx->data[i++] = 0x80u;
    if (ctx->data_len < 56) {
        while (i < 56) { ctx->data[i++] = 0x00u; }
    } else {
        while (i < 64) { ctx->data[i++] = 0x00u; }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    /* Append big-endian bit length */
    ctx->data[56] = (unsigned char)(ctx->len_high >> 24);
    ctx->data[57] = (unsigned char)(ctx->len_high >> 16);
    ctx->data[58] = (unsigned char)(ctx->len_high >>  8);
    ctx->data[59] = (unsigned char)(ctx->len_high      );
    ctx->data[60] = (unsigned char)(ctx->len_low  >> 24);
    ctx->data[61] = (unsigned char)(ctx->len_low  >> 16);
    ctx->data[62] = (unsigned char)(ctx->len_low  >>  8);
    ctx->data[63] = (unsigned char)(ctx->len_low       );
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        out[i * 4    ] = (unsigned char)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(ctx->state[i] >>  8);
        out[i * 4 + 3] = (unsigned char)(ctx->state[i]      );
    }
}

int hash_sha256_init(hash_sha256_ctx *ctx) {
    sha256_init((sha256_ctx *)ctx->_opaque);
    return 0;
}

int hash_sha256_update(hash_sha256_ctx *ctx, const void *data, size_t len) {
    if (data == NULL && len != 0) { return -1; }
    if (len == 0) { return 0; }
    sha256_update((sha256_ctx *)ctx->_opaque, (const unsigned char *)data, len);
    return 0;
}

int hash_sha256_final(hash_sha256_ctx *ctx,
                      unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    sha256_final((sha256_ctx *)ctx->_opaque, out);
    return 0;
}

#endif /* HASH_SHA256_USE_OPENSSL */
#endif /* platform selection */

/* One-shot wrapper — shared by all platforms */
int hash_sha256(const void *msg, size_t msg_len,
                unsigned char out[HASH_SHA256_DIGEST_LEN]) {
    hash_sha256_ctx ctx;
    if (msg == NULL && msg_len != 0) { return -1; }
    if (hash_sha256_init(&ctx) != 0) { return -1; }
    if (hash_sha256_update(&ctx, msg, msg_len) != 0) { return -1; }
    return hash_sha256_final(&ctx, out);
}
