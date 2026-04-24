#include "aes_gcm.h"

#include <limits.h>
#include <string.h>

static int valid_key_len(size_t n) {
    return n == 16 || n == 24 || n == 32;
}

static int valid_tag_len(size_t n) {
    return n >= 1 && n <= AES_GCM_TAG_MAX_LEN;
}

static int valid_buf(const void *p, size_t n) {
    return p != NULL || n == 0;
}

/* =========================================================== Windows CNG */
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif

typedef struct {
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_KEY_HANDLE key;
    PBYTE key_obj;
} win_key;

static void win_free(win_key *w) {
    if (w->key)     { BCryptDestroyKey(w->key);                  w->key = NULL; }
    if (w->key_obj) { HeapFree(GetProcessHeap(), 0, w->key_obj); w->key_obj = NULL; }
    if (w->alg)     { BCryptCloseAlgorithmProvider(w->alg, 0);   w->alg = NULL; }
}

static int win_load_key(win_key *w,
                        const unsigned char *key, size_t key_len) {
    NTSTATUS st;
    DWORD obj_len = 0, out = 0;

    memset(w, 0, sizeof(*w));

    st = BCryptOpenAlgorithmProvider(&w->alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) { win_free(w); return -1; }

    st = BCryptSetProperty(w->alg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(st)) { win_free(w); return -1; }

    st = BCryptGetProperty(w->alg, BCRYPT_OBJECT_LENGTH,
                           (PUCHAR)&obj_len, sizeof(obj_len), &out, 0);
    if (!BCRYPT_SUCCESS(st)) { win_free(w); return -1; }

    w->key_obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, obj_len);
    if (!w->key_obj) { win_free(w); return -1; }

    st = BCryptGenerateSymmetricKey(w->alg, &w->key,
                                    w->key_obj, obj_len,
                                    (PUCHAR)key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(st)) { win_free(w); return -1; }

    return 0;
}

int aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *pt,           size_t pt_len,
                    unsigned char *ct,
                    unsigned char *tag,       size_t tag_len) {
    win_key w;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    NTSTATUS st;
    ULONG out = 0;

    if (!valid_key_len(key_len))                         { return -1; }
    if (iv == NULL || iv_len == 0 || iv_len > ULONG_MAX) { return -1; }
    if (!valid_tag_len(tag_len))                         { return -1; }
    if (!valid_buf(aad, aad_len) || aad_len > ULONG_MAX) { return -1; }
    if (!valid_buf(pt,  pt_len ) || pt_len  > ULONG_MAX) { return -1; }
    if (pt_len != 0 && ct == NULL)                       { return -1; }
    if (tag == NULL)                                     { return -1; }

    if (win_load_key(&w, key, key_len) != 0)             { return -1; }

    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce    = (PUCHAR)iv;
    ai.cbNonce    = (ULONG)iv_len;
    ai.pbAuthData = (PUCHAR)aad;
    ai.cbAuthData = (ULONG)aad_len;
    ai.pbTag      = tag;
    ai.cbTag      = (ULONG)tag_len;

    st = BCryptEncrypt(w.key,
                       (PUCHAR)pt, (ULONG)pt_len,
                       &ai,
                       NULL, 0,
                       ct, (ULONG)pt_len,
                       &out, 0);
    win_free(&w);
    if (!BCRYPT_SUCCESS(st) || out != (ULONG)pt_len) { return -1; }
    return 0;
}

int aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *ct,           size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *pt) {
    win_key w;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    NTSTATUS st;
    ULONG out = 0;

    if (!valid_key_len(key_len))                         { return -1; }
    if (iv == NULL || iv_len == 0 || iv_len > ULONG_MAX) { return -1; }
    if (!valid_tag_len(tag_len))                         { return -1; }
    if (!valid_buf(aad, aad_len) || aad_len > ULONG_MAX) { return -1; }
    if (!valid_buf(ct,  ct_len ) || ct_len  > ULONG_MAX) { return -1; }
    if (ct_len != 0 && pt == NULL)                       { return -1; }
    if (tag == NULL)                                     { return -1; }

    if (win_load_key(&w, key, key_len) != 0)             { return -1; }

    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce    = (PUCHAR)iv;
    ai.cbNonce    = (ULONG)iv_len;
    ai.pbAuthData = (PUCHAR)aad;
    ai.cbAuthData = (ULONG)aad_len;
    ai.pbTag      = (PUCHAR)tag;
    ai.cbTag      = (ULONG)tag_len;

    st = BCryptDecrypt(w.key,
                       (PUCHAR)ct, (ULONG)ct_len,
                       &ai,
                       NULL, 0,
                       pt, (ULONG)ct_len,
                       &out, 0);
    win_free(&w);
    if (!BCRYPT_SUCCESS(st) || out != (ULONG)ct_len) { return -1; }
    return 0;
}

/* ============================================================ OpenSSL */
#elif defined(AES_GCM_USE_OPENSSL)

#include <openssl/evp.h>

static const EVP_CIPHER *gcm_cipher(size_t key_len) {
    if (key_len == 16) { return EVP_aes_128_gcm(); }
    if (key_len == 24) { return EVP_aes_192_gcm(); }
    if (key_len == 32) { return EVP_aes_256_gcm(); }
    return NULL;
}

int aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *pt,           size_t pt_len,
                    unsigned char *ct,
                    unsigned char *tag,       size_t tag_len) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int out_len = 0;
    int ok = 0;

    if (!valid_key_len(key_len))                       { return -1; }
    if (iv == NULL || iv_len == 0 || iv_len > INT_MAX) { return -1; }
    if (!valid_tag_len(tag_len))                       { return -1; }
    if (!valid_buf(aad, aad_len) || aad_len > INT_MAX) { return -1; }
    if (!valid_buf(pt,  pt_len ) || pt_len  > INT_MAX) { return -1; }
    if (pt_len != 0 && ct == NULL)                     { return -1; }
    if (tag == NULL)                                   { return -1; }

    cipher = gcm_cipher(key_len);
    if (cipher == NULL) { return -1; }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)    { return -1; }

    do {
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { break; }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                (int)iv_len, NULL) != 1) { break; }
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { break; }

        if (aad_len > 0 &&
            EVP_EncryptUpdate(ctx, NULL, &out_len,
                              (const unsigned char *)aad, (int)aad_len) != 1) { break; }

        if (pt_len > 0) {
            if (EVP_EncryptUpdate(ctx, ct, &out_len,
                                  (const unsigned char *)pt, (int)pt_len) != 1) { break; }
            if (out_len != (int)pt_len) { break; }
        }

        if (EVP_EncryptFinal_ex(ctx, NULL, &out_len) != 1) { break; }
        if (out_len != 0) { break; }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                (int)tag_len, tag) != 1) { break; }
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *ct,           size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *pt) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int out_len = 0;
    int ok = 0;

    if (!valid_key_len(key_len))                       { return -1; }
    if (iv == NULL || iv_len == 0 || iv_len > INT_MAX) { return -1; }
    if (!valid_tag_len(tag_len))                       { return -1; }
    if (!valid_buf(aad, aad_len) || aad_len > INT_MAX) { return -1; }
    if (!valid_buf(ct,  ct_len ) || ct_len  > INT_MAX) { return -1; }
    if (ct_len != 0 && pt == NULL)                     { return -1; }
    if (tag == NULL)                                   { return -1; }

    cipher = gcm_cipher(key_len);
    if (cipher == NULL) { return -1; }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)    { return -1; }

    do {
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) { break; }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                (int)iv_len, NULL) != 1) { break; }
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) { break; }

        if (aad_len > 0 &&
            EVP_DecryptUpdate(ctx, NULL, &out_len,
                              (const unsigned char *)aad, (int)aad_len) != 1) { break; }

        if (ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, pt, &out_len,
                                  (const unsigned char *)ct, (int)ct_len) != 1) { break; }
            if (out_len != (int)ct_len) { break; }
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                (int)tag_len, (void *)tag) != 1) { break; }

        if (EVP_DecryptFinal_ex(ctx, NULL, &out_len) != 1) { break; }
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok && ct_len > 0 && pt != NULL) {
        memset(pt, 0, ct_len);
    }
    return ok ? 0 : -1;
}

/* ==================================================== Pure-C fallback */
#else
/*
 * No external crypto library. Byte-oriented AES (encrypt only) plus
 * shift-and-XOR GHASH. Not fast — but portable and dependency-free.
 * Compile with -DAES_GCM_USE_OPENSSL and link -lcrypto for the OpenSSL
 * backend if you want hardware acceleration.
 */

/* ---------------------------------------------------------------- AES */

static const unsigned char aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Rcon indexed by (i / Nk); slot 0 unused. */
static const unsigned char aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

#define AES_MAX_NR 14
typedef struct {
    unsigned char rk[(AES_MAX_NR + 1) * 16];
    int nr;
} aes_ctx;

static unsigned char xtime(unsigned char b) {
    return (unsigned char)((b << 1) ^ ((b & 0x80) ? 0x1b : 0x00));
}

static void aes_key_expand(aes_ctx *c, const unsigned char *key, size_t key_len) {
    int Nk = (int)(key_len / 4);        /* 4, 6, 8   */
    int Nr = Nk + 6;                    /* 10, 12, 14 */
    int total = 4 * (Nr + 1);           /* words      */
    int i;

    c->nr = Nr;
    memcpy(c->rk, key, key_len);

    for (i = Nk; i < total; ++i) {
        unsigned char t[4];
        int base = (i - 1) * 4;
        t[0] = c->rk[base + 0];
        t[1] = c->rk[base + 1];
        t[2] = c->rk[base + 2];
        t[3] = c->rk[base + 3];

        if (i % Nk == 0) {
            unsigned char r = t[0];
            t[0] = aes_sbox[t[1]];
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[r];
            t[0] ^= aes_rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            t[0] = aes_sbox[t[0]];
            t[1] = aes_sbox[t[1]];
            t[2] = aes_sbox[t[2]];
            t[3] = aes_sbox[t[3]];
        }
        c->rk[i*4 + 0] = c->rk[(i - Nk)*4 + 0] ^ t[0];
        c->rk[i*4 + 1] = c->rk[(i - Nk)*4 + 1] ^ t[1];
        c->rk[i*4 + 2] = c->rk[(i - Nk)*4 + 2] ^ t[2];
        c->rk[i*4 + 3] = c->rk[(i - Nk)*4 + 3] ^ t[3];
    }
}

static void aes_encrypt_block(const aes_ctx *c,
                              const unsigned char in[16],
                              unsigned char out[16]) {
    unsigned char s[16];
    unsigned char t;
    int round, i, col;

    memcpy(s, in, 16);
    for (i = 0; i < 16; ++i) { s[i] ^= c->rk[i]; }

    for (round = 1; round < c->nr; ++round) {
        /* SubBytes */
        for (i = 0; i < 16; ++i) { s[i] = aes_sbox[s[i]]; }

        /* ShiftRows (column-major state, row r shifts left by r) */
        t = s[1]; s[1] = s[5]; s[5] = s[9];  s[9]  = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        /* MixColumns */
        for (col = 0; col < 4; ++col) {
            unsigned char a0 = s[col*4 + 0];
            unsigned char a1 = s[col*4 + 1];
            unsigned char a2 = s[col*4 + 2];
            unsigned char a3 = s[col*4 + 3];
            unsigned char x  = (unsigned char)(a0 ^ a1 ^ a2 ^ a3);
            s[col*4 + 0] ^= (unsigned char)(x ^ xtime((unsigned char)(a0 ^ a1)));
            s[col*4 + 1] ^= (unsigned char)(x ^ xtime((unsigned char)(a1 ^ a2)));
            s[col*4 + 2] ^= (unsigned char)(x ^ xtime((unsigned char)(a2 ^ a3)));
            s[col*4 + 3] ^= (unsigned char)(x ^ xtime((unsigned char)(a3 ^ a0)));
        }

        /* AddRoundKey */
        for (i = 0; i < 16; ++i) { s[i] ^= c->rk[round*16 + i]; }
    }

    /* Final round: no MixColumns */
    for (i = 0; i < 16; ++i) { s[i] = aes_sbox[s[i]]; }
    t = s[1]; s[1] = s[5]; s[5] = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    for (i = 0; i < 16; ++i) { s[i] ^= c->rk[c->nr*16 + i]; }

    memcpy(out, s, 16);
}

/* -------------------------------------------------------------- GHASH */

/* GHASH over GF(2^128) with reducing polynomial x^128 + x^7 + x^2 + x + 1.
   Bit 0 of byte 0 is the high-order coefficient. */
static void ghash_mul(unsigned char acc[16], const unsigned char H[16]) {
    unsigned char z[16] = {0};
    unsigned char v[16];
    int i, j;

    memcpy(v, H, 16);
    for (i = 0; i < 128; ++i) {
        unsigned char bit = (unsigned char)((acc[i >> 3] >> (7 - (i & 7))) & 1u);
        if (bit) {
            for (j = 0; j < 16; ++j) { z[j] ^= v[j]; }
        }
        {
            unsigned char lsb = (unsigned char)(v[15] & 1u);
            for (j = 15; j > 0; --j) {
                v[j] = (unsigned char)((v[j] >> 1) | ((v[j - 1] & 1u) << 7));
            }
            v[0] = (unsigned char)(v[0] >> 1);
            if (lsb) { v[0] ^= 0xe1; }
        }
    }
    memcpy(acc, z, 16);
}

static void ghash_absorb_block(unsigned char acc[16],
                               const unsigned char H[16],
                               const unsigned char block[16]) {
    int j;
    for (j = 0; j < 16; ++j) { acc[j] ^= block[j]; }
    ghash_mul(acc, H);
}

static void ghash_absorb_buf(unsigned char acc[16],
                             const unsigned char H[16],
                             const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off + 16 <= len) {
        ghash_absorb_block(acc, H, buf + off);
        off += 16;
    }
    if (off < len) {
        unsigned char tmp[16] = {0};
        memcpy(tmp, buf + off, len - off);
        ghash_absorb_block(acc, H, tmp);
    }
}

/* Big-endian 32-bit increment of bytes 12..15. */
static void gcm_inc32(unsigned char counter[16]) {
    int k;
    for (k = 15; k >= 12; --k) {
        counter[k] = (unsigned char)(counter[k] + 1);
        if (counter[k] != 0) { break; }
    }
}

/* Write a bit count (bytes * 8) as a 64-bit big-endian integer. */
static void pack_be64_bits(unsigned char out[8], size_t bytes) {
    /* bit count = bytes * 8 */
    unsigned long long bits = (unsigned long long)bytes * 8ull;
    out[0] = (unsigned char)(bits >> 56);
    out[1] = (unsigned char)(bits >> 48);
    out[2] = (unsigned char)(bits >> 40);
    out[3] = (unsigned char)(bits >> 32);
    out[4] = (unsigned char)(bits >> 24);
    out[5] = (unsigned char)(bits >> 16);
    out[6] = (unsigned char)(bits >>  8);
    out[7] = (unsigned char)(bits      );
}

/* Compute J_0 (the initial counter block). */
static void gcm_derive_j0(const aes_ctx *c,
                          const unsigned char H[16],
                          const unsigned char *iv, size_t iv_len,
                          unsigned char j0[16]) {
    (void)c;
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        unsigned char acc[16] = {0};
        unsigned char lenblk[16] = {0};
        ghash_absorb_buf(acc, H, iv, iv_len);
        pack_be64_bits(lenblk + 8, iv_len);    /* low 8 bytes = iv_bits */
        ghash_absorb_block(acc, H, lenblk);
        memcpy(j0, acc, 16);
    }
}

static int gcm_core(int do_encrypt,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *in,  size_t in_len,
                    unsigned char *out,
                    unsigned char *tag_out,
                    const unsigned char *tag_in,
                    size_t tag_len) {
    aes_ctx c;
    unsigned char H[16]   = {0};
    unsigned char J0[16];
    unsigned char cnt[16];
    unsigned char stream[16];
    unsigned char acc[16] = {0};
    unsigned char lenblk[16];
    unsigned char tag[16];
    size_t off;
    int rc = -1;

    aes_key_expand(&c, key, key_len);

    /* H = E_K(0^128) */
    aes_encrypt_block(&c, H, H);

    gcm_derive_j0(&c, H, iv, iv_len, J0);

    /* GHASH(AAD) */
    if (aad_len > 0) { ghash_absorb_buf(acc, H, aad, aad_len); }

    /* Counter starts at J_0 + 1 */
    memcpy(cnt, J0, 16);
    gcm_inc32(cnt);

    for (off = 0; off < in_len; off += 16) {
        size_t blk = (in_len - off >= 16) ? 16 : (in_len - off);
        size_t j;

        aes_encrypt_block(&c, cnt, stream);
        gcm_inc32(cnt);

        if (do_encrypt) {
            for (j = 0; j < blk; ++j) { out[off + j] = in[off + j] ^ stream[j]; }
            /* GHASH feeds on the ciphertext (== out) */
            {
                unsigned char tmp[16] = {0};
                memcpy(tmp, out + off, blk);
                ghash_absorb_block(acc, H, tmp);
            }
        } else {
            /* GHASH feeds on the ciphertext (== in) BEFORE xor */
            {
                unsigned char tmp[16] = {0};
                memcpy(tmp, in + off, blk);
                ghash_absorb_block(acc, H, tmp);
            }
            for (j = 0; j < blk; ++j) { out[off + j] = in[off + j] ^ stream[j]; }
        }
    }

    /* Length block: 64-bit BE aad_bits || 64-bit BE ct_bits */
    memset(lenblk, 0, 16);
    pack_be64_bits(lenblk + 0, aad_len);
    pack_be64_bits(lenblk + 8, in_len);
    ghash_absorb_block(acc, H, lenblk);

    /* Tag = E_K(J_0) XOR GHASH */
    aes_encrypt_block(&c, J0, stream);
    {
        int i;
        for (i = 0; i < 16; ++i) { tag[i] = stream[i] ^ acc[i]; }
    }

    if (do_encrypt) {
        memcpy(tag_out, tag, tag_len);
        rc = 0;
    } else {
        /* Constant-time tag compare */
        unsigned char diff = 0;
        size_t i;
        for (i = 0; i < tag_len; ++i) { diff = (unsigned char)(diff | (tag[i] ^ tag_in[i])); }
        if (diff == 0) {
            rc = 0;
        } else {
            if (in_len > 0 && out != NULL) { memset(out, 0, in_len); }
            rc = -1;
        }
    }

    /* Scrub locals that touch key material */
    memset(&c, 0, sizeof(c));
    memset(H, 0, sizeof(H));
    memset(J0, 0, sizeof(J0));
    memset(cnt, 0, sizeof(cnt));
    memset(stream, 0, sizeof(stream));
    memset(acc, 0, sizeof(acc));
    memset(lenblk, 0, sizeof(lenblk));
    memset(tag, 0, sizeof(tag));
    return rc;
}

int aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *pt,           size_t pt_len,
                    unsigned char *ct,
                    unsigned char *tag,       size_t tag_len) {
    if (!valid_key_len(key_len))                  { return -1; }
    if (iv == NULL || iv_len == 0)                { return -1; }
    if (!valid_tag_len(tag_len))                  { return -1; }
    if (!valid_buf(aad, aad_len))                 { return -1; }
    if (!valid_buf(pt,  pt_len ))                 { return -1; }
    if (pt_len != 0 && ct == NULL)                { return -1; }
    if (tag == NULL)                              { return -1; }

    return gcm_core(1,
                    key, key_len,
                    iv,  iv_len,
                    (const unsigned char *)aad, aad_len,
                    (const unsigned char *)pt,  pt_len,
                    ct,
                    tag, NULL,
                    tag_len);
}

int aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                    const unsigned char *iv,  size_t iv_len,
                    const void *aad,          size_t aad_len,
                    const void *ct,           size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *pt) {
    if (!valid_key_len(key_len))                  { return -1; }
    if (iv == NULL || iv_len == 0)                { return -1; }
    if (!valid_tag_len(tag_len))                  { return -1; }
    if (!valid_buf(aad, aad_len))                 { return -1; }
    if (!valid_buf(ct,  ct_len ))                 { return -1; }
    if (ct_len != 0 && pt == NULL)                { return -1; }
    if (tag == NULL)                              { return -1; }

    return gcm_core(0,
                    key, key_len,
                    iv,  iv_len,
                    (const unsigned char *)aad, aad_len,
                    (const unsigned char *)ct,  ct_len,
                    pt,
                    NULL, tag,
                    tag_len);
}

#endif
