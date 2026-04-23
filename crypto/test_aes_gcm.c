/*
 * NIST SP 800-38D test-vector harness for aes_gcm_encrypt / aes_gcm_decrypt.
 * Prints each case pass/fail and exits nonzero if any fail.
 */
#include "aes_gcm.h"

#include <stdio.h>
#include <string.h>

static int hex2bin(const char *s, unsigned char *out, size_t *out_len) {
    size_t slen = strlen(s);
    size_t i, j = 0;
    if (slen % 2 != 0) { return -1; }
    for (i = 0; i < slen; i += 2) {
        int hi, lo;
        char a = s[i], b = s[i + 1];
        if      (a >= '0' && a <= '9') { hi = a - '0'; }
        else if (a >= 'a' && a <= 'f') { hi = a - 'a' + 10; }
        else if (a >= 'A' && a <= 'F') { hi = a - 'A' + 10; }
        else                           { return -1; }
        if      (b >= '0' && b <= '9') { lo = b - '0'; }
        else if (b >= 'a' && b <= 'f') { lo = b - 'a' + 10; }
        else if (b >= 'A' && b <= 'F') { lo = b - 'A' + 10; }
        else                           { return -1; }
        out[j++] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = j;
    return 0;
}

typedef struct {
    const char *name;
    const char *key;
    const char *iv;
    const char *aad;
    const char *pt;
    const char *ct;
    const char *tag;
} vec_t;

/* Values produced and double-checked against an OpenSSL/NIST oracle. */
static const vec_t vectors[] = {
    {
        "NIST TC1 (AES-128, empty)",
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "", "", "",
        "58e2fccefa7e3061367f1d57a4e7455a"
    },
    {
        "NIST TC2 (AES-128, one zero block)",
        "00000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf"
    },
    {
        "NIST TC3 (AES-128, 4 blocks, no AAD)",
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4"
    },
    {
        "NIST TC4 (AES-128, with AAD, partial last block)",
        "feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47"
    },
    {
        "NIST TC13 (AES-256, empty)",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "", "", "",
        "530f8afbc74536b9a963b4f1c4cb738b"
    },
    {
        "NIST TC14 (AES-256, one zero block)",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "00000000000000000000000000000000",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919"
    },
    {
        "NIST TC16 (AES-256, with AAD, partial last block)",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b"
    }
};

static void dump(const char *label, const unsigned char *p, size_t n) {
    size_t i;
    fprintf(stderr, "  %s:", label);
    for (i = 0; i < n; ++i) { fprintf(stderr, " %02x", p[i]); }
    fprintf(stderr, "\n");
}

static int run_vector(const vec_t *v) {
    unsigned char key[32], iv[64], aad[64], pt[128], ct_exp[128], tag_exp[16];
    unsigned char ct_got[128], tag_got[16], pt_got[128];
    size_t key_len, iv_len, aad_len, pt_len, ct_len, tag_len;

    if (hex2bin(v->key, key,     &key_len) != 0 ||
        hex2bin(v->iv,  iv,      &iv_len)  != 0 ||
        hex2bin(v->aad, aad,     &aad_len) != 0 ||
        hex2bin(v->pt,  pt,      &pt_len)  != 0 ||
        hex2bin(v->ct,  ct_exp,  &ct_len)  != 0 ||
        hex2bin(v->tag, tag_exp, &tag_len) != 0) {
        fprintf(stderr, "%s: bad hex literal in vector\n", v->name);
        return 1;
    }
    if (ct_len != pt_len) {
        fprintf(stderr, "%s: pt/ct length mismatch\n", v->name);
        return 1;
    }

    /* Encrypt check */
    if (aes_gcm_encrypt(key, key_len, iv, iv_len,
                        aad, aad_len,
                        pt,  pt_len,
                        ct_got,
                        tag_got, tag_len) != 0) {
        fprintf(stderr, "%s: encrypt returned -1\n", v->name);
        return 1;
    }
    if (pt_len > 0 && memcmp(ct_got, ct_exp, pt_len) != 0) {
        fprintf(stderr, "%s: ciphertext mismatch\n", v->name);
        dump("want", ct_exp, pt_len);
        dump("got ", ct_got, pt_len);
        return 1;
    }
    if (memcmp(tag_got, tag_exp, tag_len) != 0) {
        fprintf(stderr, "%s: tag mismatch\n", v->name);
        dump("want", tag_exp, tag_len);
        dump("got ", tag_got, tag_len);
        return 1;
    }

    /* Decrypt check (valid tag -> plaintext recovered) */
    if (aes_gcm_decrypt(key, key_len, iv, iv_len,
                        aad, aad_len,
                        ct_exp, ct_len,
                        tag_exp, tag_len,
                        pt_got) != 0) {
        fprintf(stderr, "%s: decrypt rejected valid tag\n", v->name);
        return 1;
    }
    if (pt_len > 0 && memcmp(pt_got, pt, pt_len) != 0) {
        fprintf(stderr, "%s: decrypted plaintext mismatch\n", v->name);
        return 1;
    }

    /* Tamper check (bad tag -> rejection) */
    {
        unsigned char bad_tag[16];
        memcpy(bad_tag, tag_exp, tag_len);
        bad_tag[0] ^= 0x01;
        if (aes_gcm_decrypt(key, key_len, iv, iv_len,
                            aad, aad_len,
                            ct_exp, ct_len,
                            bad_tag, tag_len,
                            pt_got) == 0) {
            fprintf(stderr, "%s: decrypt ACCEPTED a tampered tag\n", v->name);
            return 1;
        }
    }

    printf("  ok   %s\n", v->name);
    return 0;
}

int main(void) {
    size_t i;
    int fails = 0;
    printf("aes_gcm test vectors:\n");
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        fails += run_vector(&vectors[i]);
    }
    if (fails != 0) {
        fprintf(stderr, "FAIL: %d vector(s) failed\n", fails);
        return 1;
    }
    printf("all %zu vectors passed\n", sizeof(vectors) / sizeof(vectors[0]));
    return 0;
}
