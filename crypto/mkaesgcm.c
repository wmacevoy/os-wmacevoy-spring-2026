/*
 * mkaesgcm — AES-256-GCM file tool, C port of aesgcm.py.
 *
 * Sealed blob layout (identical to aesgcm.py):
 *   nonce(12) || tag(16) || aad_len(4 BE) || aad || ciphertext
 */
#include "aes_gcm.h"
#include "secure_random.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#else
#  include <sys/stat.h>
#endif

#define KEY_LEN    32
#define NONCE_LEN  12
#define TAG_LEN    16
#define AAD_HDR    4   /* uint32 big-endian AAD length */

static const char *prog = "mkaesgcm";

static void usage(void) {
    fprintf(stderr,
        "usage:\n"
        "  %s --keygen  --key K.bin\n"
        "  %s --encrypt PLAIN [--data AAD] --key K.bin --out SEALED\n"
        "  %s --decrypt SEALED [--data AAD_OUT] --key K.bin --out PLAIN\n"
        "\n"
        "  AES-256-GCM; uses a fresh 96-bit random nonce per --encrypt.\n"
        "  --data on encrypt is authenticated (not encrypted) and is\n"
        "  embedded in the sealed blob; on decrypt it is optional and,\n"
        "  if given, receives the recovered AAD bytes.\n",
        prog, prog, prog);
}

/* ---------------------------------------------------------------- I/O */

static int read_all(const char *path, unsigned char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    size_t cap = 0, len = 0;

    if (!f) { fprintf(stderr, "%s: open '%s': %s\n", prog, path, strerror(errno)); return -1; }

    for (;;) {
        size_t n;
        if (len == cap) {
            size_t new_cap = cap ? cap * 2 : 8192;
            unsigned char *nb = (unsigned char *)realloc(buf, new_cap);
            if (!nb) { free(buf); fclose(f); fprintf(stderr, "%s: out of memory\n", prog); return -1; }
            buf = nb;
            cap = new_cap;
        }
        n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) { break; }
    }
    if (ferror(f)) {
        fprintf(stderr, "%s: read '%s': %s\n", prog, path, strerror(errno));
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = len;
    return 0;
}

static int write_all(const char *path, const void *data, size_t len, int sensitive) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "%s: open '%s': %s\n", prog, path, strerror(errno)); return -1; }
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "%s: write '%s': %s\n", prog, path, strerror(errno));
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "%s: close '%s': %s\n", prog, path, strerror(errno));
        return -1;
    }
#ifndef _WIN32
    if (sensitive) { (void)chmod(path, 0600); }
#else
    (void)sensitive;
#endif
    return 0;
}

/* ----------------------------------------------------------- commands */

static int cmd_keygen(const char *key_path) {
    unsigned char key[KEY_LEN];
    if (secure_random_bytes(key, sizeof(key)) != 0) {
        fprintf(stderr, "%s: secure_random_bytes failed\n", prog);
        return 1;
    }
    if (write_all(key_path, key, sizeof(key), 1) != 0) { return 1; }
    memset(key, 0, sizeof(key));
    return 0;
}

static int load_key(const char *path, unsigned char key[KEY_LEN]) {
    unsigned char *buf = NULL;
    size_t len = 0;
    if (read_all(path, &buf, &len) != 0) { return -1; }
    if (len != KEY_LEN) {
        fprintf(stderr, "%s: %s: expected %d-byte key, got %zu\n",
                prog, path, KEY_LEN, len);
        free(buf);
        return -1;
    }
    memcpy(key, buf, KEY_LEN);
    memset(buf, 0, len);
    free(buf);
    return 0;
}

static int cmd_encrypt(const char *key_path, const char *plain_path,
                       const char *aad_path, const char *out_path) {
    unsigned char key[KEY_LEN];
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char *pt = NULL, *aad = NULL, *blob = NULL;
    size_t pt_len = 0, aad_len = 0, blob_len;
    int rc = 1;

    if (load_key(key_path, key) != 0)                           { goto done; }
    if (read_all(plain_path, &pt, &pt_len) != 0)                { goto done; }
    if (aad_path && read_all(aad_path, &aad, &aad_len) != 0)    { goto done; }
    if (aad_len > 0xffffffffULL) {
        fprintf(stderr, "%s: AAD too large (%zu bytes; max 4 GiB)\n", prog, aad_len);
        goto done;
    }
    if (secure_random_bytes(nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "%s: secure_random_bytes failed\n", prog);
        goto done;
    }

    blob_len = NONCE_LEN + TAG_LEN + AAD_HDR + aad_len + pt_len;
    blob = (unsigned char *)malloc(blob_len ? blob_len : 1);
    if (!blob) { fprintf(stderr, "%s: out of memory\n", prog); goto done; }

    /* Lay out header */
    memcpy(blob, nonce, NONCE_LEN);
    /* tag comes after encryption */
    blob[NONCE_LEN + TAG_LEN + 0] = (unsigned char)((aad_len >> 24) & 0xff);
    blob[NONCE_LEN + TAG_LEN + 1] = (unsigned char)((aad_len >> 16) & 0xff);
    blob[NONCE_LEN + TAG_LEN + 2] = (unsigned char)((aad_len >>  8) & 0xff);
    blob[NONCE_LEN + TAG_LEN + 3] = (unsigned char)((aad_len      ) & 0xff);
    if (aad_len > 0) {
        memcpy(blob + NONCE_LEN + TAG_LEN + AAD_HDR, aad, aad_len);
    }

    if (aes_gcm_encrypt(key, KEY_LEN,
                        nonce, NONCE_LEN,
                        aad, aad_len,
                        pt, pt_len,
                        blob + NONCE_LEN + TAG_LEN + AAD_HDR + aad_len,
                        tag, TAG_LEN) != 0) {
        fprintf(stderr, "%s: aes_gcm_encrypt failed\n", prog);
        goto done;
    }
    memcpy(blob + NONCE_LEN, tag, TAG_LEN);

    if (write_all(out_path, blob, blob_len, 1) != 0) { goto done; }
    rc = 0;

done:
    memset(key, 0, sizeof(key));
    memset(tag, 0, sizeof(tag));
    if (pt)   { memset(pt, 0, pt_len);    free(pt);   }
    if (aad)  {                           free(aad);  }
    if (blob) {                           free(blob); }
    return rc;
}

static int cmd_decrypt(const char *key_path, const char *sealed_path,
                       const char *aad_out_path, const char *out_path) {
    unsigned char key[KEY_LEN];
    unsigned char *blob = NULL, *pt = NULL;
    size_t blob_len = 0;
    size_t aad_len, ct_len;
    const unsigned char *nonce, *tag, *aad, *ct;
    int rc = 1;

    if (load_key(key_path, key) != 0)                    { goto done; }
    if (read_all(sealed_path, &blob, &blob_len) != 0)    { goto done; }

    if (blob_len < (size_t)(NONCE_LEN + TAG_LEN + AAD_HDR)) {
        fprintf(stderr, "%s: %s: too short to be a sealed blob\n", prog, sealed_path);
        goto done;
    }

    nonce   = blob;
    tag     = blob + NONCE_LEN;
    aad_len = ((size_t)blob[NONCE_LEN + TAG_LEN + 0] << 24)
            | ((size_t)blob[NONCE_LEN + TAG_LEN + 1] << 16)
            | ((size_t)blob[NONCE_LEN + TAG_LEN + 2] <<  8)
            | ((size_t)blob[NONCE_LEN + TAG_LEN + 3]      );
    {
        size_t body = blob_len - (NONCE_LEN + TAG_LEN + AAD_HDR);
        if (aad_len > body) {
            fprintf(stderr, "%s: %s: truncated (AAD length %zu > remaining %zu)\n",
                    prog, sealed_path, aad_len, body);
            goto done;
        }
        ct_len = body - aad_len;
    }
    aad = blob + NONCE_LEN + TAG_LEN + AAD_HDR;
    ct  = aad + aad_len;

    pt = (unsigned char *)malloc(ct_len ? ct_len : 1);
    if (!pt) { fprintf(stderr, "%s: out of memory\n", prog); goto done; }

    if (aes_gcm_decrypt(key, KEY_LEN,
                        nonce, NONCE_LEN,
                        aad,   aad_len,
                        ct,    ct_len,
                        tag,   TAG_LEN,
                        pt) != 0) {
        fprintf(stderr, "%s: decryption/authentication failed\n", prog);
        goto done;
    }

    if (write_all(out_path, pt, ct_len, 1) != 0)         { goto done; }
    if (aad_out_path &&
        write_all(aad_out_path, aad, aad_len, 0) != 0)   { goto done; }
    rc = 0;

done:
    memset(key, 0, sizeof(key));
    if (pt)   { memset(pt, 0, ct_len); free(pt);   }
    if (blob) {                         free(blob); }
    return rc;
}

/* ------------------------------------------------------------ argv parsing */

int main(int argc, char **argv) {
    const char *key_path = NULL;
    const char *encrypt_in = NULL;
    const char *decrypt_in = NULL;
    const char *data_path = NULL;
    const char *out_path  = NULL;
    int do_keygen = 0;
    int i;

    prog = argv[0];

    for (i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if      (strcmp(a, "--key")     == 0 && i + 1 < argc) { key_path    = argv[++i]; }
        else if (strcmp(a, "--encrypt") == 0 && i + 1 < argc) { encrypt_in  = argv[++i]; }
        else if (strcmp(a, "--decrypt") == 0 && i + 1 < argc) { decrypt_in  = argv[++i]; }
        else if (strcmp(a, "--data")    == 0 && i + 1 < argc) { data_path   = argv[++i]; }
        else if (strcmp(a, "--out")     == 0 && i + 1 < argc) { out_path    = argv[++i]; }
        else if (strcmp(a, "--keygen")  == 0)                 { do_keygen   = 1;         }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0;  }
        else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", prog, a);
            usage();
            return 2;
        }
    }

    if (do_keygen) {
        if (!key_path)      { fprintf(stderr, "%s: --keygen requires --key\n", prog); return 2; }
        if (encrypt_in || decrypt_in) {
            fprintf(stderr, "%s: --keygen does not take --encrypt/--decrypt\n", prog);
            return 2;
        }
        return cmd_keygen(key_path);
    }

    if (!key_path)                 { fprintf(stderr, "%s: --key is required\n",  prog); return 2; }
    if (!out_path)                 { fprintf(stderr, "%s: --out is required\n",  prog); return 2; }
    if (encrypt_in && decrypt_in)  { fprintf(stderr, "%s: pick one of --encrypt or --decrypt\n", prog); return 2; }
    if (!encrypt_in && !decrypt_in){ fprintf(stderr, "%s: need --encrypt or --decrypt\n", prog); usage(); return 2; }

    if (encrypt_in) { return cmd_encrypt(key_path, encrypt_in, data_path, out_path); }
    else            { return cmd_decrypt(key_path, decrypt_in, data_path, out_path); }
}
